/// Compile-phase state. Collects validated rules from the parser (temporary
/// Swift collections are fine here — heap allocation is allowed before the
/// snapshot freezes), then flattens everything into an immutable
/// `CompiledRules` snapshot (docs/PLAN.md §2).
/// Build-phase dictionary key: bytes plus precomputed FNV-1a.
///
/// `fnv1a` lowercases internally (Bytes.swift), so hashing already-lowered
/// bytes here yields values identical to query-time `fnv1a(raw)` — table
/// placement in `buildOpenAddressing` stays consistent with
/// `lookupOpenAddressing`. The custom `hash(into:)` makes every dictionary
/// operation O(1) in hashing instead of routing through the generic `Hasher`
/// byte-by-byte path for each lookup.
struct ByteKey: Hashable {
    var bytes: [UInt8]
    var hash: UInt64

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
        self.hash = fnv1a(bytes)
    }

    init(bytes: [UInt8], hash: UInt64) {
        self.bytes = bytes
        self.hash = hash
    }

    @inline(__always)
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.bytes == rhs.bytes
    }

    @inline(__always)
    func hash(into hasher: inout Hasher) {
        hasher.combine(hash)
    }
}

/// Lowercase + FNV-1a in a single pass (hash covers the lowered bytes,
/// same algorithm as `fnv1a` in Bytes.swift).
private func lowerKey(_ span: Span<UInt8>) -> ByteKey {
    var out = [UInt8]()
    let count = span.count
    out.reserveCapacity(count)
    var h = FNV1a.offsetBasis
    for i in 0..<count {
        let low = lowerByte(span[unchecked: i])
        out.append(low)
        h = FNV1a.step(h, low)
    }
    return ByteKey(bytes: out, hash: h)
}

struct RuleSink {
    private(set) var nextRuleIndex: UInt32 = 0

    // Policy interning
    private var policyKeys: [ByteKey: UInt16] = [:]
    var policyArena = ByteArena()
    private(set) var policyNameRefs: [PolicyNameRef] = []

    // Collectors
    var exact: [ByteKey: (policy: UInt16, rule: UInt32)] = [:]
    var keywords: [(key: [UInt8], policy: UInt16, rule: UInt32)] = []
    var trie = SuffixTrieBuilder()
    var ipv4 = IPNodeBuilder(bitWidth: 32)
    var ipv6 = IPNodeBuilder(bitWidth: 128)
    var srcIPv4 = IPNodeBuilder(bitWidth: 32)
    var srcIPv6 = IPNodeBuilder(bitWidth: 128)
    var portMap: [UInt32: PortSlot] = [:]
    var processName: [ByteKey: (policy: UInt16, rule: UInt32)] = [:]
    var processPath: [ByteKey: (policy: UInt16, rule: UInt32)] = [:]
    var tcpRule: (policy: UInt16, rule: UInt32)?
    var udpRule: (policy: UInt16, rule: UInt32)?
    var dscpMap: [UInt8: (policy: UInt16, rule: UInt32)] = [:]
    var geoIPMap: [UInt32: (policy: UInt16, rule: UInt32)] = [:]
    var matchRule: (policy: UInt16, rule: UInt32)?

    // Logic rules (AND / OR / NOT / SUB-RULE)
    var logicRules: [LogicRule] = []
    var logicArena = ByteArena()
    var logicNodes: [LogicNode] = []
    var logicChildIndices: [UInt32] = []

    mutating func intern(
        _ span: Span<UInt8>, line: Int, column: Int
    ) throws(RuleParseError) -> UInt16 {
        guard !span.isEmpty else {
            throw RuleParseError(.invalidArgument, line: line, column: column, "empty policy name")
        }
        let key = ByteKey(Array(copying: span))
        if let id = policyKeys[key] { return id }
        guard policyNameRefs.count < 65536 else {
            throw RuleParseError(.policyTableFull, line: line, column: 1, "more than 65536 distinct policy names")
        }
        let id = UInt16(policyNameRefs.count)
        let offset = policyArena.append(span)
        policyNameRefs.append(PolicyNameRef(offset: offset, length: UInt16(span.count)))
        policyKeys[key] = id
        return id
    }

    /// 第 `i` 个元素是规则序号 `i` 对应的源文件行号（1-based）。编译期始终记录，快照是否保留由 `Diagnostics` 决定。
    private(set) var ruleSourceLines: [UInt32] = []

    /// 当前顶层规则行的行号，供编译报告使用。
    private(set) var currentLine = 0
    /// 规则集展开的嵌套深度；大于 0 时，展开出的条目不参与覆盖检测（它们共享外层序号）。
    private(set) var ruleSetDepth = 0
    /// 规则集中有效条目的累计数，用于判断规则集是否为空。
    private(set) var ruleSetEntryCount = 0

    private var keywordFirstRule: [[UInt8]: UInt32] = [:]
    private(set) var shadowedRules: [ShadowedRule] = []
    private(set) var emptyRuleSets: [EmptyRuleSet] = []

    mutating func beginLine(line: Int) {
        currentLine = line
    }

    mutating func enterRuleSet() {
        ruleSetDepth += 1
    }

    mutating func exitRuleSet() {
        ruleSetDepth -= 1
    }

    mutating func countRuleSetEntry() {
        ruleSetEntryCount += 1
    }

    mutating func noteEmptyRuleSet(name: [UInt8]) {
        guard ruleSetDepth > 0 else { return }
        emptyRuleSets.append(EmptyRuleSet(
            name: String(decoding: name, as: UTF8.self),
            line: currentLine
        ))
    }

    /// 记录一条顶层规则被更早的规则完全覆盖。只对顶层行记录，且只在首条 MATCH 之前记录
    /// （之后的规则由 `unreachableRules` 统一报告）。
    mutating func noteShadowed(ruleIndex: UInt32, by earlier: UInt32) {
        guard ruleSetDepth == 0, matchRule == nil, Int(earlier) < ruleSourceLines.count else { return }
        shadowedRules.append(ShadowedRule(
            rule: RuleLocation(ruleIndex: ruleIndex, line: currentLine),
            shadowedBy: RuleLocation(ruleIndex: earlier, line: Int(ruleSourceLines[Int(earlier)]))
        ))
    }

    mutating func commitLine(line: Int) {
        ruleSourceLines.append(UInt32(line))
        nextRuleIndex &+= 1
    }

    func makeReport(fingerprint: UInt64) -> CompileReport {
        var firstMatch: RuleLocation? = nil
        var unreachable: [RuleLocation] = []
        if let matchIndex = matchRule?.rule {
            firstMatch = RuleLocation(ruleIndex: matchIndex, line: Int(ruleSourceLines[Int(matchIndex)]))
            for index in (Int(matchIndex) + 1)..<ruleSourceLines.count {
                unreachable.append(RuleLocation(ruleIndex: UInt32(index), line: Int(ruleSourceLines[index])))
            }
        }
        return CompileReport(
            fingerprint: fingerprint,
            firstMatch: firstMatch,
            shadowedRules: shadowedRules,
            unreachableRules: unreachable,
            emptyRuleSets: emptyRuleSets
        )
    }

    var bounds = CategoryBounds()

    mutating func addExact(
        _ span: Span<UInt8>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minExactRule = min(bounds.minExactRule, ruleIndex)
        let key = lowerKey(span)
        if let old = exact[key], old.rule <= ruleIndex {
            noteShadowed(ruleIndex: ruleIndex, by: old.rule)
            return
        }
        exact[key] = (policyID, ruleIndex)
    }

    mutating func addSuffix(
        _ span: Span<UInt8>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minSuffixRule = min(bounds.minSuffixRule, ruleIndex)
        if let earlier = trie.addSuffix(domain: span, policy: policyID, rule: ruleIndex) {
            noteShadowed(ruleIndex: ruleIndex, by: earlier)
        }
    }

    mutating func addKeyword(
        _ span: Span<UInt8>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minKeywordRule = min(bounds.minKeywordRule, ruleIndex)
        let key = lowerBytes(span)
        if let first = keywordFirstRule[key] {
            noteShadowed(ruleIndex: ruleIndex, by: first)
        } else {
            keywordFirstRule[key] = ruleIndex
        }
        keywords.append((key, policyID, ruleIndex))
    }

    mutating func addIP(
        address: UInt128, prefix: UInt8, isIPv6: Bool, isSource: Bool = false, policyID: UInt16, ruleIndex: UInt32
    ) {
        let earlier: UInt32?
        if isSource {
            if isIPv6 {
                bounds.minSrcIPv6Rule = min(bounds.minSrcIPv6Rule, ruleIndex)
                earlier = srcIPv6.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            } else {
                bounds.minSrcIPv4Rule = min(bounds.minSrcIPv4Rule, ruleIndex)
                earlier = srcIPv4.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            }
        } else {
            if isIPv6 {
                bounds.minIPv6Rule = min(bounds.minIPv6Rule, ruleIndex)
                earlier = ipv6.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            } else {
                bounds.minIPv4Rule = min(bounds.minIPv4Rule, ruleIndex)
                earlier = ipv4.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            }
        }
        if let earlier {
            noteShadowed(ruleIndex: ruleIndex, by: earlier)
        }
    }

    mutating func addPort(
        _ intervals: [(low: UInt16, high: UInt16)], side: PortSide, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minPortRule = min(bounds.minPortRule, ruleIndex)
        var everyIntervalCovered = !intervals.isEmpty
        var earliest = UInt32.max
        for interval in intervals {
            let slot = portMap[(UInt32(interval.low) << 16) | UInt32(interval.high)]
                ?? PortSlot(low: interval.low, high: interval.high)
            var covered = true
            if side != .source {
                if slot.dstRule < ruleIndex { earliest = min(earliest, slot.dstRule) } else { covered = false }
            }
            if side != .destination {
                if slot.srcRule < ruleIndex { earliest = min(earliest, slot.srcRule) } else { covered = false }
            }
            everyIntervalCovered = everyIntervalCovered && covered
        }
        if everyIntervalCovered {
            noteShadowed(ruleIndex: ruleIndex, by: earliest)
        }
        for interval in intervals {
            let key = (UInt32(interval.low) << 16) | UInt32(interval.high)
            var slot = portMap[key] ?? PortSlot(low: interval.low, high: interval.high)
            if side == .destination || side == .either {
                if ruleIndex < slot.dstRule { slot.dstPolicy = policyID; slot.dstRule = ruleIndex }
            }
            if side == .source || side == .either {
                if ruleIndex < slot.srcRule { slot.srcPolicy = policyID; slot.srcRule = ruleIndex }
            }
            portMap[key] = slot
        }
    }

    mutating func addProcessName(
        _ span: Span<UInt8>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minProcessNameRule = min(bounds.minProcessNameRule, ruleIndex)
        let key = lowerKey(span)
        if let old = processName[key], old.rule <= ruleIndex {
            noteShadowed(ruleIndex: ruleIndex, by: old.rule)
            return
        }
        processName[key] = (policyID, ruleIndex)
    }

    mutating func addProcessPath(
        _ span: Span<UInt8>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minProcessPathRule = min(bounds.minProcessPathRule, ruleIndex)
        let key = lowerKey(span)
        if let old = processPath[key], old.rule <= ruleIndex {
            noteShadowed(ruleIndex: ruleIndex, by: old.rule)
            return
        }
        processPath[key] = (policyID, ruleIndex)
    }

    mutating func addNetwork(
        _ proto: NetworkProtocol, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minNetworkRule = min(bounds.minNetworkRule, ruleIndex)
        switch proto {
        case .tcp:
            if let current = tcpRule, current.rule <= ruleIndex {
                noteShadowed(ruleIndex: ruleIndex, by: current.rule)
                return
            }
            tcpRule = (policyID, ruleIndex)
        case .udp:
            if let current = udpRule, current.rule <= ruleIndex {
                noteShadowed(ruleIndex: ruleIndex, by: current.rule)
                return
            }
            udpRule = (policyID, ruleIndex)
        }
    }

    mutating func addDSCP(
        _ value: UInt8, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minDscpRule = min(bounds.minDscpRule, ruleIndex)
        if let old = dscpMap[value], old.rule <= ruleIndex {
            noteShadowed(ruleIndex: ruleIndex, by: old.rule)
            return
        }
        dscpMap[value] = (policyID, ruleIndex)
    }

    mutating func addGeoIP(
        _ code: UInt32, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minGeoIPRule = min(bounds.minGeoIPRule, ruleIndex)
        if let old = geoIPMap[code], old.rule <= ruleIndex {
            noteShadowed(ruleIndex: ruleIndex, by: old.rule)
            return
        }
        geoIPMap[code] = (policyID, ruleIndex)
    }

    mutating func addMatch(policyID: UInt16, ruleIndex: UInt32) {
        if let current = matchRule, current.rule <= ruleIndex { return }
        matchRule = (policyID, ruleIndex)
    }

    mutating func addLogicString(_ span: Span<UInt8>) -> (offset: UInt32, length: UInt16) {
        let lower = lowerBytes(span)
        let offset = logicArena.append(lower)
        return (offset, UInt16(lower.count))
    }

    mutating func addLogicNode(_ node: LogicNode) -> UInt32 {
        let index = UInt32(logicNodes.count)
        logicNodes.append(node)
        return index
    }

    mutating func addLogicChildIndices(_ indices: [UInt32]) -> UInt32 {
        let start = UInt32(logicChildIndices.count)
        logicChildIndices.append(contentsOf: indices)
        return start
    }

    mutating func reserveLogicChildIndices(count: Int) -> UInt32 {
        let start = UInt32(logicChildIndices.count)
        logicChildIndices.append(contentsOf: repeatElement(UInt32(0), count: count))
        return start
    }

    mutating func setLogicChildIndex(_ index: UInt32, at offset: UInt32) {
        logicChildIndices[Int(offset)] = index
    }

    mutating func addLogicRule(rootNodeIndex: UInt32, policyID: UInt16, ruleIndex: UInt32) {
        bounds.minLogicRule = min(bounds.minLogicRule, ruleIndex)
        logicRules.append(LogicRule(
            rootNodeIndex: rootNodeIndex,
            policyID: policyID,
            ruleIndex: ruleIndex
        ))
    }

    private func lowerBytes(_ span: Span<UInt8>) -> [UInt8] {
        var out = [UInt8]()
        let count = span.count
        out.reserveCapacity(count)
        for i in 0..<count { out.append(lowerByte(span[unchecked: i])) }
        return out
    }
}

// MARK: - Build-phase index builders

/// Reversed-label suffix trie under construction. Struct + index arena
/// (root at index 0): no classes, so no ARC traffic and no
/// `ObjectIdentifier` mapping at freeze time — flat indices are reused as-is.
struct SuffixTrieBuilder {
    struct BuildNode {
        var children: [ByteKey: UInt32] = [:]
        var label: ByteKey = ByteKey([])
        var terminal: (policy: UInt16, rule: UInt32)?
    }

    private(set) var nodes: [BuildNode] = [BuildNode()]

    /// 返回被更早规则占用的终结点序号；未覆盖时返回 `nil`。
    @discardableResult
    mutating func addSuffix(domain: Span<UInt8>, policy: UInt16, rule: UInt32) -> UInt32? {
        // Walk labels right-to-left (TLD first) with no intermediate arrays.
        // Callers pass validated domains, so labels are non-empty; the walk
        // mirrors left-to-right splitting exactly even for invalid input.
        var node = 0
        var end = domain.count
        while true {
            var start = end
            while start > 0 && domain[unchecked: start - 1] != UInt8(ascii: ".") { start -= 1 }
            let key = lowerKey(domain.extracting(start..<end))
            if let next = nodes[node].children[key] {
                node = Int(next)
            } else {
                let child = UInt32(nodes.count)
                nodes[node].children[key] = child
                nodes.append(BuildNode(label: key))
                node = Int(child)
            }
            if start == 0 { break }
            end = start - 1
        }
        if let current = nodes[node].terminal, current.rule <= rule { return current.rule }
        nodes[node].terminal = (policy, rule)
        return nil
    }
}

/// Bitwise radix trie under construction (one node per bit level, root at index 0).
/// `bitWidth` frames the address space: 32 for the IPv4 pool, 128 for IPv6.
struct IPNodeBuilder {
    struct BuildNode {
        var left: Int = -1
        var right: Int = -1
        var policy: UInt16 = UInt16.max
        var rule: UInt32 = UInt32.max
    }

    private(set) var nodes: [BuildNode] = [BuildNode()]
    private let bitWidth: Int

    init(bitWidth: Int) {
        self.bitWidth = bitWidth
    }

    /// 返回被更早规则占用的同前缀序号；未覆盖时返回 `nil`。
    @discardableResult
    mutating func insert(address: UInt128, prefix: UInt8, policy: UInt16, rule: UInt32) -> UInt32? {
        var node = 0
        var bit = bitWidth - 1
        let stopBit = bitWidth - Int(prefix) // descend `prefix` bits from the MSB
        while bit >= stopBit {
            let isOne = (address >> UInt128(bit)) & 1 == 1
            if isOne {
                if nodes[node].right == -1 {
                    nodes[node].right = nodes.count
                    nodes.append(BuildNode())
                }
                node = nodes[node].right
            } else {
                if nodes[node].left == -1 {
                    nodes[node].left = nodes.count
                    nodes.append(BuildNode())
                }
                node = nodes[node].left
            }
            bit -= 1
        }
        var terminal = nodes[node]
        if rule < terminal.rule {
            terminal.policy = policy
            terminal.rule = rule
            nodes[node] = terminal
            return nil
        }
        return terminal.rule
    }
}

/// Merge target for port intervals (one entry per distinct interval).
struct PortSlot {
    var low: UInt16
    var high: UInt16
    var dstPolicy: UInt16 = UInt16.max
    var dstRule: UInt32 = UInt32.max
    var srcPolicy: UInt16 = UInt16.max
    var srcRule: UInt32 = UInt32.max
}
