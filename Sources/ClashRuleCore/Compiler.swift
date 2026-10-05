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
private func lowerKey(_ raw: UnsafeRawBufferPointer, _ r: Range<Int>) -> ByteKey {
    var out = [UInt8]()
    out.reserveCapacity(r.count)
    var h: UInt64 = 0xcbf2_9ce4_8422_2325
    for i in r {
        let b = lowerByte(raw[i])
        out.append(b)
        h = (h ^ UInt64(b)) &* 0x100000001b3
    }
    return ByteKey(bytes: out, hash: h)
}

struct RuleSink {
    private(set) var nextRuleIndex: UInt32 = 0

    // Policy interning
    private var policyKeys: [ByteKey: UInt16] = [:]
    var policyArena = ByteArena()
    private(set) var policyRanges: [PolicyRange] = []

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
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> UInt16 {
        guard !r.isEmpty else {
            throw RuleParseError(.invalidArgument, line: line, column: r.lowerBound - base + 1, "empty policy name")
        }
        let key = ByteKey([UInt8](raw[r]))
        if let id = policyKeys[key] { return id }
        guard policyRanges.count < 65536 else {
            throw RuleParseError(.policyTableFull, line: line, column: 1, "more than 65536 distinct policy names")
        }
        let id = UInt16(policyRanges.count)
        let offset = policyArena.append(r, in: raw)
        policyRanges.append(PolicyRange(offset: offset, length: UInt16(r.count)))
        policyKeys[key] = id
        return id
    }

    mutating func commitLine() { nextRuleIndex &+= 1 }

    var bounds = CategoryBounds()

    mutating func addExact(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minExactRule = min(bounds.minExactRule, ruleIndex)
        let key = lowerKey(raw, r)
        if let old = exact[key], old.rule <= ruleIndex { return }
        exact[key] = (policyID, ruleIndex)
    }

    mutating func addSuffix(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minSuffixRule = min(bounds.minSuffixRule, ruleIndex)
        trie.addSuffix(domain: raw, range: r, policy: policyID, rule: ruleIndex)
    }

    mutating func addKeyword(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minKeywordRule = min(bounds.minKeywordRule, ruleIndex)
        let key = lowerBytes(raw, r)
        keywords.append((key, policyID, ruleIndex))
    }

    mutating func addIP(
        address: UInt128, prefix: UInt8, isIPv6: Bool, isSource: Bool = false, policyID: UInt16, ruleIndex: UInt32
    ) {
        if isSource {
            if isIPv6 {
                bounds.minSrcIPv6Rule = min(bounds.minSrcIPv6Rule, ruleIndex)
                srcIPv6.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            } else {
                bounds.minSrcIPv4Rule = min(bounds.minSrcIPv4Rule, ruleIndex)
                srcIPv4.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            }
        } else {
            if isIPv6 {
                bounds.minIPv6Rule = min(bounds.minIPv6Rule, ruleIndex)
                ipv6.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            } else {
                bounds.minIPv4Rule = min(bounds.minIPv4Rule, ruleIndex)
                ipv4.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            }
        }
    }

    mutating func addPort(
        _ intervals: [(low: UInt16, high: UInt16)], side: PortSide, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minPortRule = min(bounds.minPortRule, ruleIndex)
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
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minProcessNameRule = min(bounds.minProcessNameRule, ruleIndex)
        let key = lowerKey(raw, r)
        if let old = processName[key], old.rule <= ruleIndex { return }
        processName[key] = (policyID, ruleIndex)
    }

    mutating func addProcessPath(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minProcessPathRule = min(bounds.minProcessPathRule, ruleIndex)
        let key = lowerKey(raw, r)
        if let old = processPath[key], old.rule <= ruleIndex { return }
        processPath[key] = (policyID, ruleIndex)
    }

    mutating func addNetwork(
        _ proto: NetworkProtocol, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minNetworkRule = min(bounds.minNetworkRule, ruleIndex)
        switch proto {
        case .tcp:
            if let current = tcpRule, current.rule <= ruleIndex { return }
            tcpRule = (policyID, ruleIndex)
        case .udp:
            if let current = udpRule, current.rule <= ruleIndex { return }
            udpRule = (policyID, ruleIndex)
        }
    }

    mutating func addDSCP(
        _ value: UInt8, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minDscpRule = min(bounds.minDscpRule, ruleIndex)
        if let old = dscpMap[value], old.rule <= ruleIndex { return }
        dscpMap[value] = (policyID, ruleIndex)
    }

    mutating func addGeoIP(
        _ code: UInt32, policyID: UInt16, ruleIndex: UInt32
    ) {
        bounds.minGeoIPRule = min(bounds.minGeoIPRule, ruleIndex)
        if let old = geoIPMap[code], old.rule <= ruleIndex { return }
        geoIPMap[code] = (policyID, ruleIndex)
    }

    mutating func addMatch(policyID: UInt16, ruleIndex: UInt32) {
        if let current = matchRule, current.rule <= ruleIndex { return }
        matchRule = (policyID, ruleIndex)
    }

    mutating func addLogicString(_ raw: UnsafeRawBufferPointer, _ r: Range<Int>) -> (offset: UInt32, length: UInt16) {
        var lower = [UInt8]()
        lower.reserveCapacity(r.count)
        for i in r { lower.append(lowerByte(raw[i])) }
        let offset = logicArena.append(lower)
        return (offset, UInt16(r.count))
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

    mutating func addLogicRule(rootNodeIndex: UInt32, policyID: UInt16, ruleIndex: UInt32) {
        bounds.minLogicRule = min(bounds.minLogicRule, ruleIndex)
        logicRules.append(LogicRule(
            rootNodeIndex: rootNodeIndex,
            policyID: policyID,
            ruleIndex: ruleIndex
        ))
    }

    private func lowerBytes(_ raw: UnsafeRawBufferPointer, _ r: Range<Int>) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(r.count)
        for i in r { out.append(lowerByte(raw[i])) }
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

    mutating func addSuffix(domain raw: UnsafeRawBufferPointer, range r: Range<Int>, policy: UInt16, rule: UInt32) {
        // Walk labels right-to-left (TLD first) with no intermediate arrays.
        // Callers pass validated domains, so labels are non-empty; the walk
        // mirrors left-to-right splitting exactly even for invalid input.
        var node = 0
        var end = r.upperBound
        while true {
            var start = end
            while start > r.lowerBound && raw[start - 1] != UInt8(ascii: ".") { start -= 1 }
            let key = lowerKey(raw, start..<end)
            if let next = nodes[node].children[key] {
                node = Int(next)
            } else {
                let child = UInt32(nodes.count)
                nodes[node].children[key] = child
                nodes.append(BuildNode(label: key))
                node = Int(child)
            }
            if start == r.lowerBound { break }
            end = start - 1
        }
        if let current = nodes[node].terminal, current.rule <= rule { return }
        nodes[node].terminal = (policy, rule)
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

    mutating func insert(address: UInt128, prefix: UInt8, policy: UInt16, rule: UInt32) {
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
        }
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
