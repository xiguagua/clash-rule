/// Compile-phase state. Collects validated rules from the parser (temporary
/// Swift collections are fine here — heap allocation is allowed before the
/// snapshot freezes), then flattens everything into an immutable
/// `CompiledRules` snapshot (docs/PLAN.md §2).
struct RuleSink {
    private(set) var nextRuleIndex: UInt32 = 0

    // Policy interning
    private var policyKeys: [[UInt8]: UInt16] = [:]
    var policyArena = ByteArena()
    private(set) var policyRanges: [PolicyRange] = []

    // Collectors
    var exact: [[UInt8]: (policy: UInt16, rule: UInt32)] = [:]
    var keywords: [(key: [UInt8], policy: UInt16, rule: UInt32)] = []
    let trie = SuffixTrieBuilder()
    var ipv4 = IPNodeBuilder(bitWidth: 32)
    var ipv6 = IPNodeBuilder(bitWidth: 128)
    var srcIPv4 = IPNodeBuilder(bitWidth: 32)
    var srcIPv6 = IPNodeBuilder(bitWidth: 128)
    var portMap: [UInt32: PortSlot] = [:]
    var processName: [[UInt8]: (policy: UInt16, rule: UInt32)] = [:]
    var processPath: [[UInt8]: (policy: UInt16, rule: UInt32)] = [:]
    var tcpRule: (policy: UInt16, rule: UInt32)?
    var udpRule: (policy: UInt16, rule: UInt32)?
    var dscpMap: [UInt8: (policy: UInt16, rule: UInt32)] = [:]
    var geoIPMap: [UInt32: (policy: UInt16, rule: UInt32)] = [:]
    var matchRule: (policy: UInt16, rule: UInt32)?

    mutating func intern(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> UInt16 {
        guard !r.isEmpty else {
            throw RuleParseError(.invalidArgument, line: line, column: r.lowerBound - base + 1, "empty policy name")
        }
        let key = [UInt8](raw[r])
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

    mutating func addExact(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        let key = lowerBytes(raw, r)
        if let old = exact[key], old.rule <= ruleIndex { return }
        exact[key] = (policyID, ruleIndex)
    }

    mutating func addSuffix(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        var labels: [[UInt8]] = []
        var labelStart = r.lowerBound
        for i in r where raw[i] == UInt8(ascii: ".") {
            labels.append(lowerBytes(raw, labelStart..<i))
            labelStart = i + 1
        }
        labels.append(lowerBytes(raw, labelStart..<r.upperBound))
        trie.addSuffix(labels: labels, policy: policyID, rule: ruleIndex)
    }

    mutating func addKeyword(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        let key = lowerBytes(raw, r)
        keywords.append((key, policyID, ruleIndex))
    }

    mutating func addIP(
        address: UInt128, prefix: UInt8, isIPv6: Bool, isSource: Bool = false, policyID: UInt16, ruleIndex: UInt32
    ) {
        if isSource {
            if isIPv6 {
                srcIPv6.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            } else {
                srcIPv4.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            }
        } else {
            if isIPv6 {
                ipv6.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            } else {
                ipv4.insert(address: address, prefix: prefix, policy: policyID, rule: ruleIndex)
            }
        }
    }

    mutating func addPort(
        _ intervals: [(low: UInt16, high: UInt16)], side: PortSide, policyID: UInt16, ruleIndex: UInt32
    ) {
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
        let key = lowerBytes(raw, r)
        if let old = processName[key], old.rule <= ruleIndex { return }
        processName[key] = (policyID, ruleIndex)
    }

    mutating func addProcessPath(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, policyID: UInt16, ruleIndex: UInt32
    ) {
        let key = lowerBytes(raw, r)
        if let old = processPath[key], old.rule <= ruleIndex { return }
        processPath[key] = (policyID, ruleIndex)
    }

    mutating func addNetwork(
        _ proto: NetworkProtocol, policyID: UInt16, ruleIndex: UInt32
    ) {
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
        if let old = dscpMap[value], old.rule <= ruleIndex { return }
        dscpMap[value] = (policyID, ruleIndex)
    }

    mutating func addGeoIP(
        _ code: UInt32, policyID: UInt16, ruleIndex: UInt32
    ) {
        if let old = geoIPMap[code], old.rule <= ruleIndex { return }
        geoIPMap[code] = (policyID, ruleIndex)
    }

    mutating func addMatch(policyID: UInt16, ruleIndex: UInt32) {
        if let current = matchRule, current.rule <= ruleIndex { return }
        matchRule = (policyID, ruleIndex)
    }

    private func lowerBytes(_ raw: UnsafeRawBufferPointer, _ r: Range<Int>) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(r.count)
        for i in r { out.append(lowerByte(raw[i])) }
        return out
    }
}

// MARK: - Build-phase index builders

/// Reversed-label suffix trie under construction.
final class SuffixTrieBuilder {
    final class Node {
        var children: [[UInt8]: Node] = [:]
        var label: [UInt8] = []
        var terminal: (policy: UInt16, rule: UInt32)?
    }

    private(set) var root = Node()

    func addSuffix(labels: [[UInt8]], policy: UInt16, rule: UInt32) {
        var node = root
        for label in labels.reversed() {
            if let next = node.children[label] {
                node = next
            } else {
                let child = Node()
                child.label = label
                node.children[label] = child
                node = child
            }
        }
        if let current = node.terminal, current.rule <= rule { return }
        node.terminal = (policy, rule)
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
