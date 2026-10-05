/// Context describing a network connection to be matched.
///
/// Owned byte-array representation for caller ergonomics.
/// On hot paths, prefer calling `Matcher.match(...)` directly with borrowed `Span<UInt8>`
/// parameters to avoid heap allocation.
public struct MatchContext: Sendable {
    public var domain: [UInt8]
    public var targetAddress: UInt128?
    public var targetPort: UInt16
    public var sourceAddress: UInt128?
    public var sourcePort: UInt16
    public var processName: [UInt8]
    public var processPath: [UInt8]
    public var network: NetworkProtocol?
    public var dscp: UInt8?
    public var countryCode: UInt32

    public init(
        domain: [UInt8] = [],
        targetAddress: UInt128? = nil,
        targetPort: UInt16 = 0,
        sourceAddress: UInt128? = nil,
        sourcePort: UInt16 = 0,
        processName: [UInt8] = [],
        processPath: [UInt8] = [],
        network: NetworkProtocol? = nil,
        dscp: UInt8? = nil,
        countryCode: UInt32 = 0
    ) {
        self.domain = domain
        self.targetAddress = targetAddress
        self.targetPort = targetPort
        self.sourceAddress = sourceAddress
        self.sourcePort = sourcePort
        self.processName = processName
        self.processPath = processPath
        self.network = network
        self.dscp = dscp
        self.countryCode = countryCode
    }
}

/// Zero-allocation, lock-free matcher over a compiled snapshot.
/// Hot-path contract (docs/PLAN.md §3/§4): no `String`, no heap allocation,
/// no locks; domain bytes arrive as a borrowed view.
///
/// Semantics: rule-file order = priority. Every category is consulted and the
/// winner is the candidate with the lowest rule index — equivalent to a
/// sequential scan, but O(1)-ish per request.
public struct Matcher: Sendable {
    public let rules: CompiledRules

    public init(_ rules: CompiledRules) {
        self.rules = rules
    }

    /// Preferred entry point: borrowed `Span<UInt8>` for domain, process name, and process path.
    /// Hot-path contract (docs/PLAN.md §3/§4): zero heap allocation, no locks, zero unsafe pointers.
    public func match(
        domain: Span<UInt8> = Span(),
        targetAddress: UInt128? = nil,
        targetPort: UInt16 = 0,
        sourceAddress: UInt128? = nil,
        sourcePort: UInt16 = 0,
        processName: Span<UInt8> = Span(),
        processPath: Span<UInt8> = Span(),
        network: NetworkProtocol? = nil,
        dscp: UInt8? = nil,
        countryCode: UInt32 = 0
    ) -> MatchResult? {
        var collector = CandidateCollector()

        if rules.hasMatchRule {
            collector.consider(policy: rules.matchPolicy, rule: rules.matchRuleIndex)
        }

        let bounds = rules.bounds

        // Tier 1: Fastest O(1) checks (~2–15 ns)
        if domain.count > 0 && collector.bestRule > bounds.minExactRule {
            collector.consider(rules.lookupExactDomain(domain))
            if collector.isOptimal { return collector.finish() }
        }

        if let dscp = dscp, collector.bestRule > bounds.minDscpRule {
            collector.consider(rules.lookupDSCP(dscp))
            if collector.isOptimal { return collector.finish() }
        }

        if let net = network, collector.bestRule > bounds.minNetworkRule {
            collector.consider(rules.lookupNetwork(net))
            if collector.isOptimal { return collector.finish() }
        }

        if collector.bestRule > bounds.minPortRule {
            // 与 mihomo 对齐：端口 0 是普通端口值，无特殊跳过。
            // mihomo Port.Match 直接做区间匹配，未指定端口 (0) 可命中 DST-PORT,0。
            collector.consider(rules.lookupPort(targetPort, isDestination: true))
            if collector.isOptimal { return collector.finish() }
            collector.consider(rules.lookupPort(sourcePort, isDestination: false))
            if collector.isOptimal { return collector.finish() }
        }

        if processName.count > 0 && collector.bestRule > bounds.minProcessNameRule {
            collector.consider(rules.lookupProcessName(processName))
            if collector.isOptimal { return collector.finish() }
        }

        if processPath.count > 0 && collector.bestRule > bounds.minProcessPathRule {
            collector.consider(rules.lookupProcessPath(processPath))
            if collector.isOptimal { return collector.finish() }
        }

        if countryCode != 0 && collector.bestRule > bounds.minGeoIPRule {
            collector.consider(rules.lookupGeoIP(countryCode))
            if collector.isOptimal { return collector.finish() }
        }

        // Tier 2: Radix and Suffix Trie Traversals (~20–80 ns)
        if domain.count > 0 && collector.bestRule > bounds.minSuffixRule {
            collector.consider(rules.lookupSuffix(domain))
            if collector.isOptimal { return collector.finish() }
        }

        if let address = targetAddress {
            let minIP = min(bounds.minIPv4Rule, bounds.minIPv6Rule)
            if collector.bestRule > minIP {
                collector.consider(rules.lookupAddress(address))
                if collector.isOptimal { return collector.finish() }
            }
        }

        if let srcAddress = sourceAddress {
            let minSrcIP = min(bounds.minSrcIPv4Rule, bounds.minSrcIPv6Rule)
            if collector.bestRule > minSrcIP {
                collector.consider(rules.lookupSourceAddress(srcAddress))
                if collector.isOptimal { return collector.finish() }
            }
        }

        // Tier 3: Keyword Search (linear scan or future AC automaton)
        if domain.count > 0 && collector.bestRule > bounds.minKeywordRule {
            collector.consider(rules.lookupKeyword(domain))
            if collector.isOptimal { return collector.finish() }
        }

        // Tier 4: Logic Rules
        if !rules.logicRules.isEmpty && collector.bestRule > bounds.minLogicRule {
            for logicRule in rules.logicRules {
                guard logicRule.ruleIndex < collector.bestRule else { break }
                if rules.evalLogicNode(
                    Int(logicRule.rootNodeIndex),
                    domain: domain,
                    targetAddress: targetAddress,
                    targetPort: targetPort,
                    sourceAddress: sourceAddress,
                    sourcePort: sourcePort,
                    processName: processName,
                    processPath: processPath,
                    network: network,
                    dscp: dscp,
                    countryCode: countryCode
                ) {
                    collector.consider(policy: logicRule.policyID, rule: logicRule.ruleIndex)
                    if collector.isOptimal { return collector.finish() }
                }
            }
        }

        return collector.finish()
    }

    /// Match against a structured `MatchContext`.
    public func match(context: MatchContext) -> MatchResult? {
        match(
            domain: context.domain.span,
            targetAddress: context.targetAddress,
            targetPort: context.targetPort,
            sourceAddress: context.sourceAddress,
            sourcePort: context.sourcePort,
            processName: context.processName.span,
            processPath: context.processPath.span,
            network: context.network,
            dscp: context.dscp,
            countryCode: context.countryCode
        )
    }
}

/// Zero-cost, stack-allocated arbiter that tracks the winning (lowest ruleIndex) candidate.
struct CandidateCollector: BitwiseCopyable, Sendable {
    var bestRule: UInt32 = UInt32.max
    var bestPolicy: UInt16 = 0

    @inline(__always)
    mutating func consider(_ hit: (policy: UInt16, rule: UInt32)?) {
        guard let hit, hit.rule < bestRule else { return }
        bestRule = hit.rule
        bestPolicy = hit.policy
    }

    @inline(__always)
    mutating func consider(policy: UInt16, rule: UInt32) {
        guard rule < bestRule else { return }
        bestRule = rule
        bestPolicy = policy
    }

    @inline(__always)
    var isOptimal: Bool {
        bestRule == 0
    }

    @inline(__always)
    func finish() -> MatchResult? {
        guard bestRule != UInt32.max else { return nil }
        return MatchResult(policyID: bestPolicy, ruleIndex: bestRule)
    }
}

/// A successful match: the policy handle and the winning rule's position in
/// the rule file (0-based).
public struct MatchResult: Sendable, Equatable {
    public let policyID: UInt16
    public let ruleIndex: UInt32

    init(policyID: UInt16, ruleIndex: UInt32) {
        self.policyID = policyID
        self.ruleIndex = ruleIndex
    }
}

// MARK: - Lookups (internal, all zero-allocation)

extension CompiledRules {
    private func lookupOpenAddressing(
        _ key: Span<UInt8>,
        entries: ContiguousArray<ExactEntry>,
        keys: ContiguousArray<UInt8>,
        mask: UInt32
    ) -> (policy: UInt16, rule: UInt32)? {
        guard mask != 0, !entries.isEmpty, key.count > 0 else { return nil }
        let hash = fnv1a(key)
        var position = Int(hash & UInt64(mask))
        while true {
            let entry = entries[position]
            guard entry.keyLength != 0 else { return nil }
            let length = Int(entry.keyLength)
            if length == key.count {
                var equal = true
                let keyStart = Int(entry.keyOffset)
                for k in 0..<length where lowerByte(key[unchecked: k]) != keys[keyStart + k] {
                    equal = false
                    break
                }
                if equal { return (entry.policyID, entry.ruleIndex) }
            }
            position = (position + 1) & Int(mask)
        }
    }

    func lookupExactDomain(_ domain: Span<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        lookupOpenAddressing(domain, entries: exactEntries, keys: exactKeys, mask: exactSlotMask)
    }

    func lookupProcessName(_ process: Span<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        lookupOpenAddressing(process, entries: processNameEntries, keys: processNameKeys, mask: processNameSlotMask)
    }

    func lookupProcessPath(_ path: Span<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        lookupOpenAddressing(path, entries: processPathEntries, keys: processPathKeys, mask: processPathSlotMask)
    }

    func lookupSuffix(_ domain: Span<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        guard !trieNodes.isEmpty, domain.count > 0 else { return nil }
        var node = Int(trieRoot)
        var best: (policy: UInt16, rule: UInt32)? = nil
        // Walk labels right-to-left; every terminal node on the path is a candidate.
        var end = domain.count
        while end > 0 {
            var start = end - 1
            while start > 0 && domain[unchecked: start - 1] != UInt8(ascii: ".") { start -= 1 }
            let labelLength = end - start

            let parent = trieNodes[node]
            var child: UInt32? = nil
            var k = 0
            while k < Int(parent.childCount) {
                let childEntryIndex = Int(parent.firstChildEntry) + k
                let childNode = trieNodes[Int(trieChildIndices[childEntryIndex])]
                if Int(childNode.labelLength) == labelLength {
                    var equal = true
                    let labelStart = Int(childNode.labelOffset)
                    for j in 0..<labelLength where lowerByte(domain[unchecked: start + j]) != trieLabels[labelStart + j] {
                        equal = false
                        break
                    }
                    if equal {
                        child = trieChildIndices[childEntryIndex]
                        break
                    }
                }
                k += 1
            }
            guard let childIndex = child else { break }
            node = Int(childIndex)
            let hit = trieNodes[node]
            if hit.isTerminal {
                if best == nil || hit.ruleIndex < best!.rule { best = (hit.policyID, hit.ruleIndex) }
            }
            if start == 0 { break }
            end = start - 1
        }
        return best
    }

    func lookupKeyword(_ domain: Span<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        guard !keywordEntries.isEmpty, domain.count > 0 else { return nil }
        var best: (policy: UInt16, rule: UInt32)? = nil
        entryLoop: for entry in keywordEntries {
            let needleLength = Int(entry.keyLength)
            guard domain.count >= needleLength else { continue }
            let keyStart = Int(entry.keyOffset)
            var start = 0
            while start <= domain.count - needleLength {
                var k = 0
                while k < needleLength && lowerByte(domain[unchecked: start + k]) == keywordArena[keyStart + k] { k += 1 }
                if k == needleLength {
                    if best == nil || entry.ruleIndex < best!.rule { best = (entry.policyID, entry.ruleIndex) }
                    continue entryLoop
                }
                start += 1
            }
        }
        return best
    }

    func lookupAddress(_ address: UInt128) -> (policy: UInt16, rule: UInt32)? {
        // IPv4 编码在低 32 位，高位全零时与 IPv6 ::/96 段地址歧义，
        // 双 trie 都查、取最小 ruleIndex（与 mihomo 语义对齐的保守处理）。
        if address >> 32 == 0 {
            let v4 = walkIPv4Address(ipv4Nodes, address: UInt32(truncatingIfNeeded: address))
            let v6 = walkAddress(ipv6Nodes, address: address, startBit: 127)
            switch (v4, v6) {
            case let (a?, b?): return a.rule < b.rule ? a : b
            case let (a?, nil): return a
            case let (nil, b?): return b
            case (nil, nil): return nil
            }
        } else {
            return walkAddress(ipv6Nodes, address: address, startBit: 127)
        }
    }

    func lookupSourceAddress(_ address: UInt128) -> (policy: UInt16, rule: UInt32)? {
        if address >> 32 == 0 {
            let v4 = walkIPv4Address(srcIPv4Nodes, address: UInt32(truncatingIfNeeded: address))
            let v6 = walkAddress(srcIPv6Nodes, address: address, startBit: 127)
            switch (v4, v6) {
            case let (a?, b?): return a.rule < b.rule ? a : b
            case let (a?, nil): return a
            case let (nil, b?): return b
            case (nil, nil): return nil
            }
        } else {
            return walkAddress(srcIPv6Nodes, address: address, startBit: 127)
        }
    }

    func lookupNetwork(_ net: NetworkProtocol) -> (policy: UInt16, rule: UInt32)? {
        switch net {
        case .tcp:
            return tcpRuleIndex != UInt32.max ? (tcpPolicy, tcpRuleIndex) : nil
        case .udp:
            return udpRuleIndex != UInt32.max ? (udpPolicy, udpRuleIndex) : nil
        }
    }

    func lookupDSCP(_ val: UInt8) -> (policy: UInt16, rule: UInt32)? {
        guard val < 64, !dscpTable.isEmpty else { return nil }
        let entry = dscpTable[Int(val)]
        return entry.ruleIndex != DscpEntry.noRule ? (entry.policyID, entry.ruleIndex) : nil
    }

    func lookupGeoIP(_ code: UInt32) -> (policy: UInt16, rule: UInt32)? {
        guard code != 0, !geoIPEntries.isEmpty else { return nil }
        var lo = 0
        var hi = geoIPEntries.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            let entry = geoIPEntries[mid]
            if entry.countryCode == code {
                return (entry.policyID, entry.ruleIndex)
            } else if entry.countryCode < code {
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return nil
    }

    private func walkIPv4Address(
        _ nodes: ContiguousArray<IPNode>, address: UInt32
    ) -> (policy: UInt16, rule: UInt32)? {
        guard !nodes.isEmpty else { return nil }
        var node = 0
        var best: (policy: UInt16, rule: UInt32)? = nil
        var bit = 31
        while true {
            let current = nodes[node]
            if current.ruleIndex != IPNode.noRule {
                if best == nil || current.ruleIndex < best!.rule { best = (current.policyID, current.ruleIndex) }
            }
            guard bit >= 0 else { break }
            let isOne = ((address >> bit) & 1) == 1
            let child = isOne ? current.right : current.left
            guard child != IPNode.noChild else { break }
            node = Int(child)
            bit -= 1
        }
        return best
    }

    private func walkAddress(
        _ nodes: ContiguousArray<IPNode>, address: UInt128, startBit: Int
    ) -> (policy: UInt16, rule: UInt32)? {
        guard !nodes.isEmpty else { return nil }
        var node = 0
        var best: (policy: UInt16, rule: UInt32)? = nil
        var bit = startBit
        while true {
            let current = nodes[node]
            if current.ruleIndex != IPNode.noRule {
                if best == nil || current.ruleIndex < best!.rule { best = (current.policyID, current.ruleIndex) }
            }
            guard bit >= 0 else { break }
            let isOne = (address >> UInt128(bit)) & 1 == 1
            let child = isOne ? current.right : current.left
            guard child != IPNode.noChild else { break }
            node = Int(child)
            bit -= 1
        }
        return best
    }

    func lookupPort(_ port: UInt16, isDestination: Bool) -> (policy: UInt16, rule: UInt32)? {
        guard !portEntries.isEmpty else { return nil }
        // Rightmost entry with low <= port.
        var lo = 0
        var hi = portEntries.count - 1
        var position = -1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if portEntries[mid].low <= port { position = mid; lo = mid + 1 } else { hi = mid - 1 }
        }
        guard position >= 0 else { return nil }
        var best: (policy: UInt16, rule: UInt32)? = nil
        var i = position
        while i >= 0 {
            let entry = portEntries[i]
            if entry.maxHigh < port {
                // No entry in 0...i has high >= port
                break
            }
            if entry.high >= port {
                let (policy, rule) = isDestination ? (entry.dstPolicy, entry.dstRule) : (entry.srcPolicy, entry.srcRule)
                if rule != PortEntry.noRule {
                    if best == nil || rule < best!.rule { best = (policy, rule) }
                }
            }
            i -= 1
        }
        return best
    }

    func evalLogicNode(
        _ rootNodeIndex: Int,
        domain: Span<UInt8>,
        targetAddress: UInt128?,
        targetPort: UInt16,
        sourceAddress: UInt128?,
        sourcePort: UInt16,
        processName: Span<UInt8>,
        processPath: Span<UInt8>,
        network: NetworkProtocol?,
        dscp: UInt8?,
        countryCode: UInt32
    ) -> Bool {
        func eval(_ nodeIndex: Int) -> Bool {
            guard nodeIndex < logicNodes.count else { return false }
            let node = logicNodes[nodeIndex]
            guard let op = LogicOp(rawValue: node.op) else { return false }

            switch op {
            case .and:
                let start = Int(node.firstChildIndex)
                for i in 0..<Int(node.childCount) {
                    let child = Int(logicChildIndices[start + i])
                    if !eval(child) {
                        return false
                    }
                }
                return true

            case .or:
                let start = Int(node.firstChildIndex)
                for i in 0..<Int(node.childCount) {
                    let child = Int(logicChildIndices[start + i])
                    if eval(child) {
                        return true
                    }
                }
                return false

            case .not:
                let child = Int(node.firstChildIndex)
                return !eval(child)

            case .domain:
                guard domain.count == Int(node.argLength) else { return false }
                let start = Int(node.argOffset)
                let len = Int(node.argLength)
                for k in 0..<len where lowerByte(domain[unchecked: k]) != logicArena[start + k] {
                    return false
                }
                return true

            case .domainSuffix:
                let len = Int(node.argLength)
                guard domain.count >= len else { return false }
                let start = Int(node.argOffset)
                let domainOffset = domain.count - len
                if domainOffset > 0 && domain[unchecked: domainOffset - 1] != UInt8(ascii: ".") {
                    return false
                }
                for k in 0..<len where lowerByte(domain[unchecked: domainOffset + k]) != logicArena[start + k] {
                    return false
                }
                return true

            case .domainKeyword:
                let len = Int(node.argLength)
                guard domain.count >= len else { return false }
                let start = Int(node.argOffset)
                var i = 0
                while i <= domain.count - len {
                    var k = 0
                    while k < len && lowerByte(domain[unchecked: i + k]) == logicArena[start + k] { k += 1 }
                    if k == len { return true }
                    i += 1
                }
                return false

            case .ipCIDR:
                let isSource = (node.flags & 2) != 0
                guard let addr = isSource ? sourceAddress : targetAddress else { return false }
                let prefix = Int(node.prefix)
                let isIPv6 = (node.flags & 1) != 0
                if isIPv6 {
                    let nodeAddr = (UInt128(node.addressHigh) << 64) | UInt128(node.addressLow)
                    let shift = 128 - prefix
                    let mask = (prefix == 0) ? UInt128(0) : (~UInt128(0) << shift)
                    return (addr & mask) == (nodeAddr & mask)
                } else {
                    let nodeAddr32 = UInt32(node.addressLow)
                    let addr32 = UInt32(addr & 0xFFFF_FFFF)
                    let shift = 32 - prefix
                    let mask = (prefix == 0) ? UInt32(0) : (~UInt32(0) << shift)
                    return (addr32 & mask) == (nodeAddr32 & mask)
                }

            case .port:
                let portSide = node.flags
                let lo = node.portLow
                let hi = node.argLength
                if portSide == 1 {
                    return targetPort >= lo && targetPort <= hi
                } else if portSide == 2 {
                    return sourcePort >= lo && sourcePort <= hi
                } else {
                    return (targetPort >= lo && targetPort <= hi) ||
                           (sourcePort >= lo && sourcePort <= hi)
                }

            case .processName:
                guard processName.count == Int(node.argLength) else { return false }
                let start = Int(node.argOffset)
                let len = Int(node.argLength)
                for k in 0..<len where lowerByte(processName[unchecked: k]) != logicArena[start + k] {
                    return false
                }
                return true

            case .processPath:
                guard processPath.count == Int(node.argLength) else { return false }
                let start = Int(node.argOffset)
                let len = Int(node.argLength)
                for k in 0..<len where lowerByte(processPath[unchecked: k]) != logicArena[start + k] {
                    return false
                }
                return true

            case .network:
                guard let net = network else { return false }
                return net.rawValue == node.networkProto

            case .dscp:
                guard let d = dscp else { return false }
                return d == UInt8(node.portLow)

            case .geoIP:
                return countryCode != 0 && countryCode == node.countryCode
            }
        }

        return eval(rootNodeIndex)
    }
}

