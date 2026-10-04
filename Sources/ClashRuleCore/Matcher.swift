/// Context describing a network connection to be matched.
public struct MatchContext: @unchecked Sendable {
    public var domain: UnsafeBufferPointer<UInt8>
    public var targetAddress: UInt128?
    public var targetPort: UInt16
    public var sourceAddress: UInt128?
    public var sourcePort: UInt16
    public var processName: UnsafeBufferPointer<UInt8>
    public var processPath: UnsafeBufferPointer<UInt8>
    public var network: NetworkProtocol?
    public var dscp: UInt8?
    public var countryCode: UInt32

    public init(
        domain: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: nil, count: 0),
        targetAddress: UInt128? = nil,
        targetPort: UInt16 = 0,
        sourceAddress: UInt128? = nil,
        sourcePort: UInt16 = 0,
        processName: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: nil, count: 0),
        processPath: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: nil, count: 0),
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

    /// Match against a structured `MatchContext`. Zero heap allocation.
    public func match(context: MatchContext) -> MatchResult? {
        var collector = CandidateCollector()

        if rules.hasMatchRule {
            collector.consider(policy: rules.matchPolicy, rule: rules.matchRuleIndex)
        }

        if context.domain.count > 0 {
            collector.consider(rules.lookupExactDomain(context.domain))
            collector.consider(rules.lookupSuffix(context.domain))
            collector.consider(rules.lookupKeyword(context.domain))
        }

        if let address = context.targetAddress {
            collector.consider(rules.lookupAddress(address))
        }

        if let srcAddress = context.sourceAddress {
            collector.consider(rules.lookupSourceAddress(srcAddress))
        }

        collector.consider(rules.lookupPort(context.targetPort, isDestination: true))
        collector.consider(rules.lookupPort(context.sourcePort, isDestination: false))

        if context.processName.count > 0 {
            collector.consider(rules.lookupProcessName(context.processName))
        }

        if context.processPath.count > 0 {
            collector.consider(rules.lookupProcessPath(context.processPath))
        }

        if let net = context.network {
            collector.consider(rules.lookupNetwork(net))
        }

        if let dscp = context.dscp {
            collector.consider(rules.lookupDSCP(dscp))
        }

        if context.countryCode != 0 {
            collector.consider(rules.lookupGeoIP(context.countryCode))
        }

        if !rules.logicRules.isEmpty {
            for logicRule in rules.logicRules {
                guard logicRule.ruleIndex < collector.bestRule else { break }
                if rules.evalLogicNode(Int(logicRule.rootNodeIndex), context: context) {
                    collector.consider(policy: logicRule.policyID, rule: logicRule.ruleIndex)
                }
            }
        }

        return collector.finish()
    }

    /// Buffer-pointer entry point, available on all supported deployment targets.
    public func match(
        domain: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: nil, count: 0),
        targetAddress: UInt128? = nil,
        targetPort: UInt16 = 0,
        sourceAddress: UInt128? = nil,
        sourcePort: UInt16 = 0,
        processName: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: nil, count: 0),
        processPath: UnsafeBufferPointer<UInt8> = UnsafeBufferPointer(start: nil, count: 0),
        network: NetworkProtocol? = nil,
        dscp: UInt8? = nil,
        countryCode: UInt32 = 0
    ) -> MatchResult? {
        match(context: MatchContext(
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
        ))
    }

    /// Preferred entry point: domain bytes as a borrowed `Span` (SE-0447).
    /// The span convenience properties (`Array.span`, `Data.bytes`) need
    /// macOS 26+ / iOS 26+; on older targets use the buffer-pointer overload.
    @available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
    public func match(
        domain: borrowing Span<UInt8>,
        targetAddress: UInt128? = nil,
        targetPort: UInt16 = 0,
        sourceAddress: UInt128? = nil,
        sourcePort: UInt16 = 0,
        network: NetworkProtocol? = nil,
        dscp: UInt8? = nil,
        countryCode: UInt32 = 0
    ) -> MatchResult? {
        domain.withUnsafeBufferPointer { buffer in
            match(
                domain: buffer,
                targetAddress: targetAddress,
                targetPort: targetPort,
                sourceAddress: sourceAddress,
                sourcePort: sourcePort,
                network: network,
                dscp: dscp,
                countryCode: countryCode
            )
        }
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
        _ key: UnsafeBufferPointer<UInt8>,
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
                for k in 0..<length where lowerByte(key[k]) != keys[keyStart + k] {
                    equal = false
                    break
                }
                if equal { return (entry.policyID, entry.ruleIndex) }
            }
            position = (position + 1) & Int(mask)
        }
    }

    func lookupExactDomain(_ domain: UnsafeBufferPointer<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        lookupOpenAddressing(domain, entries: exactEntries, keys: exactKeys, mask: exactSlotMask)
    }

    func lookupProcessName(_ process: UnsafeBufferPointer<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        lookupOpenAddressing(process, entries: processNameEntries, keys: processNameKeys, mask: processNameSlotMask)
    }

    func lookupProcessPath(_ path: UnsafeBufferPointer<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        lookupOpenAddressing(path, entries: processPathEntries, keys: processPathKeys, mask: processPathSlotMask)
    }

    func lookupSuffix(_ domain: UnsafeBufferPointer<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        guard !trieNodes.isEmpty, domain.count > 0 else { return nil }
        var node = Int(trieRoot)
        var best: (policy: UInt16, rule: UInt32)? = nil
        // Walk labels right-to-left; every terminal node on the path is a candidate.
        var end = domain.count
        while end > 0 {
            var start = end - 1
            while start > 0 && domain[start - 1] != UInt8(ascii: ".") { start -= 1 }
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
                    for j in 0..<labelLength where lowerByte(domain[start + j]) != trieLabels[labelStart + j] {
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

    func lookupKeyword(_ domain: UnsafeBufferPointer<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        guard !keywordEntries.isEmpty, domain.count > 0 else { return nil }
        var best: (policy: UInt16, rule: UInt32)? = nil
        entryLoop: for entry in keywordEntries {
            let needleLength = Int(entry.keyLength)
            guard domain.count >= needleLength else { continue }
            let keyStart = Int(entry.keyOffset)
            var start = 0
            while start <= domain.count - needleLength {
                var k = 0
                while k < needleLength && lowerByte(domain[start + k]) == keywordArena[keyStart + k] { k += 1 }
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
        // IPv4 is encoded in the low 32 bits. An all-zero high half is ambiguous,
        // so both tries are consulted and the lowest rule index wins.
        var best = (address >> 32 == 0) ? walkAddress(ipv4Nodes, address: address, startBit: 31) : nil
        if let hit = walkAddress(ipv6Nodes, address: address, startBit: 127) {
            if best == nil || hit.rule < best!.rule { best = hit }
        }
        return best
    }

    func lookupSourceAddress(_ address: UInt128) -> (policy: UInt16, rule: UInt32)? {
        var best = (address >> 32 == 0) ? walkAddress(srcIPv4Nodes, address: address, startBit: 31) : nil
        if let hit = walkAddress(srcIPv6Nodes, address: address, startBit: 127) {
            if best == nil || hit.rule < best!.rule { best = hit }
        }
        return best
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

    func evalLogicNode(_ nodeIndex: Int, context: MatchContext) -> Bool {
        guard nodeIndex < logicNodes.count else { return false }
        let node = logicNodes[nodeIndex]
        guard let op = LogicOp(rawValue: node.op) else { return false }

        switch op {
        case .and:
            let start = Int(node.firstChildIndex)
            for i in 0..<Int(node.childCount) {
                let child = Int(logicChildIndices[start + i])
                if !evalLogicNode(child, context: context) {
                    return false
                }
            }
            return true

        case .or:
            let start = Int(node.firstChildIndex)
            for i in 0..<Int(node.childCount) {
                let child = Int(logicChildIndices[start + i])
                if evalLogicNode(child, context: context) {
                    return true
                }
            }
            return false

        case .not:
            let child = Int(node.firstChildIndex)
            return !evalLogicNode(child, context: context)

        case .domain:
            guard context.domain.count == Int(node.argLength) else { return false }
            let start = Int(node.argOffset)
            let len = Int(node.argLength)
            for k in 0..<len where lowerByte(context.domain[k]) != logicArena[start + k] {
                return false
            }
            return true

        case .domainSuffix:
            let len = Int(node.argLength)
            guard context.domain.count >= len else { return false }
            let start = Int(node.argOffset)
            let domainOffset = context.domain.count - len
            if domainOffset > 0 && context.domain[domainOffset - 1] != UInt8(ascii: ".") {
                return false
            }
            for k in 0..<len where lowerByte(context.domain[domainOffset + k]) != logicArena[start + k] {
                return false
            }
            return true

        case .domainKeyword:
            let len = Int(node.argLength)
            guard context.domain.count >= len else { return false }
            let start = Int(node.argOffset)
            var i = 0
            while i <= context.domain.count - len {
                var k = 0
                while k < len && lowerByte(context.domain[i + k]) == logicArena[start + k] { k += 1 }
                if k == len { return true }
                i += 1
            }
            return false

        case .ipCIDR:
            let isSource = (node.flags & 2) != 0
            guard let addr = isSource ? context.sourceAddress : context.targetAddress else { return false }
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
                return context.targetPort >= lo && context.targetPort <= hi
            } else if portSide == 2 {
                return context.sourcePort >= lo && context.sourcePort <= hi
            } else {
                return (context.targetPort >= lo && context.targetPort <= hi) ||
                       (context.sourcePort >= lo && context.sourcePort <= hi)
            }

        case .processName:
            guard context.processName.count == Int(node.argLength) else { return false }
            let start = Int(node.argOffset)
            let len = Int(node.argLength)
            for k in 0..<len where lowerByte(context.processName[k]) != logicArena[start + k] {
                return false
            }
            return true

        case .processPath:
            guard context.processPath.count == Int(node.argLength) else { return false }
            let start = Int(node.argOffset)
            let len = Int(node.argLength)
            for k in 0..<len where lowerByte(context.processPath[k]) != logicArena[start + k] {
                return false
            }
            return true

        case .network:
            guard let net = context.network else { return false }
            return net.rawValue == node.networkProto

        case .dscp:
            guard let d = context.dscp else { return false }
            return d == UInt8(node.portLow)

        case .geoIP:
            return context.countryCode != 0 && context.countryCode == node.countryCode
        }
    }
}
