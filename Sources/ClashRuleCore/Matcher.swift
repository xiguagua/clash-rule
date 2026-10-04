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

    /// Preferred entry point: domain bytes as a borrowed `Span` (SE-0447).
    /// The span convenience properties (`Array.span`, `Data.bytes`) need
    /// macOS 26+ / iOS 26+; on older targets use the buffer-pointer overload.
    @available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
    public func match(
        domain: borrowing Span<UInt8>,
        targetAddress: UInt128?,
        targetPort: UInt16,
        sourcePort: UInt16
    ) -> MatchResult? {
        domain.withUnsafeBufferPointer { buffer in
            match(
                domain: buffer,
                targetAddress: targetAddress,
                targetPort: targetPort,
                sourcePort: sourcePort
            )
        }
    }

    /// Buffer-pointer entry point, available on all supported deployment targets.
    /// - Parameters:
    ///   - domain: request hostname, no trailing dot; empty = unknown host.
    ///   - targetAddress: destination IP. IPv4 is encoded in the low 32 bits;
    ///     IPv6 as the full 128 bits (a zero high half is consulted in both tries).
    ///   - targetPort: destination port.
    ///   - sourcePort: source port.
    /// - Returns: the matching rule's policy handle, or `nil` if nothing matches.
    public func match(
        domain: UnsafeBufferPointer<UInt8>,
        targetAddress: UInt128?,
        targetPort: UInt16,
        sourcePort: UInt16
    ) -> MatchResult? {
        var collector = CandidateCollector()

        if rules.hasMatchRule {
            collector.consider(policy: rules.matchPolicy, rule: rules.matchRuleIndex)
        }

        if domain.count > 0 {
            collector.consider(rules.lookupExactDomain(domain))
            collector.consider(rules.lookupSuffix(domain))
            collector.consider(rules.lookupKeyword(domain))
        }

        if let address = targetAddress {
            collector.consider(rules.lookupAddress(address))
        }

        collector.consider(rules.lookupPort(targetPort, isDestination: true))
        collector.consider(rules.lookupPort(sourcePort, isDestination: false))

        return collector.finish()
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
    func lookupExactDomain(_ domain: UnsafeBufferPointer<UInt8>) -> (policy: UInt16, rule: UInt32)? {
        guard exactSlotMask != 0, !exactEntries.isEmpty, domain.count > 0 else { return nil }
        let hash = fnv1a(domain)
        var position = Int(hash & UInt64(exactSlotMask))
        while true {
            let entry = exactEntries[position]
            guard entry.keyLength != 0 else { return nil }
            let length = Int(entry.keyLength)
            if length == domain.count {
                var equal = true
                let keyStart = Int(entry.keyOffset)
                for k in 0..<length where lowerByte(domain[k]) != exactKeys[keyStart + k] {
                    equal = false
                    break
                }
                if equal { return (entry.policyID, entry.ruleIndex) }
            }
            position = (position + 1) & Int(exactSlotMask)
        }
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
}
