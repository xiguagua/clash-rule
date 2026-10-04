/// Immutable compiled snapshot. Flat POD arrays only — no reference types, no
/// enum-with-associated-values unions (docs/PLAN.md §2). Value-type sharing
/// across threads is safe: all mutation happens before the snapshot freezes.
public struct CompiledRules: Sendable {
    // Policy table
    var policyRangesArr: ContiguousArray<PolicyRange>
    var policyArena: ContiguousArray<UInt8>

    // Exact domain (open addressing, power-of-two capacity)
    var exactKeys: ContiguousArray<UInt8>
    var exactEntries: ContiguousArray<ExactEntry>
    var exactSlotMask: UInt32

    // Reversed-label suffix trie
    var trieLabels: ContiguousArray<UInt8>
    var trieNodes: ContiguousArray<SuffixTrieNode>
    var trieChildIndices: ContiguousArray<UInt32>
    var trieRoot: UInt32

    // IP radix tries (root at index 0)
    var ipv4Nodes: ContiguousArray<IPNode>
    var ipv6Nodes: ContiguousArray<IPNode>

    // Ports (sorted by (low, high))
    var portEntries: ContiguousArray<PortEntry>

    // Keywords (linear scan; AC automaton comes later)
    var keywordEntries: ContiguousArray<KeywordEntry>
    var keywordArena: ContiguousArray<UInt8>

    // MATCH fallback
    var matchPolicy: UInt16
    var matchRuleIndex: UInt32
    var hasMatchRule: Bool

    public var ruleCount: Int

    /// Diagnostic convenience — allocates a `String`. Never use in the hot path.
    public func policyName(_ id: UInt16) -> String {
        precondition(Int(id) < policyRangesArr.count, "policyID out of range")
        let range = policyRangesArr[Int(id)]
        let start = Int(range.offset)
        return String(decoding: policyArena[start..<(start + Int(range.length))], as: UTF8.self)
    }
}

// MARK: - Flattening

extension RuleSink {
    /// Freeze everything into the immutable snapshot.
    func finish() -> CompiledRules {
        let policyRangeArray = ContiguousArray(policyRanges)
        let policyArenaBytes = policyArena.bytes

        // Exact domain hash table.
        var exactKeysArena = ByteArena()
        var exactEntryArray = ContiguousArray<ExactEntry>()
        var exactMask: UInt32 = 0
        if !exact.isEmpty {
            let capacity = Self.nextPow2(max(16, exact.count * 2))
            exactMask = UInt32(capacity - 1)
            exactEntryArray = ContiguousArray(repeating: ExactEntry(), count: capacity)
            // Sorted insertion keeps the layout deterministic for a given config.
            for key in exact.keys.sorted(by: lexLess) {
                let slot = exact[key]!
                let keyOffset = exactKeysArena.append(key)
                let hash = fnv1a(key)
                var position = Int(hash & UInt64(exactMask))
                while exactEntryArray[position].keyLength != 0 {
                    position = (position + 1) & Int(exactMask)
                }
                exactEntryArray[position] = ExactEntry(
                    keyOffset: keyOffset,
                    keyLength: UInt16(key.count),
                    policyID: slot.policy,
                    ruleIndex: slot.rule
                )
            }
        }

        // Suffix trie flatten (two passes: label nodes first, then link children —
        // contiguity of each node's child block must not interleave with recursion).
        var trieLabelsArena = ByteArena()
        var trieNodeArray = ContiguousArray<SuffixTrieNode>()
        var trieChildArray = ContiguousArray<UInt32>()
        var nodeIndexMap: [ObjectIdentifier: UInt32] = [:]

        // Pass 1: assign indices and store labels.
        func assign(_ node: SuffixTrieBuilder.Node) -> UInt32 {
            let labelOffset = trieLabelsArena.append(node.label)
            let index = UInt32(trieNodeArray.count)
            nodeIndexMap[ObjectIdentifier(node)] = index
            let terminal = node.terminal
            trieNodeArray.append(SuffixTrieNode(
                firstChildEntry: 0,
                childCount: 0,
                isTerminal: terminal != nil,
                labelOffset: labelOffset,
                labelLength: UInt16(node.label.count),
                policyID: terminal?.policy ?? 0,
                ruleIndex: terminal?.rule ?? 0
            ))
            for child in node.children.values { _ = assign(child) }
            return index
        }

        // Pass 2: link child blocks (each node's entries are appended consecutively).
        func link(_ node: SuffixTrieBuilder.Node) {
            let index = Int(nodeIndexMap[ObjectIdentifier(node)]!)
            let firstChildEntry = UInt32(trieChildArray.count)
            var childCount = 0
            for labelKey in node.children.keys.sorted(by: lexLess) {
                trieChildArray.append(nodeIndexMap[ObjectIdentifier(node.children[labelKey]!)]!)
                childCount += 1
            }
            trieNodeArray[index].firstChildEntry = firstChildEntry
            trieNodeArray[index].childCount = UInt16(childCount)
            for child in node.children.values { link(child) }
        }

        let trieRootIndex = assign(trie.root)
        link(trie.root)

        // IP tries.
        func flattenIPNodes(_ builder: IPNodeBuilder) -> ContiguousArray<IPNode> {
            var array = ContiguousArray<IPNode>()
            array.reserveCapacity(builder.nodes.count)
            for build in builder.nodes {
                array.append(IPNode(
                    left: build.left == -1 ? IPNode.noChild : UInt32(build.left),
                    right: build.right == -1 ? IPNode.noChild : UInt32(build.right),
                    policyID: build.policy,
                    ruleIndex: build.rule
                ))
            }
            return array
        }
        let ipv4Array = flattenIPNodes(ipv4)
        let ipv6Array = flattenIPNodes(ipv6)

        // Ports.
        var portArray = ContiguousArray(portMap.values.map { entry in
            PortEntry(
                low: entry.low,
                high: entry.high,
                dstPolicy: entry.dstPolicy == UInt16.max ? 0 : entry.dstPolicy,
                dstRule: entry.dstRule,
                srcPolicy: entry.srcPolicy == UInt16.max ? 0 : entry.srcPolicy,
                srcRule: entry.srcRule
            )
        })
        portArray.sort { a, b in
            if a.low != b.low { return a.low < b.low }
            return a.high < b.high
        }
        var runningMax: UInt16 = 0
        for i in 0..<portArray.count {
            runningMax = max(runningMax, portArray[i].high)
            portArray[i].maxHigh = runningMax
        }

        // Keywords.
        var keywordArenaBytes = ByteArena()
        var keywordArray = ContiguousArray<KeywordEntry>()
        for entry in keywords {
            let keyOffset = keywordArenaBytes.append(entry.key)
            keywordArray.append(KeywordEntry(
                keyOffset: keyOffset,
                keyLength: UInt16(entry.key.count),
                policyID: entry.policy,
                ruleIndex: entry.rule
            ))
        }

        return CompiledRules(
            policyRangesArr: policyRangeArray,
            policyArena: policyArenaBytes,
            exactKeys: exactKeysArena.bytes,
            exactEntries: exactEntryArray,
            exactSlotMask: exactMask,
            trieLabels: trieLabelsArena.bytes,
            trieNodes: trieNodeArray,
            trieChildIndices: trieChildArray,
            trieRoot: trieRootIndex,
            ipv4Nodes: ipv4Array,
            ipv6Nodes: ipv6Array,
            portEntries: portArray,
            keywordEntries: keywordArray,
            keywordArena: keywordArenaBytes.bytes,
            matchPolicy: matchRule?.policy ?? 0,
            matchRuleIndex: matchRule?.rule ?? 0,
            hasMatchRule: matchRule != nil,
            ruleCount: Int(nextRuleIndex)
        )
    }

    private static func nextPow2(_ n: Int) -> Int {
        var capacity = 1
        while capacity < n { capacity <<= 1 }
        return capacity
    }
}

/// Public compile entry point.
public enum RuleCompiler {
    /// Parses UTF-8 rule text and compiles it into an immutable snapshot.
    ///
    /// - Parameter input: raw UTF-8 bytes of the rule file (borrowed, zero-copy).
    /// - Throws: `RuleParseError` (typed) with 1-based line/column on failure.
    public static func compile(_ input: UnsafeRawBufferPointer) throws(RuleParseError) -> CompiledRules {
        var sink = RuleSink()
        try RuleParser.parse(input, into: &sink)
        return sink.finish()
    }

    /// Span-based entry (SE-0447) — the preferred zero-copy API where the host
    /// can construct a `RawSpan` (convenience properties need macOS 26+ / iOS 26+).
    @available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
    public static func compile(_ input: RawSpan) throws(RuleParseError) -> CompiledRules {
        try input.withUnsafeBytes { (raw: UnsafeRawBufferPointer) throws(RuleParseError) in
            try compile(raw)
        }
    }
}
