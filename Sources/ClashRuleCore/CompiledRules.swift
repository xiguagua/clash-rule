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
    var srcIPv4Nodes: ContiguousArray<IPNode>
    var srcIPv6Nodes: ContiguousArray<IPNode>

    // Ports (sorted by (low, high))
    var portEntries: ContiguousArray<PortEntry>

    // Keywords (linear scan; AC automaton comes later)
    var keywordEntries: ContiguousArray<KeywordEntry>
    var keywordArena: ContiguousArray<UInt8>

    // Process name & path (open addressing, power-of-two capacity)
    var processNameKeys: ContiguousArray<UInt8>
    var processNameEntries: ContiguousArray<ExactEntry>
    var processNameSlotMask: UInt32
    var processPathKeys: ContiguousArray<UInt8>
    var processPathEntries: ContiguousArray<ExactEntry>
    var processPathSlotMask: UInt32

    // Network protocol
    var tcpPolicy: UInt16
    var tcpRuleIndex: UInt32
    var udpPolicy: UInt16
    var udpRuleIndex: UInt32

    // DSCP (64-entry flat table)
    var dscpTable: ContiguousArray<DscpEntry>

    // GeoIP (sorted by countryCode)
    var geoIPEntries: ContiguousArray<GeoIPEntry>

    // Logic rules (AND / OR / NOT / SUB-RULE)
    var logicRules: ContiguousArray<LogicRule>
    var logicNodes: ContiguousArray<LogicNode>
    var logicChildIndices: ContiguousArray<UInt32>
    var logicArena: ContiguousArray<UInt8>

    var matchPolicy: UInt16
    var matchRuleIndex: UInt32
    var hasMatchRule: Bool
    public private(set) var bounds: CategoryBounds

    public var ruleCount: Int

    /// Total heap memory occupied by flat POD arrays and arenas in bytes.
    public var approximateMemoryBytes: Int {
        var total = 0
        total += policyRangesArr.count * MemoryLayout<PolicyRange>.stride
        total += policyArena.count
        total += exactKeys.count
        total += exactEntries.count * MemoryLayout<ExactEntry>.stride
        total += trieLabels.count
        total += trieNodes.count * MemoryLayout<SuffixTrieNode>.stride
        total += trieChildIndices.count * MemoryLayout<UInt32>.stride
        total += ipv4Nodes.count * MemoryLayout<IPNode>.stride
        total += ipv6Nodes.count * MemoryLayout<IPNode>.stride
        total += srcIPv4Nodes.count * MemoryLayout<IPNode>.stride
        total += srcIPv6Nodes.count * MemoryLayout<IPNode>.stride
        total += portEntries.count * MemoryLayout<PortEntry>.stride
        total += keywordEntries.count * MemoryLayout<KeywordEntry>.stride
        total += keywordArena.count
        total += processNameKeys.count + processNameEntries.count * MemoryLayout<ExactEntry>.stride
        total += processPathKeys.count + processPathEntries.count * MemoryLayout<ExactEntry>.stride
        total += dscpTable.count * MemoryLayout<DscpEntry>.stride
        total += geoIPEntries.count * MemoryLayout<GeoIPEntry>.stride
        total += logicRules.count * MemoryLayout<LogicRule>.stride
        total += logicNodes.count * MemoryLayout<LogicNode>.stride
        total += logicChildIndices.count * MemoryLayout<UInt32>.stride
        total += logicArena.count
        return total
    }

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

        // Open-addressing hash table builder for exact domain, process name, and process path.
        func buildOpenAddressing(
            _ map: [ByteKey: (policy: UInt16, rule: UInt32)]
        ) -> (keys: ContiguousArray<UInt8>, entries: ContiguousArray<ExactEntry>, mask: UInt32) {
            var arena = ByteArena()
            var entryArray = ContiguousArray<ExactEntry>()
            var mask: UInt32 = 0
            if !map.isEmpty {
                let capacity = Self.nextPow2(max(16, map.count * 2))
                mask = UInt32(capacity - 1)
                entryArray = ContiguousArray(repeating: ExactEntry(), count: capacity)
                for key in map.keys.sorted(by: { lexLess($0.bytes, $1.bytes) }) {
                    let slot = map[key]!
                    let keyOffset = arena.append(key.bytes)
                    // Same FNV-1a-over-lowered-bytes as query-time `fnv1a(raw)`.
                    let hash = key.hash
                    var position = Int(hash & UInt64(mask))
                    while entryArray[position].keyLength != 0 {
                        position = (position + 1) & Int(mask)
                    }
                    entryArray[position] = ExactEntry(
                        keyOffset: keyOffset,
                        keyLength: UInt16(key.bytes.count),
                        policyID: slot.policy,
                        ruleIndex: slot.rule
                    )
                }
            }
            return (arena.bytes, entryArray, mask)
        }

        let exactTable = buildOpenAddressing(exact)
        let processNameTable = buildOpenAddressing(processName)
        let processPathTable = buildOpenAddressing(processPath)

        // Suffix trie flatten: builder nodes are already arena-indexed
        // (root == 0), so flat indices are reused as-is — no `ObjectIdentifier`
        // map, no recursion. Two linear passes: labels first, then link each
        // node's consecutively-stored child block.
        var trieLabelsArena = ByteArena()
        var trieNodeArray = ContiguousArray<SuffixTrieNode>()
        var trieChildArray = ContiguousArray<UInt32>()
        let buildNodes = trie.nodes
        trieNodeArray.reserveCapacity(buildNodes.count)
        var totalChildren = 0
        for build in buildNodes { totalChildren += build.children.count }
        trieChildArray.reserveCapacity(totalChildren)

        // Pass 1: store labels (flat index == builder index).
        for build in buildNodes {
            let labelOffset = trieLabelsArena.append(build.label.bytes)
            let terminal = build.terminal
            trieNodeArray.append(SuffixTrieNode(
                firstChildEntry: 0,
                childCount: 0,
                isTerminal: terminal != nil,
                labelOffset: labelOffset,
                labelLength: UInt16(build.label.bytes.count),
                policyID: terminal?.policy ?? 0,
                ruleIndex: terminal?.rule ?? 0
            ))
        }

        // Pass 2: link child blocks (each node's entries are appended consecutively).
        // Child order is irrelevant to lookup (linear scan), sorting exists only
        // for deterministic snapshots. Single-child nodes (the common case) skip
        // sorting entirely; multi-child nodes sort (label, child) pairs once with
        // a reused scratch buffer — no per-node allocation, no second hash lookup.
        var scratch: [(key: ByteKey, value: UInt32)] = []
        scratch.reserveCapacity(256)
        for index in 0..<buildNodes.count {
            let build = buildNodes[index]
            let firstChildEntry = UInt32(trieChildArray.count)
            if build.children.count <= 1 {
                for child in build.children.values { trieChildArray.append(child) }
            } else {
                scratch.removeAll(keepingCapacity: true)
                scratch.append(contentsOf: build.children)
                scratch.sort { lexLess($0.key.bytes, $1.key.bytes) }
                for pair in scratch { trieChildArray.append(pair.value) }
            }
            trieNodeArray[index].firstChildEntry = firstChildEntry
            trieNodeArray[index].childCount = UInt16(build.children.count)
        }

        let trieRootIndex: UInt32 = 0

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
        let srcIPv4Array = flattenIPNodes(srcIPv4)
        let srcIPv6Array = flattenIPNodes(srcIPv6)

        // Ports.
        var portArray = ContiguousArray<PortEntry>()
        portArray.reserveCapacity(portMap.count)
        for entry in portMap.values {
            portArray.append(PortEntry(
                low: entry.low,
                high: entry.high,
                dstPolicy: entry.dstPolicy == UInt16.max ? 0 : entry.dstPolicy,
                dstRule: entry.dstRule,
                srcPolicy: entry.srcPolicy == UInt16.max ? 0 : entry.srcPolicy,
                srcRule: entry.srcRule
            ))
        }
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

        // DSCP table.
        var dscpArray = ContiguousArray(repeating: DscpEntry(), count: 64)
        for (val, slot) in dscpMap where val < 64 {
            dscpArray[Int(val)] = DscpEntry(policyID: slot.policy, ruleIndex: slot.rule)
        }

        // GeoIP.
        var geoIPArray = ContiguousArray<GeoIPEntry>()
        for (code, slot) in geoIPMap {
            geoIPArray.append(GeoIPEntry(countryCode: code, policyID: slot.policy, ruleIndex: slot.rule))
        }
        geoIPArray.sort { $0.countryCode < $1.countryCode }

        // Logic rules (sorted by ruleIndex for early-prune arbitration).
        var sortedLogicRules = ContiguousArray(logicRules)
        sortedLogicRules.sort { $0.ruleIndex < $1.ruleIndex }
        let logicNodeArray = ContiguousArray(logicNodes)
        let logicChildArray = ContiguousArray(logicChildIndices)
        let logicArenaBytes = logicArena.bytes

        return CompiledRules(
            policyRangesArr: policyRangeArray,
            policyArena: policyArenaBytes,
            exactKeys: exactTable.keys,
            exactEntries: exactTable.entries,
            exactSlotMask: exactTable.mask,
            trieLabels: trieLabelsArena.bytes,
            trieNodes: trieNodeArray,
            trieChildIndices: trieChildArray,
            trieRoot: trieRootIndex,
            ipv4Nodes: ipv4Array,
            ipv6Nodes: ipv6Array,
            srcIPv4Nodes: srcIPv4Array,
            srcIPv6Nodes: srcIPv6Array,
            portEntries: portArray,
            keywordEntries: keywordArray,
            keywordArena: keywordArenaBytes.bytes,
            processNameKeys: processNameTable.keys,
            processNameEntries: processNameTable.entries,
            processNameSlotMask: processNameTable.mask,
            processPathKeys: processPathTable.keys,
            processPathEntries: processPathTable.entries,
            processPathSlotMask: processPathTable.mask,
            tcpPolicy: tcpRule?.policy ?? 0,
            tcpRuleIndex: tcpRule?.rule ?? UInt32.max,
            udpPolicy: udpRule?.policy ?? 0,
            udpRuleIndex: udpRule?.rule ?? UInt32.max,
            dscpTable: dscpArray,
            geoIPEntries: geoIPArray,
            logicRules: sortedLogicRules,
            logicNodes: logicNodeArray,
            logicChildIndices: logicChildArray,
            logicArena: logicArenaBytes,
            matchPolicy: matchRule?.policy ?? 0,
            matchRuleIndex: matchRule?.rule ?? 0,
            hasMatchRule: matchRule != nil,
            bounds: bounds,
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
    /// 按名字解析外部 `RULE-SET`，以借用方式把规则集原始 UTF-8 字节交给解析器。
    ///
    /// 调用约定（解析器会校验，违反时抛 `.invalidRuleSetResolver`）：
    /// - 找到规则集：**恰好调用一次** `body(bytes)`，然后返回 `true`；
    /// - 未找到：**不调用** `body`，返回 `false`（解析器抛 `.unknownRuleSet`）；
    /// - 宿主加载失败：抛 `RuleParseError.ruleSetLoadFailed(_:)`，解析器会回填行列号；
    /// - `body` 抛出的错误（规则集内容的解析错误）必须原样向外传播，不得吞掉或替换。
    ///
    /// `bytes` 仅在 `body` 调用期间需要有效；解析器不会保留它。
    /// 嵌套 `RULE-SET` 会在 `body` 内部重入同一个 resolver。
    public typealias RuleSetResolver = (
        _ name: Span<UInt8>,
        _ body: (Span<UInt8>) throws(RuleParseError) -> Void
    ) throws(RuleParseError) -> Bool

    /// Parses UTF-8 rule text and compiles it into an immutable snapshot.
    ///
    /// - Parameters:
    ///   - input: raw UTF-8 bytes of the rule file (borrowed, zero-copy).
    ///   - ruleSetResolver: optional callback resolving external RULE-SET references.
    /// - Throws: `RuleParseError` (typed) with 1-based line/column on failure.
    public static func compile(
        _ input: RawSpan,
        ruleSetResolver: RuleSetResolver? = nil
    ) throws(RuleParseError) -> CompiledRules {
        var sink = RuleSink()
        try RuleParser.parse(Span(viewing: input), ruleSetResolver: ruleSetResolver, into: &sink)
        return sink.finish()
    }

    /// Convenience overload taking an in-memory dictionary of rule-set strings.
    public static func compile(
        _ input: RawSpan,
        ruleSets: [String: String]
    ) throws(RuleParseError) -> CompiledRules {
        var byteMap: [[UInt8]: [UInt8]] = [:]
        byteMap.reserveCapacity(ruleSets.count)
        for (name, contents) in ruleSets {
            byteMap[[UInt8](name.utf8)] = [UInt8](contents.utf8)
        }
        return try compile(input, byteRuleSets: byteMap)
    }

    /// Convenience overload taking an in-memory dictionary of byte-array rule sets.
    public static func compile(
        _ input: RawSpan,
        ruleSets: [String: [UInt8]]
    ) throws(RuleParseError) -> CompiledRules {
        var byteMap: [[UInt8]: [UInt8]] = [:]
        byteMap.reserveCapacity(ruleSets.count)
        for (k, v) in ruleSets {
            byteMap[[UInt8](k.utf8)] = v
        }
        return try compile(input, byteRuleSets: byteMap)
    }

    private static func compile(
        _ input: RawSpan,
        byteRuleSets: [[UInt8]: [UInt8]]
    ) throws(RuleParseError) -> CompiledRules {
        var sink = RuleSink()
        try RuleParser.parse(Span(viewing: input), byteRuleSets: byteRuleSets, into: &sink)
        return sink.finish()
    }
}
