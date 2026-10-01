// Flat POD structures stored in the compiled snapshot.
// See docs/PLAN.md §2: fixed-size, trivially copyable, no reference types,
// no enum-with-associated-values unions in index storage.

/// `policyID → (offset, length)` into the policy-name arena.
struct PolicyRange: BitwiseCopyable, Sendable {
    var offset: UInt32 = 0
    var length: UInt16 = 0
}

/// Open-addressing entry for exact `DOMAIN` rules. `keyLength == 0` marks an empty slot.
struct ExactEntry: BitwiseCopyable, Sendable {
    var keyOffset: UInt32 = 0
    var keyLength: UInt16 = 0
    var policyID: UInt16 = 0
    var ruleIndex: UInt32 = 0
}

/// Node of the reversed-label suffix trie (`DOMAIN-SUFFIX`).
/// A node's children are stored contiguously in `CompiledRules.trieChildIndices`.
struct SuffixTrieNode: BitwiseCopyable, Sendable {
    var firstChildEntry: UInt32 = 0 // index into trieChildIndices
    var childCount: UInt16 = 0
    var isTerminal: Bool = false    // a DOMAIN-SUFFIX rule ends here
    var labelOffset: UInt32 = 0
    var labelLength: UInt16 = 0
    var policyID: UInt16 = 0
    var ruleIndex: UInt32 = 0
}

/// Binary radix-trie node for CIDR rules, one node per bit level.
/// Missing child = `.max`; non-terminal = `ruleIndex == .max`.
struct IPNode: BitwiseCopyable, Sendable {
    var left: UInt32 = IPNode.noChild
    var right: UInt32 = IPNode.noChild
    var policyID: UInt16 = 0
    var _padding: UInt16 = 0
    var ruleIndex: UInt32 = IPNode.noRule

    static let noChild = UInt32.max
    static let noRule = UInt32.max
}

/// Interval for `PORT` / `DST-PORT` / `SRC-PORT`. `.max` = side not configured.
struct PortEntry: BitwiseCopyable, Sendable {
    var low: UInt16 = 0
    var high: UInt16 = 0
    var dstPolicy: UInt16 = 0
    var dstRule: UInt32 = PortEntry.noRule
    var srcPolicy: UInt16 = 0
    var srcRule: UInt32 = PortEntry.noRule

    static let noRule = UInt32.max
}

/// Linear-scan entry for `DOMAIN-KEYWORD` (small counts; AC automaton is a later milestone).
struct KeywordEntry: BitwiseCopyable, Sendable {
    var keyOffset: UInt32 = 0
    var keyLength: UInt16 = 0
    var policyID: UInt16 = 0
    var ruleIndex: UInt32 = 0
}
