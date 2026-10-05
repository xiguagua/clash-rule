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
    var maxHigh: UInt16 = 0
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

/// Entry for `GEOIP`. Stored sorted by `countryCode`.
struct GeoIPEntry: BitwiseCopyable, Sendable {
    var countryCode: UInt32 = 0
    var policyID: UInt16 = 0
    var _padding: UInt16 = 0
    var ruleIndex: UInt32 = 0
}

/// Entry for `DSCP`.
struct DscpEntry: BitwiseCopyable, Sendable {
    var policyID: UInt16 = 0
    var _padding: UInt16 = 0
    var ruleIndex: UInt32 = DscpEntry.noRule

    static let noRule = UInt32.max
}

/// Opcode for nodes in the flat logic expression tree.
public enum LogicOp: UInt8, BitwiseCopyable, Sendable {
    case and = 1
    case or = 2
    case not = 3
    case domain = 4
    case domainSuffix = 5
    case domainKeyword = 6
    case ipCIDR = 7
    case port = 8
    case processName = 9
    case processPath = 10
    case network = 11
    case dscp = 12
    case geoIP = 13
}

/// Flat POD node in the logic expression tree.
struct LogicNode: BitwiseCopyable, Sendable {
    var op: UInt8 = 0
    var flags: UInt8 = 0            // bit 0: isIPv6, bit 1: isSource, bits 2..3: portSide (0=either, 1=dst, 2=src)
    var childCount: UInt16 = 0      // number of children for AND/OR
    var firstChildIndex: UInt32 = 0 // start index in logicChildIndices (AND/OR) or child node index (NOT)
    var argOffset: UInt32 = 0       // offset in logicArena (for strings)
    var argLength: UInt16 = 0       // string length or high port
    var portLow: UInt16 = 0         // low port or dscp
    var addressLow: UInt64 = 0      // low 64 bits of IP address
    var addressHigh: UInt64 = 0     // high 64 bits of IP address
    var prefix: UInt8 = 0           // CIDR prefix length
    var networkProto: UInt8 = 0     // 1=tcp, 2=udp
    var _padding: UInt16 = 0
    var countryCode: UInt32 = 0     // packed country code
}

/// Compiled logic rule (AND / OR / NOT / SUB-RULE).
struct LogicRule: BitwiseCopyable, Sendable {
    var rootNodeIndex: UInt32 = 0
    var policyID: UInt16 = 0
    var _padding: UInt16 = 0
    var ruleIndex: UInt32 = 0
}

/// Earliest rule indices per category used for bounded short-circuit pruning.
public struct CategoryBounds: BitwiseCopyable, Sendable {
    public var minExactRule: UInt32 = UInt32.max
    public var minSuffixRule: UInt32 = UInt32.max
    public var minKeywordRule: UInt32 = UInt32.max
    public var minIPv4Rule: UInt32 = UInt32.max
    public var minIPv6Rule: UInt32 = UInt32.max
    public var minSrcIPv4Rule: UInt32 = UInt32.max
    public var minSrcIPv6Rule: UInt32 = UInt32.max
    public var minPortRule: UInt32 = UInt32.max
    public var minProcessNameRule: UInt32 = UInt32.max
    public var minProcessPathRule: UInt32 = UInt32.max
    public var minNetworkRule: UInt32 = UInt32.max
    public var minDscpRule: UInt32 = UInt32.max
    public var minGeoIPRule: UInt32 = UInt32.max
    public var minLogicRule: UInt32 = UInt32.max

    public init() {}
}
