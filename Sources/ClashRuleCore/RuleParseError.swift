/// A parse failure with 1-based position. Thrown (typed) from `RuleCompiler.compile`.
/// Diagnostics are parse-phase only; they may allocate.
public struct RuleParseError: Error, Sendable, Equatable {
    public enum Code: Sendable, Equatable {
        case unknownRuleType
        case malformedLine
        case invalidArgument
        case invalidPort
        case invalidAddress
        case unknownFlag
        case policyTableFull
        case unknownRuleSet
        case circularRuleSet
    }

    public let code: Code
    /// 1-based line number.
    public let line: Int
    /// 1-based column (byte offset within the line; approximate for multi-byte UTF-8).
    public let column: Int
    public let detail: String

    init(_ code: Code, line: Int, column: Int, _ detail: String = "") {
        self.code = code
        self.line = line
        self.column = column
        self.detail = detail
    }
}

extension RuleParseError: CustomStringConvertible {
    public var description: String {
        "\(line):\(column): error: \(code)\(detail.isEmpty ? "" : " — \(detail)")"
    }
}
