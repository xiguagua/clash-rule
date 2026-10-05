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
        /// 宿主 `RuleSetResolver` 报告的加载失败（I/O、权限、网络等）。
        case ruleSetLoadFailed
        /// `RuleSetResolver` 违反调用约定（见 `RuleCompiler.RuleSetResolver`）。
        case invalidRuleSetResolver
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

    /// 供 `RuleSetResolver` 报告宿主侧加载失败。
    ///
    /// 行列号由解析器回填为引用该规则集的 `RULE-SET` 行位置，调用方无需关心。
    public static func ruleSetLoadFailed(_ detail: String) -> RuleParseError {
        RuleParseError(.ruleSetLoadFailed, line: 0, column: 0, detail)
    }
}

extension RuleParseError: CustomStringConvertible {
    public var description: String {
        "\(line):\(column): error: \(code)\(detail.isEmpty ? "" : " — \(detail)")"
    }
}
