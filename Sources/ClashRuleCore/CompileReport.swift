/// 编译期诊断报告：描述配置本身的问题（永远不会生效的规则、空规则集）以及配置指纹。
///
/// 报告只在编译时生成，不影响编译结果，也不占用快照内存。
public struct CompileReport: Sendable, Equatable {
    /// 配置内容的 FNV-1a 指纹，覆盖主配置文本与规则集内容。内容相同则指纹相同。
    public let fingerprint: UInt64
    /// 首条 `MATCH` 规则的位置；配置中没有 `MATCH` 时为 `nil`。
    public let firstMatch: RuleLocation?
    /// 被更早的规则完全覆盖、永远不会生效的顶层规则。
    public let shadowedRules: [ShadowedRule]
    /// 位于首条 `MATCH` 之后、永远不会生效的规则。
    public let unreachableRules: [RuleLocation]
    /// 内容为空的规则集。
    public let emptyRuleSets: [EmptyRuleSet]
}

/// 规则在源文件中的位置。
public struct RuleLocation: Sendable, Equatable {
    /// 规则序号（与 `MatchResult.ruleIndex` 一致）。注释和空行不计入序号。
    public let ruleIndex: UInt32
    /// 源文件中的行号（1-based）。RULE-SET 展开出的规则，行号指向 `RULE-SET` 所在行。
    public let line: Int
}

/// 被覆盖的规则：它的所有键都已被更早的规则占用，因此永远不会生效。
public struct ShadowedRule: Sendable, Equatable {
    /// 被覆盖的规则。
    public let rule: RuleLocation
    /// 覆盖它的更早规则。若该规则来自规则集，位置指向 `RULE-SET` 行。
    public let shadowedBy: RuleLocation
}

/// 内容为空的规则集。
public struct EmptyRuleSet: Sendable, Equatable {
    /// 规则集名称。
    public let name: String
    /// 引用该规则集的 `RULE-SET` 行号。
    public let line: Int
}

/// 带诊断报告的编译结果。
public struct CompileResult: Sendable {
    public let rules: CompiledRules
    public let report: CompileReport
}
