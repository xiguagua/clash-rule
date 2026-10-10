import ClashRuleCore
import Foundation

#if Diagnostics
private let diagnosticsEnabled = true
#else
private let diagnosticsEnabled = false
#endif

private let warningDisplayLimit = 50

func renderCheck(_ loaded: LoadedRules) -> String {
    let rules = loaded.rules
    let report = loaded.report
    var lines = [
        "编译通过：\(loaded.path)",
        "规则数：\(rules.ruleCount)",
        "策略数：\(rules.policyCount)",
        "快照大小：\(rules.approximateMemoryBytes) 字节",
        "配置指纹：\(hexFingerprint(report.fingerprint))",
    ]
    let warningCount = report.shadowedRules.count + report.unreachableRules.count + report.emptyRuleSets.count
    guard warningCount > 0 else {
        lines.append("警告：无")
        return lines.joined(separator: "\n") + "\n"
    }

    lines.append("警告：覆盖 \(report.shadowedRules.count) 条，MATCH 之后 \(report.unreachableRules.count) 条，空规则集 \(report.emptyRuleSets.count) 个")
    var details = report.shadowedRules.map { shadowedDescription($0, loaded: loaded) }
    details += report.unreachableRules.map { unreachableDescription($0, loaded: loaded) }
    details += report.emptyRuleSets.map { "第 \($0.line) 行引用的规则集 \($0.name) 为空" }
    lines += details.prefix(warningDisplayLimit).map { "  " + $0 }
    if details.count > warningDisplayLimit {
        lines.append("  …… 还有 \(details.count - warningDisplayLimit) 条未显示")
    }
    return lines.joined(separator: "\n") + "\n"
}

private func shadowedDescription(_ shadowed: ShadowedRule, loaded: LoadedRules) -> String {
    let content = lineText(loaded.text, line: shadowed.rule.line)
    let winnerLine = shadowed.shadowedBy.line
    let winnerIsRuleSet = lineText(loaded.text, line: winnerLine).uppercased().hasPrefix("RULE-SET")
    let by = winnerIsRuleSet ? "第 \(winnerLine) 行的规则集" : "第 \(winnerLine) 行"
    return "第 \(shadowed.rule.line) 行 \(content) 被\(by)覆盖，永远不会生效"
}

private func unreachableDescription(_ location: RuleLocation, loaded: LoadedRules) -> String {
    let content = lineText(loaded.text, line: location.line)
    let anchor = loaded.report.firstMatch.map { "第 \($0.line) 行的 MATCH 之后" } ?? "MATCH 之后"
    return "第 \(location.line) 行 \(content) 位于\(anchor)，永远不会生效"
}

private func hexFingerprint(_ value: UInt64) -> String {
    let digits = String(value, radix: 16)
    return "0x" + String(repeating: "0", count: 16 - digits.count) + digits
}

func renderExplain(loaded: LoadedRules, request: [String], trace: MatchTrace) -> String {
    let rules = loaded.rules
    var lines = [
        "规则文件：\(loaded.path)（\(rules.ruleCount) 条规则，\(rules.policyCount) 个策略）",
        "请求：\(request.isEmpty ? "（未指定字段）" : request.joined(separator: "，"))",
    ]
    if !diagnosticsEnabled {
        lines.append("注意：本构建未启用 Diagnostics trait，无法显示源行号；请使用 --traits Diagnostics 重新构建。")
    }
    lines.append("")
    for entry in trace.categories {
        let label = categoryLabel(entry.category).padding(toLength: 22, withPad: " ", startingAt: 0)
        let outcome = describe(entry.outcome, loaded: loaded, winner: trace.result)
        lines.append("  \(label)\(outcome)")
    }
    lines.append("")
    lines.append(summary(trace, loaded: loaded))
    return lines.joined(separator: "\n") + "\n"
}

private func describe(_ outcome: CategoryOutcome, loaded: LoadedRules, winner: MatchResult?) -> String {
    switch outcome {
    case .notApplicable:
        return "跳过（请求未提供该字段）"
    case .noRules:
        return "跳过（规则中没有此类规则）"
    case .noMatch:
        return "未命中"
    case .hit(let hit):
        var description = "命中 #\(hit.ruleIndex) → \(loaded.rules.policyName(hit.policyID))"
        if let line = sourceLine(hit.ruleIndex, in: loaded.rules) {
            let content = lineText(loaded.text, line: line)
            description += "，第 \(line) 行：\(content)"
            if content.uppercased().hasPrefix("RULE-SET") {
                description += "（规则集内部规则）"
            }
        }
        if let winner {
            description += hit == winner ? "  [胜出]" : "  [被 \(ruleReference(winner.ruleIndex, loaded: loaded))覆盖]"
        }
        return description
    }
}

private func summary(_ trace: MatchTrace, loaded: LoadedRules) -> String {
    guard let winner = trace.result else {
        return "结果：未命中"
    }
    let policy = loaded.rules.policyName(winner.policyID)
    let category = trace.winningCategory.map(categoryLabel) ?? "-"
    return "结果：命中 \(ruleReference(winner.ruleIndex, loaded: loaded)) → \(policy)（胜出类别：\(category)）"
}

private func ruleReference(_ ruleIndex: UInt32, loaded: LoadedRules) -> String {
    guard let line = sourceLine(ruleIndex, in: loaded.rules) else { return "#\(ruleIndex)" }
    return "#\(ruleIndex)（第 \(line) 行）"
}

private func categoryLabel(_ category: MatchCategory) -> String {
    switch category {
    case .match: "MATCH"
    case .exactDomain: "DOMAIN"
    case .suffixDomain: "DOMAIN-SUFFIX"
    case .keywordDomain: "DOMAIN-KEYWORD"
    case .targetAddress: "IP-CIDR"
    case .sourceAddress: "SRC-IP-CIDR"
    case .destinationPort: "DST-PORT"
    case .sourcePort: "SRC-PORT"
    case .processName: "PROCESS-NAME"
    case .processPath: "PROCESS-PATH"
    case .network: "NETWORK"
    case .dscp: "DSCP"
    case .geoIP: "GEOIP"
    case .logic: "AND/OR/NOT/SUB-RULE"
    }
}

private func sourceLine(_ ruleIndex: UInt32, in rules: CompiledRules) -> Int? {
#if Diagnostics
    return rules.sourceLine(ofRule: ruleIndex)
#else
    return nil
#endif
}

private func lineText(_ text: String, line: Int) -> String {
    let lines = text.components(separatedBy: "\n")
    guard line >= 1, line <= lines.count else { return "" }
    return lines[line - 1].trimmingCharacters(in: .whitespacesAndNewlines)
}
