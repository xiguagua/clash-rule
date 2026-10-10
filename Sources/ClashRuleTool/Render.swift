import ClashRuleCore
import Foundation

#if Diagnostics
private let diagnosticsEnabled = true
#else
private let diagnosticsEnabled = false
#endif

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
