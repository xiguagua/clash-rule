/// 一次匹配中可被求值的类别。
public enum MatchCategory: Sendable, Equatable {
    /// `MATCH` 兜底规则。
    case match
    /// `DOMAIN`（精确域名）。
    case exactDomain
    /// `DOMAIN-SUFFIX`（域名后缀）。
    case suffixDomain
    /// `DOMAIN-KEYWORD`（域名关键字）。
    case keywordDomain
    /// `IP-CIDR` / `IP-CIDR6`（目标地址，IPv4 与 IPv6 合并查询）。
    case targetAddress
    /// `SRC-IP-CIDR`（源地址）。
    case sourceAddress
    /// `DST-PORT`。
    case destinationPort
    /// `SRC-PORT`。
    case sourcePort
    /// `PROCESS-NAME`。
    case processName
    /// `PROCESS-PATH`。
    case processPath
    /// `NETWORK`。
    case network
    /// `DSCP`。
    case dscp
    /// `GEOIP`。
    case geoIP
    /// `AND` / `OR` / `NOT` / `SUB-RULE` 逻辑规则。每条命中的逻辑规则各占一项。
    case logic
}

/// 某个类别在一次匹配中的结果。
public enum CategoryOutcome: Sendable, Equatable {
    /// 请求中缺少该类别所需的输入（例如没有域名）。
    case notApplicable
    /// 规则集中没有该类别的规则。
    case noRules
    /// 有该类别的规则，但没有命中。
    case noMatch
    /// 命中，结果为该类别内的最佳候选。
    case hit(MatchResult)
}

/// 单个类别的求值记录。
public struct CategoryTrace: Sendable, Equatable {
    public let category: MatchCategory
    public let outcome: CategoryOutcome
}

/// `Matcher.explain` 的返回值：每个类别的求值结果，以及最终胜出者。
///
/// 与 `Matcher.match` 不同，`explain` 不做剪枝，每个类别都会被完整求值，
/// 因此可以看到所有候选，而不只是胜出者。`result` 与 `match` 的返回值一致。
public struct MatchTrace: Sendable, Equatable {
    /// 胜出者，未命中为 `nil`。与 `Matcher.match` 的返回值一致。
    public let result: MatchResult?
    /// 按 `match` 的求值顺序列出的各类别结果。
    public let categories: [CategoryTrace]

    /// 胜出规则所在的类别，未命中为 `nil`。
    public var winningCategory: MatchCategory? {
        guard let result else { return nil }
        return categories.first { $0.outcome == .hit(result) }?.category
    }
}

extension Matcher {
    /// 解释一次匹配：列出每个类别的候选结果，不做剪枝。
    ///
    /// 适用于排查"为什么命中这条规则"或"为什么没有命中"。该函数会分配内存，
    /// 不应放在热路径上；热路径请使用 `match`。
    public func explain(context: MatchContext) -> MatchTrace {
        explain(
            domain: context.domain.span,
            targetAddress: context.targetAddress,
            targetPort: context.targetPort,
            sourceAddress: context.sourceAddress,
            sourcePort: context.sourcePort,
            processName: context.processName.span,
            processPath: context.processPath.span,
            network: context.network,
            dscp: context.dscp,
            countryCode: context.countryCode
        )
    }

    /// 与 `match(domain:...)` 参数一致的解释接口。
    public func explain(
        domain: Span<UInt8> = Span(),
        targetAddress: UInt128? = nil,
        targetPort: UInt16 = 0,
        sourceAddress: UInt128? = nil,
        sourcePort: UInt16 = 0,
        processName: Span<UInt8> = Span(),
        processPath: Span<UInt8> = Span(),
        network: NetworkProtocol? = nil,
        dscp: UInt8? = nil,
        countryCode: UInt32 = 0
    ) -> MatchTrace {
        let rules = self.rules
        let bounds = rules.bounds
        var categories: [CategoryTrace] = []

        func record(
            _ category: MatchCategory,
            applicable: Bool,
            hasRules: Bool,
            _ lookup: () -> (policy: UInt16, rule: UInt32)?
        ) {
            guard applicable else {
                categories.append(CategoryTrace(category: category, outcome: .notApplicable))
                return
            }
            guard hasRules else {
                categories.append(CategoryTrace(category: category, outcome: .noRules))
                return
            }
            let outcome: CategoryOutcome = lookup().map {
                .hit(MatchResult(policyID: $0.policy, ruleIndex: $0.rule))
            } ?? .noMatch
            categories.append(CategoryTrace(category: category, outcome: outcome))
        }

        if rules.hasMatchRule {
            categories.append(CategoryTrace(
                category: .match,
                outcome: .hit(MatchResult(policyID: rules.matchPolicy, ruleIndex: rules.matchRuleIndex))
            ))
        } else {
            categories.append(CategoryTrace(category: .match, outcome: .noRules))
        }

        record(.exactDomain, applicable: !domain.isEmpty, hasRules: bounds.minExactRule != UInt32.max) {
            rules.lookupExactDomain(domain)
        }
        record(.dscp, applicable: dscp != nil, hasRules: bounds.minDscpRule != UInt32.max) {
            dscp.flatMap { rules.lookupDSCP($0) }
        }
        record(.network, applicable: network != nil, hasRules: bounds.minNetworkRule != UInt32.max) {
            network.flatMap { rules.lookupNetwork($0) }
        }
        record(.destinationPort, applicable: true, hasRules: bounds.minPortRule != UInt32.max) {
            rules.lookupPort(targetPort, isDestination: true)
        }
        record(.sourcePort, applicable: true, hasRules: bounds.minPortRule != UInt32.max) {
            rules.lookupPort(sourcePort, isDestination: false)
        }
        record(.processName, applicable: !processName.isEmpty, hasRules: bounds.minProcessNameRule != UInt32.max) {
            rules.lookupProcessName(processName)
        }
        record(.processPath, applicable: !processPath.isEmpty, hasRules: bounds.minProcessPathRule != UInt32.max) {
            rules.lookupProcessPath(processPath)
        }
        record(.geoIP, applicable: countryCode != 0, hasRules: bounds.minGeoIPRule != UInt32.max) {
            rules.lookupGeoIP(countryCode)
        }
        record(.suffixDomain, applicable: !domain.isEmpty, hasRules: bounds.minSuffixRule != UInt32.max) {
            rules.lookupSuffix(domain)
        }
        record(
            .targetAddress,
            applicable: targetAddress != nil,
            hasRules: min(bounds.minIPv4Rule, bounds.minIPv6Rule) != UInt32.max
        ) {
            targetAddress.flatMap { rules.lookupAddress($0) }
        }
        record(
            .sourceAddress,
            applicable: sourceAddress != nil,
            hasRules: min(bounds.minSrcIPv4Rule, bounds.minSrcIPv6Rule) != UInt32.max
        ) {
            sourceAddress.flatMap { rules.lookupSourceAddress($0) }
        }
        record(.keywordDomain, applicable: !domain.isEmpty, hasRules: bounds.minKeywordRule != UInt32.max) {
            rules.lookupKeyword(domain, maxRuleIndex: UInt32.max)
        }

        if rules.logicRules.isEmpty {
            categories.append(CategoryTrace(category: .logic, outcome: .noRules))
        } else {
            var anyLogicHit = false
            for logicRule in rules.logicRules {
                let matched = rules.evalLogicNode(
                    Int(logicRule.rootNodeIndex),
                    domain: domain,
                    targetAddress: targetAddress,
                    targetPort: targetPort,
                    sourceAddress: sourceAddress,
                    sourcePort: sourcePort,
                    processName: processName,
                    processPath: processPath,
                    network: network,
                    dscp: dscp,
                    countryCode: countryCode
                )
                guard matched else { continue }
                anyLogicHit = true
                categories.append(CategoryTrace(
                    category: .logic,
                    outcome: .hit(MatchResult(policyID: logicRule.policyID, ruleIndex: logicRule.ruleIndex))
                ))
            }
            if !anyLogicHit {
                categories.append(CategoryTrace(category: .logic, outcome: .noMatch))
            }
        }

        var result: MatchResult? = nil
        for entry in categories {
            guard case let .hit(hit) = entry.outcome else { continue }
            if let current = result, current.ruleIndex <= hit.ruleIndex { continue }
            result = hit
        }
        return MatchTrace(result: result, categories: categories)
    }
}
