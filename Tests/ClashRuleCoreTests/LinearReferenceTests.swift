import Testing
@testable import ClashRuleCore

/// 线性首条匹配的参考实现（仅用于测试）。
///
/// 每条规则单独编译成只含一条规则的快照，请求按规则顺序逐条查询，第一条命中即为结果。
/// 单规则快照只走一条索引路径，不涉及跨规则的合并、剪枝和早停，因此它验证的是
/// 快照合并与仲裁逻辑，而单条规则的语义由 Golden 测试（对照 mihomo）保证。
struct LinearReference {
    struct Verdict: Equatable {
        let policy: String
        let ruleIndex: Int
    }

    private let singles: [(matcher: Matcher, rules: CompiledRules)]

    init(lines: [String]) throws {
        singles = try lines.map { line in
            let rules = try RuleCompiler.compile(line)
            return (Matcher(rules), rules)
        }
    }

    func match(_ context: MatchContext) -> Verdict? {
        for (index, single) in singles.enumerated() {
            if let hit = single.matcher.match(context: context) {
                return Verdict(policy: single.rules.policyName(hit.policyID), ruleIndex: index)
            }
        }
        return nil
    }
}

/// 确定性随机数（SplitMix64）：同一种子生成同一组规则和请求，失败时可以复现。
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// 随机规则与请求的生成器。标签与策略取自小集合，使规则之间会频繁冲突，
/// 从而覆盖"同一键被多条规则占用"的合并路径。
private enum RandomRules {
    static let labels = ["a", "b", "c", "ab"]
    static let tlds = ["com", "net"]
    static let keywords = ["a", "b", "ab", "ca"]
    static let policies = ["P0", "P1", "P2", "DIRECT", "REJECT"]
    static let processNames = ["curl", "wget", "ssh"]
    static let cidrs = ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.0.0.0/16", "192.168.0.0/16"]
    static let portRanges = ["443", "80", "53", "1000-2000", "0-65535"]
    static let ips: [String?] = [nil, "10.0.0.1", "10.1.2.3", "10.1.9.9", "192.168.1.1", "2001:db8::1", "2001:db9::1"]
    static let ports: [UInt16] = [0, 53, 80, 443, 1000, 1500, 2000, 65535]
    static let networks: [NetworkProtocol?] = [nil, .tcp, .udp]
    static let dscps: [UInt8?] = [nil, 0, 46, 63]
    static let countries = ["", "US", "CN"]

    static func pick<T>(_ values: [T], _ generator: inout SplitMix64) -> T {
        values[Int.random(in: 0..<values.count, using: &generator)]
    }

    static func domain(_ generator: inout SplitMix64) -> String {
        let depth = Int.random(in: 1...3, using: &generator)
        var parts: [String] = []
        for _ in 0..<depth {
            parts.append(pick(labels, &generator))
        }
        parts.append(pick(tlds, &generator))
        return parts.joined(separator: ".")
    }

    static func rule(_ generator: inout SplitMix64) -> String {
        let policy = pick(policies, &generator)
        switch Int.random(in: 0..<16, using: &generator) {
        case 0: return "DOMAIN,\(domain(&generator)),\(policy)"
        case 1: return "DOMAIN-SUFFIX,\(domain(&generator)),\(policy)"
        case 2: return "DOMAIN-KEYWORD,\(pick(keywords, &generator)),\(policy)"
        case 3: return "IP-CIDR,\(pick(cidrs, &generator)),\(policy)"
        case 4: return "IP-CIDR,\(pick(cidrs, &generator)),\(policy),no-resolve"
        case 5: return "SRC-IP-CIDR,\(pick(cidrs, &generator)),\(policy)"
        case 6: return "IP-CIDR6,2001:db8::/32,\(policy)"
        case 7: return "DST-PORT,\(pick(portRanges, &generator)),\(policy)"
        case 8: return "SRC-PORT,\(pick(portRanges, &generator)),\(policy)"
        case 9: return "PROCESS-NAME,\(pick(processNames, &generator)),\(policy)"
        case 10: return "PROCESS-PATH,/usr/bin/\(pick(processNames, &generator)),\(policy)"
        case 11: return "NETWORK,\(pick(["tcp", "udp"], &generator)),\(policy)"
        case 12: return "DSCP,\(Int.random(in: 0..<64, using: &generator)),\(policy)"
        case 13: return "GEOIP,\(pick(["US", "CN"], &generator)),\(policy)"
        case 14: return logicRule(policy, &generator)
        default: return "MATCH,\(policy)"
        }
    }

    private static func logicRule(_ policy: String, _ generator: inout SplitMix64) -> String {
        switch Int.random(in: 0..<3, using: &generator) {
        case 0:
            let suffix = domain(&generator)
            return "AND,((DOMAIN-SUFFIX,\(suffix)),(NETWORK,tcp)),\(policy)"
        case 1:
            let exact = domain(&generator)
            return "OR,((DOMAIN,\(exact)),(PORT,443)),\(policy)"
        default:
            return "NOT,((DOMAIN-KEYWORD,ab)),\(policy)"
        }
    }

    static func context(_ generator: inout SplitMix64) -> MatchContext {
        let domainBytes = Int.random(in: 0..<6, using: &generator) == 0 ? [] : Array(domain(&generator).utf8)
        let processName = Int.random(in: 0..<3, using: &generator) == 0 ? Array(pick(processNames, &generator).utf8) : []
        let processPath = Int.random(in: 0..<4, using: &generator) == 0 ? Array("/usr/bin/curl".utf8) : []
        let country = pick(countries, &generator)
        return MatchContext(
            domain: domainBytes,
            targetAddress: pick(ips, &generator).flatMap(parseIPAddress),
            targetPort: pick(ports, &generator),
            sourceAddress: pick(ips, &generator).flatMap(parseIPAddress),
            sourcePort: pick(ports, &generator),
            processName: processName,
            processPath: processPath,
            network: pick(networks, &generator),
            dscp: pick(dscps, &generator),
            countryCode: country.isEmpty ? 0 : packCountryCode(country)
        )
    }
}

@Suite struct LinearReferenceTests {
    @Test func referenceReturnsFirstMatchingLine() throws {
        let reference = try LinearReference(lines: [
            "DOMAIN-SUFFIX,a.com,X",
            "DOMAIN,b.a.com,Y",
            "MATCH,Z",
        ])
        let verdict = reference.match(MatchContext(domain: Array("b.a.com".utf8)))
        #expect(verdict == LinearReference.Verdict(policy: "X", ruleIndex: 0))
        #expect(reference.match(MatchContext(domain: Array("c.org".utf8))) == LinearReference.Verdict(policy: "Z", ruleIndex: 2))
    }

    @Test func indexedMatchAgreesWithLinearFirstMatch() throws {
        var hits = 0
        var misses = 0
        for seed in 0..<200 {
            var generator = SplitMix64(seed: UInt64(seed))
            let count = Int.random(in: 1...30, using: &generator)
            var lines: [String] = []
            for _ in 0..<count {
                lines.append(RandomRules.rule(&generator))
            }

            let rules = try RuleCompiler.compile(lines.joined(separator: "\n"))
            #expect(rules.invariantViolations().isEmpty, "seed \(seed)")
            let matcher = Matcher(rules)
            let reference = try LinearReference(lines: lines)

            for _ in 0..<50 {
                let context = RandomRules.context(&generator)
                let actual = matcher.match(context: context).map {
                    LinearReference.Verdict(policy: rules.policyName($0.policyID), ruleIndex: Int($0.ruleIndex))
                }
                let expected = reference.match(context)
                if expected == nil { misses += 1 } else { hits += 1 }
                #expect(actual == expected, "seed \(seed)\n规则：\(lines)\n请求：\(context)")
                #expect(matcher.explain(context: context).result == matcher.match(context: context), "seed \(seed)")
            }
        }
        #expect(hits > 0)
        #expect(misses > 0)
    }
}
