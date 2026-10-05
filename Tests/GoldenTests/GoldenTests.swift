import Testing
import Foundation
@testable import ClashRuleCore

// MARK: - IP & Context Helpers

private func parseIP(_ str: String) -> UInt128? {
    var sin = sockaddr_in()
    if inet_pton(AF_INET, str, &sin.sin_addr) == 1 {
        let v = UInt32(bigEndian: sin.sin_addr.s_addr)
        return UInt128(v)
    }
    var sin6 = sockaddr_in6()
    if inet_pton(AF_INET6, str, &sin6.sin6_addr) == 1 {
        let b = withUnsafeBytes(of: &sin6.sin6_addr) { Array($0) }
        var v: UInt128 = 0
        for byte in b {
            v = (v << 8) | UInt128(byte)
        }
        return v
    }
    return nil
}

private func parseCountryCode(_ str: String) -> UInt32 {
    guard str.count >= 2 else { return 0 }
    var code: UInt32 = 0
    for b in str.utf8 {
        let upper: UInt8 = (b >= UInt8(ascii: "a") && b <= UInt8(ascii: "z")) ? (b - 32) : b
        code = (code << 8) | UInt32(upper)
    }
    return code
}

// MARK: - JSON DTOs

private struct TestCaseDTO: Decodable {
    let id: String
    let description: String
    let rule_set: String
    let request: RequestDTO
    let expected: ExpectedDTO
}

private struct RequestDTO: Decodable {
    let domain: String?
    let target_ip: String?
    let target_port: UInt16?
    let source_ip: String?
    let source_port: UInt16?
    let process_name: String?
    let process_path: String?
    let network: String?
    let dscp: UInt8?
    let geoip: String?
}

private struct ExpectedDTO: Decodable {
    let matched: Bool
    let policy: String
    let rule_type: String?
}

// MARK: - Fixtures Loader

private func loadFixtureData(relativePath: String) throws -> Data {
    #if SWIFT_PACKAGE
    if let url = Bundle.module.url(forResource: relativePath, withExtension: nil) {
        return try Data(contentsOf: url)
    }
    if let url = Bundle.module.url(forResource: "Fixtures/" + relativePath, withExtension: nil) {
        return try Data(contentsOf: url)
    }
    #endif

    // Fallback: search relative to source directory
    let candidates = [
        "Tests/GoldenTests/Fixtures/" + relativePath,
        "Fixtures/" + relativePath,
        "../../Tests/GoldenTests/Fixtures/" + relativePath
    ]
    for candidate in candidates {
        let url = URL(fileURLWithPath: candidate)
        if FileManager.default.fileExists(atPath: url.path) {
            return try Data(contentsOf: url)
        }
    }
    throw CocoaError(.fileNoSuchFile)
}

// MARK: - Test Suites

@Suite struct GoldenMihomoParityTests {

    @Test func verifyAllOracleCasesAgainstMihomo() throws {
        let casesData = try loadFixtureData(relativePath: "golden_cases.json")
        let testCases = try JSONDecoder().decode([TestCaseDTO].self, from: casesData)
        #expect(!testCases.isEmpty, "golden_cases.json should contain test cases")

        // Group test cases by rule_set
        var casesByRuleSet: [String: [TestCaseDTO]] = [:]
        for tc in testCases {
            casesByRuleSet[tc.rule_set, default: []].append(tc)
        }

        for (ruleSetPath, cases) in casesByRuleSet {
            let ruleData = try loadFixtureData(relativePath: ruleSetPath)

            // Compile the rule set
            let compiledRules: CompiledRules
            if ruleSetPath.hasSuffix(".list") {
                // Rule-set payload file (e.g. community lists)
                // When mihomo evaluated these, default policy was PROXY for telegram/proxylite, DIRECT for lan/apple
                let defaultPolicy = ruleSetPath.contains("telegram") || ruleSetPath.contains("proxylite") ? "PROXY" : "DIRECT"
                let rootConfig = "RULE-SET,payload_list,\(defaultPolicy)\n"
                let rootBytes = Array(rootConfig.utf8)
                compiledRules = try RuleCompiler.compile(
                    rootBytes.span.bytes,
                    ruleSets: ["payload_list": [UInt8](ruleData)]
                )
            } else {
                compiledRules = try RuleCompiler.compile(ruleData.bytes)
            }

            let matcher = Matcher(compiledRules)

            // Test each case under this rule set
            for tc in cases {
                let domainBytes = [UInt8]((tc.request.domain ?? "").utf8)
                let procNameBytes = [UInt8]((tc.request.process_name ?? "").utf8)
                let procPathBytes = [UInt8]((tc.request.process_path ?? "").utf8)

                let netProto: NetworkProtocol? = {
                    guard let n = tc.request.network?.lowercased() else { return nil }
                    if n == "tcp" { return .tcp }
                    if n == "udp" { return .udp }
                    return nil
                }()

                let targetAddr = tc.request.target_ip.flatMap(parseIP)
                let sourceAddr = tc.request.source_ip.flatMap(parseIP)
                let country = tc.request.geoip.map(parseCountryCode) ?? 0

                let matchedResult = matcher.match(
                    domain: domainBytes.span,
                    targetAddress: targetAddr,
                    targetPort: tc.request.target_port ?? 0,
                    sourceAddress: sourceAddr,
                    sourcePort: tc.request.source_port ?? 0,
                    processName: procNameBytes.span,
                    processPath: procPathBytes.span,
                    network: netProto,
                    dscp: tc.request.dscp,
                    countryCode: country
                )

                if tc.expected.matched {
                    #expect(
                        matchedResult != nil,
                        "Case [\(tc.id): \(tc.description)] expected match on policy '\(tc.expected.policy)', but got nil"
                    )
                    if let res = matchedResult {
                        let actualPolicy = compiledRules.policyName(res.policyID)
                        #expect(
                            actualPolicy == tc.expected.policy,
                            "Case [\(tc.id): \(tc.description)] policy mismatch: expected '\(tc.expected.policy)', got '\(actualPolicy)'"
                        )
                    }
                } else {
                    #expect(
                        matchedResult == nil,
                        "Case [\(tc.id): \(tc.description)] expected no match, but got policy '\(matchedResult.map { compiledRules.policyName($0.policyID) } ?? "")'"
                    )
                }
            }
        }
    }
}

@Suite struct CommunityRuleSetsIntegrationTests {

    @Test func verifyEndToEndRealisticClashConfig() throws {
        let lanData = try loadFixtureData(relativePath: "community/acl4ssr_lan.list")
        let appleData = try loadFixtureData(relativePath: "community/blackmatrix7_apple.list")
        let telegramData = try loadFixtureData(relativePath: "community/blackmatrix7_telegram.list")
        let proxyLiteData = try loadFixtureData(relativePath: "community/acl4ssr_proxylite.list")

        let configText = """
        # Realistic Clash Config with 4 Community Rule-Sets
        RULE-SET,lan,DIRECT
        RULE-SET,apple,APPLE-POLICY
        RULE-SET,telegram,TELEGRAM-PROXY
        RULE-SET,proxylite,GENERAL-PROXY
        GEOIP,CN,DIRECT
        MATCH,FINAL-FALLBACK
        """

        let configBytes = Array(configText.utf8)
        let compiled = try RuleCompiler.compile(
            configBytes.span.bytes,
            ruleSets: [
                "lan": [UInt8](lanData),
                "apple": [UInt8](appleData),
                "telegram": [UInt8](telegramData),
                "proxylite": [UInt8](proxyLiteData),
            ]
        )

        let matcher = Matcher(compiled)

        func check(
            domain: String? = nil,
            ip: String? = nil,
            port: UInt16 = 0,
            proc: String? = nil,
            geoip: String? = nil,
            expected: String
        ) {
            let dBytes = [UInt8]((domain ?? "").utf8)
            let pBytes = [UInt8]((proc ?? "").utf8)
            let ipAddr = ip.flatMap(parseIP)
            let country = geoip.map(parseCountryCode) ?? 0

            let res = matcher.match(
                domain: dBytes.span,
                targetAddress: ipAddr,
                targetPort: port,
                processName: pBytes.span,
                countryCode: country
            )

            #expect(res != nil, "Expected match for domain=\(domain ?? "-"), ip=\(ip ?? "-")")
            if let r = res {
                let actual = compiled.policyName(r.policyID)
                #expect(actual == expected, "Expected '\(expected)', got '\(actual)' for domain=\(domain ?? "-"), ip=\(ip ?? "-")")
            }
        }

        // 1. LAN matches DIRECT
        check(domain: "localhost", expected: "DIRECT")
        check(ip: "10.0.0.1", expected: "DIRECT")
        check(ip: "192.168.1.10", expected: "DIRECT")
        check(ip: "172.20.0.5", expected: "DIRECT")

        // 2. Apple matches APPLE-POLICY
        check(domain: "apple.com", expected: "APPLE-POLICY")
        check(domain: "store.apple.com", expected: "APPLE-POLICY")
        check(domain: "icons.axm-usercontent-apple.com", expected: "APPLE-POLICY")

        // 3. Telegram matches TELEGRAM-PROXY
        check(domain: "t.me", expected: "TELEGRAM-PROXY")
        check(domain: "web.telegram.org", expected: "TELEGRAM-PROXY")
        check(ip: "91.108.4.1", expected: "TELEGRAM-PROXY")
        check(proc: "Telegram.exe", expected: "TELEGRAM-PROXY")

        // 4. ProxyLite matches GENERAL-PROXY
        check(domain: "reddit.com", expected: "GENERAL-PROXY")
        check(domain: "notion.so", expected: "GENERAL-PROXY")
        check(domain: "1password.com", expected: "GENERAL-PROXY")

        // 5. GeoIP fallback
        check(ip: "114.114.114.114", geoip: "CN", expected: "DIRECT")

        // 6. Unknown domain falls through to FINAL-FALLBACK
        check(domain: "totally-unknown-service.xyz", ip: "1.2.3.4", expected: "FINAL-FALLBACK")
    }
}
