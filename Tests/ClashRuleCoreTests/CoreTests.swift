import Testing
import Foundation
@testable import ClashRuleCore

// MARK: - Fixtures

private func compile(_ text: String) throws -> CompiledRules {
    let data = Data(text.utf8)
    return try data.withUnsafeBytes { try RuleCompiler.compile($0) }
}

private func v4(_ hex: UInt32) -> UInt128 { UInt128(hex) }

private func v6(_ hex: String) -> UInt128 {
    UInt128(hex, radix: 16)!
}

private func matchDomain(
    _ matcher: Matcher,
    _ domain: String,
    address: UInt128? = nil,
    targetPort: UInt16 = 0,
    sourcePort: UInt16 = 0
) -> MatchResult? {
    let bytes = Array(domain.utf8)
    return bytes.withUnsafeBufferPointer {
        matcher.match(domain: $0, targetAddress: address, targetPort: targetPort, sourcePort: sourcePort)
    }
}

// MARK: - Basic matching

@Suite struct MatcherTests {
    private let config = """
        # basic fixture
        DOMAIN,google.com,DIRECT
        DOMAIN-SUFFIX,example.com,Proxy
        DOMAIN-KEYWORD,ads,Block
        IP-CIDR,10.0.0.0/8,LAN
        IP-CIDR,192.168.1.0/24,LAN,no-resolve
        IP-CIDR6,2001:db8::/32,Proxy6
        PORT,80/443,PortDirect
        DST-PORT,8080-8090,DstProxy
        SRC-PORT,1000-2000,SrcDirect
        MATCH,Final
        """

    private func make() throws -> (CompiledRules, Matcher) {
        let rules = try compile(config)
        return (rules, Matcher(rules))
    }

    private func match(
        _ matcher: Matcher,
        domain: String,
        address: UInt128? = nil,
        targetPort: UInt16 = 0,
        sourcePort: UInt16 = 0
    ) -> MatchResult? {
        matchDomain(matcher, domain, address: address, targetPort: targetPort, sourcePort: sourcePort)
    }

    @Test func domainExact() throws {
        let (rules, matcher) = try make()
        let result = match(matcher, domain: "google.com")
        #expect(result != nil)
        #expect(rules.policyName(result!.policyID) == "DIRECT")
        #expect(result!.ruleIndex == 0)
    }

    @Test func domainExactIsCaseInsensitive() throws {
        let rules = try compile("DOMAIN,GOOGLE.com,DIRECT\n")
        let matcher = Matcher(rules)
        let result = match(matcher, domain: "google.COM")
        #expect(result != nil)
        #expect(rules.policyName(result!.policyID) == "DIRECT")
    }

    @Test func domainSuffixMatchesSubdomainAndSelf() throws {
        let (_, matcher) = try make()
        #expect(match(matcher, domain: "www.example.com")!.policyID != 0) // resolves below
        let (rules, m) = try make()
        #expect(rules.policyName(match(m, domain: "www.example.com")!.policyID) == "Proxy")
        #expect(rules.policyName(match(m, domain: "example.com")!.policyID) == "Proxy")
    }

    @Test func domainSuffixRespectsLabelBoundary() throws {
        let (_, matcher) = try make()
        // "notexample.com" must NOT match suffix "example.com".
        let result = match(matcher, domain: "notexample.com")
        #expect(result != nil)
        #expect(rules_name(matcher, result!) == "Final")
    }

    private func rules_name(_ matcher: Matcher, _ result: MatchResult) -> String {
        matcher.rules.policyName(result.policyID)
    }

    @Test func domainKeyword() throws {
        let (rules, matcher) = try make()
        let result = match(matcher, domain: "sub.ads.example.net")
        #expect(rules.policyName(result!.policyID) == "Block")
        // Keyword hit wins over later MATCH but loses to earlier suffix? "ads.example.com" —
        // suffix example.com (index 1) vs keyword ads (index 2): suffix wins.
        let both = match(matcher, domain: "ads.example.com")
        #expect(rules.policyName(both!.policyID) == "Proxy")
    }

    @Test func keywordIsCaseInsensitive() throws {
        let (rules, matcher) = try make()
        let result = match(matcher, domain: "Sub.ADS.Example.NET")
        #expect(rules.policyName(result!.policyID) == "Block")
    }

    @Test func ipv4CIDR() throws {
        let (rules, matcher) = try make()
        #expect(rules.policyName(match(matcher, domain: "", address: v4(0x0A01_0203))!.policyID) == "LAN")   // 10.1.2.3
        #expect(rules.policyName(match(matcher, domain: "", address: v4(0x0A00_0000))!.policyID) == "LAN")   // network address itself
        #expect(rules.policyName(match(matcher, domain: "", address: v4(0xC0A8_0137))!.policyID) == "LAN")   // 192.168.1.55
        #expect(rules.policyName(match(matcher, domain: "", address: v4(0x0B00_0001))!.policyID) == "Final") // 11.0.0.1
    }

    @Test func ipv6CIDR() throws {
        let (rules, matcher) = try make()
        #expect(rules.policyName(match(matcher, domain: "", address: v6("20010db8000000000000000000000001"))!.policyID) == "Proxy6")
        #expect(rules.policyName(match(matcher, domain: "", address: v6("20010db9000000000000000000000001"))!.policyID) == "Final")
    }

    @Test func ports() throws {
        let (rules, matcher) = try make()
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 443)!.policyID) == "PortDirect")
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 8085)!.policyID) == "DstProxy")
        #expect(rules.policyName(match(matcher, domain: "", sourcePort: 1500)!.policyID) == "SrcDirect")
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 21)!.policyID) == "Final")
    }

    @Test func portRuleMatchesSourceOrDestination() throws {
        let rules = try compile("PORT,80,PortRule\nMATCH,Final\n")
        let matcher = Matcher(rules)
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 80)!.policyID) == "PortRule")
        #expect(rules.policyName(match(matcher, domain: "", sourcePort: 80)!.policyID) == "PortRule")
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 81)!.policyID) == "Final")
    }

    @Test func matchFallbackOnlyWhenNothingElseMatches() throws {
        let (_, matcher) = try make()
        #expect(rules_name(matcher, match(matcher, domain: "google.com")!) == "DIRECT")
        #expect(rules_name(matcher, match(matcher, domain: "unknown.host", targetPort: 21)!) == "Final")
    }

    @Test func fileOrderBeatsCategoryEvaluationOrder() throws {
        // Suffix listed first: must win even though exact lookup "runs" first in the matcher.
        let rules = try compile("DOMAIN-SUFFIX,example.com,SuffixFirst\nDOMAIN,example.com,ExactSecond\n")
        let matcher = Matcher(rules)
        #expect(rules.policyName(match(matcher, domain: "example.com")!.policyID) == "SuffixFirst")

        // Exact listed first: exact wins.
        let rules2 = try compile("DOMAIN,example.com,ExactFirst\nDOMAIN-SUFFIX,example.com,SuffixSecond\n")
        let matcher2 = Matcher(rules2)
        #expect(rules2.policyName(match(matcher2, domain: "example.com")!.policyID) == "ExactFirst")
    }

    @Test func emptyConfigMatchesNothing() throws {
        let rules = try compile("")
        #expect(rules.ruleCount == 0)
        let matcher = Matcher(rules)
        #expect(match(matcher, domain: "anything.com", targetPort: 443) == nil)
    }

    @Test func blankLinesAndCommentsIgnored() throws {
        let rules = try compile("\n# comment\n\r\n  \nDOMAIN,google.com,DIRECT\n\n")
        #expect(rules.ruleCount == 1)
    }

    @Test func crlfLineEndings() throws {
        let rules = try compile("DOMAIN,google.com,DIRECT\r\nMATCH,Final\r\n")
        let matcher = Matcher(rules)
        #expect(matchDomain(matcher, "google.com") != nil)
    }

    @Test func overlappingPrefixesPickLowestRuleIndex() throws {
        let rules = try compile(
            "IP-CIDR,10.0.0.0/8,Eight\nIP-CIDR,10.1.0.0/16,Sixteen\nIP-CIDR,10.1.2.0/24,TwentyFour\nMATCH,Final\n"
        )
        let matcher = Matcher(rules)
        // 10.1.2.3 is inside all three; file order decides → "Eight".
        #expect(rules.policyName(match(matcher, domain: "", address: v4(0x0A01_0203))!.policyID) == "Eight")
        // 10.1.3.1 is only inside /8.
        #expect(rules.policyName(match(matcher, domain: "", address: v4(0x0A01_0301))!.policyID) == "Eight")
        // 10.2.0.1 only /8 too; 10.1.2.x covered by all, still lowest index wins.
        #expect(rules.policyName(match(matcher, domain: "", address: v4(0x0A02_0001))!.policyID) == "Eight")
    }
}

// MARK: - Parser errors

@Suite struct ParserErrorTests {
    private func expectError(
        _ text: String, _ code: RuleParseError.Code, line: Int,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let data = Data(text.utf8)
        do {
            _ = try RuleCompiler.compile(data.withUnsafeBytes { $0 })
            Issue.record("expected error \(code) at line \(line), but compile succeeded", sourceLocation: sourceLocation)
        } catch {
            // compile is typed-throws, so `error` is a RuleParseError here.
            #expect(error.code == code, sourceLocation: sourceLocation)
            #expect(error.line == line, sourceLocation: sourceLocation)
        }
    }

    @Test func unknownRuleType() {
        expectError("RULE-SET,myset,DIRECT\n", .unknownRuleType, line: 1)
    }

    @Test func errorLineNumbers() {
        expectError("DOMAIN,google.com,DIRECT\nJUNK,x\n", .unknownRuleType, line: 2)
    }

    @Test func missingPolicy() {
        expectError("DOMAIN,example.com\n", .malformedLine, line: 1)
    }

    @Test func emptyDomain() {
        expectError("DOMAIN,,DIRECT\n", .malformedLine, line: 1)
    }

    @Test func invalidDomainCharacters() {
        expectError("DOMAIN,exa mple.com,DIRECT\n", .invalidArgument, line: 1)
        expectError("DOMAIN,.example.com,DIRECT\n", .invalidArgument, line: 1)
        expectError("DOMAIN,example.com.,DIRECT\n", .invalidArgument, line: 1)
        expectError("DOMAIN,a..b.com,DIRECT\n", .invalidArgument, line: 1)
    }

    @Test func invalidIPv4() {
        expectError("IP-CIDR,256.1.1.0/24,DIRECT\n", .invalidAddress, line: 1)
        expectError("IP-CIDR,10.0.0.0/33,DIRECT\n", .invalidArgument, line: 1)
        expectError("IP-CIDR,10.0.0.0,DIRECT\n", .invalidAddress, line: 1)
        expectError("IP-CIDR,10.0.0/8,DIRECT\n", .invalidAddress, line: 1)
    }

    @Test func invalidIPv6() {
        expectError("IP-CIDR6,2001:db8:::1/32,DIRECT\n", .invalidAddress, line: 1)
        expectError("IP-CIDR6,2001:db8:1:2:3:4:5:6:7/32,DIRECT\n", .invalidAddress, line: 1)
        expectError("IP-CIDR6,2001:db8::zz/32,DIRECT\n", .invalidAddress, line: 1)
        expectError("IP-CIDR6,2001:db8::/129,DIRECT\n", .invalidArgument, line: 1)
    }

    @Test func invalidPorts() {
        expectError("PORT,99999,DIRECT\n", .invalidPort, line: 1)
        expectError("PORT,abc,DIRECT\n", .invalidPort, line: 1)
        expectError("DST-PORT,9000-8000,DIRECT\n", .invalidPort, line: 1)
        expectError("PORT,80,,DIRECT\n", .malformedLine, line: 1)
    }

    @Test func unknownFlag() {
        expectError("IP-CIDR,10.0.0.0/8,DIRECT,fast-path\n", .unknownFlag, line: 1)
        expectError("DOMAIN,example.com,DIRECT,no-resolve\n", .unknownFlag, line: 1)
    }

    @Test func matchRequiresNoArgument() {
        expectError("MATCH,Final,extra\n", .malformedLine, line: 1)
        expectError("MATCH\n", .malformedLine, line: 1)
    }

    @Test func noResolveFlagAcceptedOnCIDR() throws {
        let rules = try compile("IP-CIDR6,2001:db8::/32,L6,no-resolve\n")
        #expect(rules.ruleCount == 1)
    }
}
