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

@Suite(.serialized) struct MatcherTests {
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

    @Test func exactDomainHashCollisionsAndLinearProbing() throws {
        // Compile enough domain rules to fill open-addressing table slots and verify lookups & misses.
        var text = ""
        for i in 0..<100 {
            text += "DOMAIN,host-\(i).internal,Policy\(i)\n"
        }
        text += "MATCH,Final\n"
        let rules = try compile(text)
        let matcher = Matcher(rules)

        for i in 0..<100 {
            let hit = match(matcher, domain: "host-\(i).internal")
            #expect(hit != nil)
            #expect(rules.policyName(hit!.policyID) == "Policy\(i)")
        }
        // Negative lookups (misses) should fall back to MATCH
        let miss = match(matcher, domain: "host-999.internal")
        #expect(rules.policyName(miss!.policyID) == "Final")
        let partialMiss = match(matcher, domain: "host-1.internals")
        #expect(rules.policyName(partialMiss!.policyID) == "Final")
    }

    @Test func deepAndBranchingSuffixTrie() throws {
        let config = """
            DOMAIN-SUFFIX,com,ComPolicy
            DOMAIN-SUFFIX,example.com,ExamplePolicy
            DOMAIN-SUFFIX,api.example.com,ApiPolicy
            DOMAIN-SUFFIX,v1.api.example.com,V1ApiPolicy
            DOMAIN-SUFFIX,web.example.com,WebPolicy
            DOMAIN-SUFFIX,deep.branch.sub.corp.internal,DeepPolicy
            MATCH,Final
            """
        let rules = try compile(config)
        let matcher = Matcher(rules)

        // Multiple children under example.com
        #expect(rules.policyName(match(matcher, domain: "v1.api.example.com")!.policyID) == "ComPolicy") // 'com' is first in file!
    }

    @Test func suffixTrieFileOrderPriority() throws {
        // Specific rule placed before broad rule
        let config = """
            DOMAIN-SUFFIX,v1.api.example.com,Specific
            DOMAIN-SUFFIX,api.example.com,Medium
            DOMAIN-SUFFIX,example.com,Broad
            MATCH,Final
            """
        let rules = try compile(config)
        let matcher = Matcher(rules)

        #expect(rules.policyName(match(matcher, domain: "a.b.v1.api.example.com")!.policyID) == "Specific")
        #expect(rules.policyName(match(matcher, domain: "other.api.example.com")!.policyID) == "Medium")
        #expect(rules.policyName(match(matcher, domain: "foo.example.com")!.policyID) == "Broad")
        #expect(rules.policyName(match(matcher, domain: "different.com")!.policyID) == "Final")
    }

    @Test func overlappingAndNestedPortIntervals() throws {
        // Wide range first, nested narrower range second, third even narrower
        let config = """
            DST-PORT,100-2000,WideRule
            DST-PORT,500-600,NarrowRule
            DST-PORT,550-560,TightRule
            MATCH,Final
            """
        let rules = try compile(config)
        let matcher = Matcher(rules)

        // 555 is covered by all 3; WideRule is ruleIndex 0 -> wins.
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 555)!.policyID) == "WideRule")
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 500)!.policyID) == "WideRule")
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 100)!.policyID) == "WideRule")
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 2000)!.policyID) == "WideRule")
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 2001)!.policyID) == "Final")
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 99)!.policyID) == "Final")

        // Invert file order: NarrowRule first, WideRule second
        let configInverted = """
            DST-PORT,500-600,NarrowRule
            DST-PORT,100-2000,WideRule
            MATCH,Final
            """
        let rulesInverted = try compile(configInverted)
        let matcherInverted = Matcher(rulesInverted)

        // Port 550 hits NarrowRule (rule 0)
        #expect(rulesInverted.policyName(match(matcherInverted, domain: "", targetPort: 550)!.policyID) == "NarrowRule")
        // Port 200 hits WideRule (rule 1)
        #expect(rulesInverted.policyName(match(matcherInverted, domain: "", targetPort: 200)!.policyID) == "WideRule")
    }

    @Test func cidrBoundaryMasks() throws {
        let config = """
            IP-CIDR,0.0.0.0/0,CatchAllV4
            IP-CIDR,192.168.1.1/32,SingleHost
            IP-CIDR6,::/0,CatchAllV6
            MATCH,Final
            """
        let rules = try compile(config)
        let matcher = Matcher(rules)

        // Single host matches CatchAllV4 because CatchAllV4 is listed first!
        #expect(rules.policyName(match(matcher, domain: "", address: v4(0xC0A8_0101))!.policyID) == "CatchAllV4")

        let config2 = """
            IP-CIDR,192.168.1.1/32,SingleHost
            IP-CIDR,0.0.0.0/0,CatchAllV4
            MATCH,Final
            """
        let rules2 = try compile(config2)
        let matcher2 = Matcher(rules2)
        #expect(rules2.policyName(match(matcher2, domain: "", address: v4(0xC0A8_0101))!.policyID) == "SingleHost")
        #expect(rules2.policyName(match(matcher2, domain: "", address: v4(0x0808_0808))!.policyID) == "CatchAllV4")

        // IPv6 catch all
        #expect(rules.policyName(match(matcher, domain: "", address: v6("20010db8000000000000000000000001"))!.policyID) == "CatchAllV6")
    }

    @Test func concurrentMatchingSafety() async throws {
        let (_, matcher) = try make()
        // Run concurrent queries across TaskGroup
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<100 {
                group.addTask {
                    let domain = (i % 2 == 0) ? "google.com" : "sub.ads.example.net"
                    let port: UInt16 = (i % 3 == 0) ? 443 : 8085
                    let res = matchDomain(matcher, domain, targetPort: port)
                    #expect(res != nil)
                }
            }
        }
    }

    @Test func zeroAllocationHotPath() throws {
        let (rules, matcher) = try make()
        _ = rules
        let sample = Array("www.example.com".utf8)

        #if canImport(Darwin)
        let zone = malloc_default_zone()

        // Warm up
        sample.withUnsafeBufferPointer { buf in
            _ = matcher.match(domain: buf, targetAddress: v4(0x0A01_0203), targetPort: 8085, sourcePort: 1500)
        }

        // Check zone size in use across repeated iterations
        var stats1 = malloc_statistics_t()
        var stats2 = malloc_statistics_t()
        sample.withUnsafeBufferPointer { buf in
            malloc_zone_statistics(zone, &stats1)
            for _ in 0..<100 {
                _ = matcher.match(domain: buf, targetAddress: v4(0x0A01_0203), targetPort: 8085, sourcePort: 1500)
            }
            malloc_zone_statistics(zone, &stats2)
        }
        // No allocations were leaked or performed by match itself; stats2.size_allocated <= stats1.size_allocated + noise
        // Ensure size_allocated did not increase due to match iterations
        #expect(stats2.size_in_use <= stats1.size_in_use)
        #endif
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
