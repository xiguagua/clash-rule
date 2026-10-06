import Testing
import Foundation
@testable import ClashRuleCore

// MARK: - Fixtures

private func compile(_ text: String) throws -> CompiledRules {
    try RuleCompiler.compile(text)
}

private func v4(_ hex: UInt32) -> UInt128 { UInt128(hex) }

private func v6(_ hex: String) -> UInt128 {
    UInt128(hex, radix: 16)!
}

@Suite struct IPAddressParsingTests {
    @Test func parsesIPv4WithoutChangingByteOrder() {
        #expect(parseIPAddress("0.0.0.0") == UInt128(0))
        #expect(parseIPAddress("10.0.0.1") == UInt128(0x0A00_0001))
        #expect(parseIPAddress("255.255.255.255") == UInt128(UInt32.max))
    }

    @Test func parsesFullAndCompressedIPv6() {
        let expanded = v6("20010db8000000000000000000000001")
        #expect(parseIPAddress("2001:db8:0:0:0:0:0:1") == expanded)
        #expect(parseIPAddress("2001:db8::1") == expanded)
        #expect(parseIPAddress("2001:DB8::1") == expanded)
        #expect(parseIPAddress("1::2:3") == v6("00010000000000000000000000020003"))
        #expect(parseIPAddress("::") == UInt128(0))
        #expect(parseIPAddress("::1") == UInt128(1))
        #expect(parseIPAddress("1::") == v6("00010000000000000000000000000000"))
    }

    @Test func rejectsMalformedAddressesAndOverflow() {
        for address in [
            "", "1.2.3", "1.2.3.4.5", "1.2.3.256", "4294967296.0.0.1",
            "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1::2::3",
            "1:2:3:4:5:6:7::8", ":1:2:3:4:5:6:7", "2001:db8::g",
        ] {
            #expect(parseIPAddress(address) == nil, "accepted invalid IP: \(address)")
        }
    }
}

private func matchDomain(
    _ matcher: Matcher,
    _ domain: String,
    address: UInt128? = nil,
    targetPort: UInt16 = 0,
    sourcePort: UInt16 = 0
) -> MatchResult? {
    let bytes = Array(domain.utf8)
    return matcher.match(domain: bytes.span, targetAddress: address, targetPort: targetPort, sourcePort: sourcePort)
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

    @Test func portZeroMatchesLikeMihomo() throws {
        // mihomo Port.Match 无 0 守卫：未指定端口 (0) 可命中 DST-PORT,0。
        let rules = try compile("DST-PORT,0,ZeroPort\nMATCH,Final\n")
        let matcher = Matcher(rules)
        #expect(rules.policyName(match(matcher, domain: "", targetPort: 0)!.policyID) == "ZeroPort")
        let srcRules = try compile("SRC-PORT,0,ZeroSrc\nMATCH,Final\n")
        let srcMatcher = Matcher(srcRules)
        #expect(srcRules.policyName(match(srcMatcher, domain: "", sourcePort: 0)!.policyID) == "ZeroSrc")
    }

    @Test func ambiguousLowAddressConsultsBothTries() throws {
        // UInt128(1) 既是 0.0.0.1 也是 ::1：高位全零时双 trie 都查。
        let v6Only = try compile("IP-CIDR6,::/0,V6All\nMATCH,Final\n")
        let v6Matcher = Matcher(v6Only)
        #expect(v6Only.policyName(match(v6Matcher, domain: "", address: UInt128(1))!.policyID) == "V6All")
    }

    @Test func dualStackSameValueLowestRuleWins() throws {
        let v4First = try compile("IP-CIDR,0.0.0.1/32,V4Host\nIP-CIDR6,::1/128,V6Host\nMATCH,Final\n")
        let m1 = Matcher(v4First)
        #expect(v4First.policyName(match(m1, domain: "", address: UInt128(1))!.policyID) == "V4Host")
        let v6First = try compile("IP-CIDR6,::1/128,V6Host\nIP-CIDR,0.0.0.1/32,V4Host\nMATCH,Final\n")
        let m2 = Matcher(v6First)
        #expect(v6First.policyName(match(m2, domain: "", address: UInt128(1))!.policyID) == "V6Host")
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
        _ = matcher.match(domain: sample.span, targetAddress: v4(0x0A01_0203), targetPort: 8085, sourcePort: 1500)

        // Check zone size in use across repeated iterations
        var stats1 = malloc_statistics_t()
        var stats2 = malloc_statistics_t()
        malloc_zone_statistics(zone, &stats1)
        for _ in 0..<100 {
            _ = matcher.match(domain: sample.span, targetAddress: v4(0x0A01_0203), targetPort: 8085, sourcePort: 1500)
        }
        malloc_zone_statistics(zone, &stats2)
        // No allocations were leaked or performed by match itself; stats2.size_allocated <= stats1.size_allocated + noise
        // Ensure size_allocated did not increase due to match iterations
        #expect(stats2.size_in_use <= stats1.size_in_use)
        #endif
    }

    @Test func sourceIPCIDR() throws {
        let text = """
            SRC-IP-CIDR,192.168.1.100/32,SrcDirect
            SRC-IP-CIDR,10.0.0.0/8,SrcLAN
            SRC-IP-CIDR6,2001:db8:1::/48,SrcV6
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        // Matching source IPv4
        let res1 = matcher.match(sourceAddress: v4(0xC0A8_0164))
        #expect(res1?.policyID == 0)
        #expect(rules.policyName(res1!.policyID) == "SrcDirect")

        // Matching subnet
        let res2 = matcher.match(sourceAddress: v4(0x0A05_0505))
        #expect(rules.policyName(res2!.policyID) == "SrcLAN")

        // Destination IP must not trigger SRC-IP-CIDR
        let res3 = matcher.match(targetAddress: v4(0x0A05_0505))
        #expect(rules.policyName(res3!.policyID) == "Fallback")

        // Matching source IPv6
        let res4 = matcher.match(sourceAddress: v6("20010db8000100000000000000000001"))
        #expect(rules.policyName(res4!.policyID) == "SrcV6")
    }

    @Test func processNameAndPath() throws {
        let text = """
            PROCESS-NAME,curl,CurlPolicy
            PROCESS-NAME,Telegram.exe,TelegramPolicy
            PROCESS-PATH,/usr/local/bin/git,GitPolicy
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let curl = Array("curl".utf8)
        let curlUpper = Array("CURL".utf8)
        let telegram = Array("telegram.exe".utf8)
        let gitPath = Array("/usr/local/bin/git".utf8)
        let other = Array("wget".utf8)

        let res1 = matcher.match(processName: curl.span)
        #expect(rules.policyName(res1!.policyID) == "CurlPolicy")

        let res2 = matcher.match(processName: curlUpper.span)
        #expect(rules.policyName(res2!.policyID) == "CurlPolicy")

        let res3 = matcher.match(processName: telegram.span)
        #expect(rules.policyName(res3!.policyID) == "TelegramPolicy")

        let res4 = matcher.match(processPath: gitPath.span)
        #expect(rules.policyName(res4!.policyID) == "GitPolicy")

        let res5 = matcher.match(processName: other.span)
        #expect(rules.policyName(res5!.policyID) == "Fallback")
    }

    @Test func networkProtocol() throws {
        let text = """
            NETWORK,tcp,TCPPolicy
            NETWORK,udp,UDPPolicy
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let resTCP = matcher.match(network: .tcp)
        #expect(rules.policyName(resTCP!.policyID) == "TCPPolicy")

        let resUDP = matcher.match(network: .udp)
        #expect(rules.policyName(resUDP!.policyID) == "UDPPolicy")

        let resNone = matcher.match()
        #expect(rules.policyName(resNone!.policyID) == "Fallback")
    }

    @Test func dscp() throws {
        let text = """
            DSCP,4,DSCP4Policy
            DSCP,46,EFPolicy
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let res1 = matcher.match(dscp: 4)
        #expect(rules.policyName(res1!.policyID) == "DSCP4Policy")

        let res2 = matcher.match(dscp: 46)
        #expect(rules.policyName(res2!.policyID) == "EFPolicy")

        let res3 = matcher.match(dscp: 10)
        #expect(rules.policyName(res3!.policyID) == "Fallback")
    }

    @Test func geoIP() throws {
        let text = """
            GEOIP,CN,ChinaPolicy
            GEOIP,US,USPolicy
            GEOIP,LAN,LanPolicy,no-resolve
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let resCN = matcher.match(countryCode: packCountryCode("CN"))
        #expect(rules.policyName(resCN!.policyID) == "ChinaPolicy")

        // Lowercase query pack
        let resCNLower = matcher.match(countryCode: packCountryCode("cn"))
        #expect(rules.policyName(resCNLower!.policyID) == "ChinaPolicy")

        let resUS = matcher.match(countryCode: packCountryCode("US"))
        #expect(rules.policyName(resUS!.policyID) == "USPolicy")

        let resLAN = matcher.match(countryCode: packCountryCode("LAN"))
        #expect(rules.policyName(resLAN!.policyID) == "LanPolicy")

        let resJP = matcher.match(countryCode: packCountryCode("JP"))
        #expect(rules.policyName(resJP!.policyID) == "Fallback")
    }

    @Test func multiCategoryPriorityArbitration() throws {
        let text = """
            # Rule 0: Process matches
            PROCESS-NAME,curl,ProcessRule
            # Rule 1: Domain matches
            DOMAIN,example.com,DomainRule
            # Rule 2: GeoIP matches
            GEOIP,CN,GeoRule
            # Rule 3: Network matches
            NETWORK,tcp,NetworkRule
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let domain = Array("example.com".utf8)
        let proc = Array("curl".utf8)

        // Process (rule 0) beats Domain (rule 1), Geo (rule 2), Network (rule 3)
        let resProcess = matcher.match(
            domain: domain.span,
            processName: proc.span,
            network: .tcp,
            countryCode: packCountryCode("CN")
        )
        #expect(resProcess?.ruleIndex == 0)
        #expect(rules.policyName(resProcess!.policyID) == "ProcessRule")

        // Without process, Domain (rule 1) beats Geo (rule 2) and Network (rule 3)
        let resDomain = matcher.match(
            domain: domain.span,
            network: .tcp,
            countryCode: packCountryCode("CN")
        )
        #expect(resDomain?.ruleIndex == 1)
        #expect(rules.policyName(resDomain!.policyID) == "DomainRule")

        // Without domain, GeoIP (rule 2) beats Network (rule 3)
        let resGeo = matcher.match(network: .tcp, countryCode: packCountryCode("CN"))
        #expect(resGeo?.ruleIndex == 2)
        #expect(rules.policyName(resGeo!.policyID) == "GeoRule")
    }

    @Test func andRule() throws {
        let text = """
            AND,((DOMAIN-SUFFIX,google.com),(DST-PORT,443)),GoogleSSL
            AND,((IP-CIDR,10.0.0.0/8),(NETWORK,tcp)),InternalTCP
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let d1 = Array("mail.google.com".utf8)
        let res = matcher.match(domain: d1.span, targetPort: 443)
        #expect(rules.policyName(res!.policyID) == "GoogleSSL")

        let res80 = matcher.match(domain: d1.span, targetPort: 80)
        #expect(rules.policyName(res80!.policyID) == "Fallback")

        let resTCP = matcher.match(targetAddress: v4(0x0A01_0203), network: .tcp)
        #expect(rules.policyName(resTCP!.policyID) == "InternalTCP")

        let resUDP = matcher.match(targetAddress: v4(0x0A01_0203), network: .udp)
        #expect(rules.policyName(resUDP!.policyID) == "Fallback")
    }

    @Test func orRule() throws {
        let text = """
            OR,((DOMAIN,apple.com),(DOMAIN,icloud.com)),AppleDirect
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let apple = Array("apple.com".utf8)
        let icloud = Array("icloud.com".utf8)
        let other = Array("google.com".utf8)

        let res1 = matcher.match(domain: apple.span)
        #expect(rules.policyName(res1!.policyID) == "AppleDirect")

        let res2 = matcher.match(domain: icloud.span)
        #expect(rules.policyName(res2!.policyID) == "AppleDirect")

        let res3 = matcher.match(domain: other.span)
        #expect(rules.policyName(res3!.policyID) == "Fallback")
    }

    @Test func notRule() throws {
        let text = """
            NOT,((NETWORK,udp)),NotUDP
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let resTCP = matcher.match(network: .tcp)
        #expect(rules.policyName(resTCP!.policyID) == "NotUDP")

        let resUDP = matcher.match(network: .udp)
        #expect(rules.policyName(resUDP!.policyID) == "Fallback")
    }

    @Test func subRule() throws {
        let text = """
            SUB-RULE,(NETWORK,tcp),SubGroupTCP
            SUB-RULE,(AND,((DOMAIN-SUFFIX,corp.internal),(PORT,8080))),SubGroupCorp
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let res1 = matcher.match(network: .tcp)
        #expect(rules.policyName(res1!.policyID) == "SubGroupTCP")

        let corp = Array("api.corp.internal".utf8)
        let resCorp = matcher.match(domain: corp.span, targetPort: 8080, network: .udp)
        #expect(rules.policyName(resCorp!.policyID) == "SubGroupCorp")
    }

    @Test func nestedLogicRules() throws {
        let text = """
            AND,((OR,((DOMAIN,a.com),(DOMAIN,b.com))),(NOT,((NETWORK,udp)))),ComplexPolicy
            MATCH,Fallback
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let a = Array("a.com".utf8)
        let b = Array("b.com".utf8)
        let c = Array("c.com".utf8)

        let resA = matcher.match(domain: a.span, network: .tcp)
        #expect(rules.policyName(resA!.policyID) == "ComplexPolicy")

        let resB = matcher.match(domain: b.span, network: .tcp)
        #expect(rules.policyName(resB!.policyID) == "ComplexPolicy")

        let resAUdp = matcher.match(domain: a.span, network: .udp)
        #expect(rules.policyName(resAUdp!.policyID) == "Fallback")

        let resC = matcher.match(domain: c.span, network: .tcp)
        #expect(rules.policyName(resC!.policyID) == "Fallback")
    }

    @Test func logicRuleFileOrderArbitration() throws {
        let text = """
            # Rule 0
            DOMAIN,priority.com,DirectRule
            # Rule 1
            AND,((DOMAIN-SUFFIX,com),(PORT,443)),LogicRule
            # Rule 2
            DOMAIN-SUFFIX,com,SuffixRule
            """
        let rules = try compile(text)
        let matcher = Matcher(rules)

        let prio = Array("priority.com".utf8)
        let res = matcher.match(domain: prio.span, targetPort: 443)
        #expect(res?.ruleIndex == 0)
        #expect(rules.policyName(res!.policyID) == "DirectRule")

        let other = Array("other.com".utf8)
        let resOther = matcher.match(domain: other.span, targetPort: 443)
        #expect(resOther?.ruleIndex == 1)
        #expect(rules.policyName(resOther!.policyID) == "LogicRule")

        let res80 = matcher.match(domain: other.span, targetPort: 80)
        #expect(res80?.ruleIndex == 2)
        #expect(rules.policyName(res80!.policyID) == "SuffixRule")
    }

    @Test func ruleSetClassical() throws {
        let rulesText = """
            RULE-SET,my-rules,PROXY
            MATCH,DIRECT
            """
        let listText = """
            # Classical rules in rule-set
            DOMAIN,exact.com
            DOMAIN-SUFFIX,suffix.com
            DOMAIN-KEYWORD,keyword
            IP-CIDR,192.168.50.0/24
            PORT,9000
            PROCESS-NAME,curl
            NETWORK,tcp
            DSCP,10
            GEOIP,JP
            """
        let rules = try RuleCompiler.compile(rulesText, ruleSets: ["my-rules": listText])
        let matcher = Matcher(rules)

        // Exact domain
        let resExact = matchDomain(matcher, "exact.com")
        #expect(resExact?.ruleIndex == 0)
        #expect(rules.policyName(resExact!.policyID) == "PROXY")

        // Suffix
        let resSuffix = matchDomain(matcher, "sub.suffix.com")
        #expect(resSuffix?.ruleIndex == 0)
        #expect(rules.policyName(resSuffix!.policyID) == "PROXY")

        // Keyword
        let resKw = matchDomain(matcher, "mykeyworddomain.org")
        #expect(resKw?.ruleIndex == 0)
        #expect(rules.policyName(resKw!.policyID) == "PROXY")

        // IP-CIDR
        let ctxIP = MatchContext(targetAddress: v4(0xC0A8_3205)) // 192.168.50.5
        let resIP = matcher.match(context: ctxIP)
        #expect(resIP?.ruleIndex == 0)
        #expect(rules.policyName(resIP!.policyID) == "PROXY")

        // Port
        let ctxPort = MatchContext(targetPort: 9000)
        let resPort = matcher.match(context: ctxPort)
        #expect(resPort?.ruleIndex == 0)
        #expect(rules.policyName(resPort!.policyID) == "PROXY")

        // Process name
        let pName = Array("curl".utf8)
        let resProc = matcher.match(processName: pName.span)
        #expect(resProc?.ruleIndex == 0)
        #expect(rules.policyName(resProc!.policyID) == "PROXY")

        // Network
        let resNet = matcher.match(context: MatchContext(network: .tcp))
        #expect(resNet?.ruleIndex == 0)
        #expect(rules.policyName(resNet!.policyID) == "PROXY")

        // DSCP
        let resDscp = matcher.match(context: MatchContext(dscp: 10))
        #expect(resDscp?.ruleIndex == 0)
        #expect(rules.policyName(resDscp!.policyID) == "PROXY")

        // GeoIP
        let resGeo = matcher.match(context: MatchContext(countryCode: 0x4A50)) // 'JP'
        #expect(resGeo?.ruleIndex == 0)
        #expect(rules.policyName(resGeo!.policyID) == "PROXY")

        // Miss fallback to MATCH
        let resMiss = matchDomain(matcher, "unmatched.net")
        #expect(resMiss?.ruleIndex == 1)
        #expect(rules.policyName(resMiss!.policyID) == "DIRECT")
    }

    @Test func ruleSetPayloadFormats() throws {
        let rulesText = """
            RULE-SET,domain-set,PROXY
            RULE-SET,cidr-set,DIRECT
            MATCH,FALLBACK
            """
        let domainPayload = """
            # Mixed plain domains, suffix prefixes, yaml dash, and quotes
            plain.com
            .dot-suffix.org
            +.plus-suffix.net
            - yaml-style.com
            - '.quoted-yaml.io'
            - "+.plus-quoted.co"
            """
        let cidrPayload = """
            10.10.0.0/16
            2001:db8:abcd::/48
            - '172.16.0.0/12'
            """
        let rules = try RuleCompiler.compile(rulesText, ruleSets: [
            "domain-set": domainPayload,
            "cidr-set": cidrPayload,
        ])
        let matcher = Matcher(rules)

        #expect(rules.policyName(matchDomain(matcher, "plain.com")!.policyID) == "PROXY")
        #expect(rules.policyName(matchDomain(matcher, "sub.dot-suffix.org")!.policyID) == "PROXY")
        #expect(rules.policyName(matchDomain(matcher, "deep.plus-suffix.net")!.policyID) == "PROXY")
        #expect(rules.policyName(matchDomain(matcher, "yaml-style.com")!.policyID) == "PROXY")
        #expect(rules.policyName(matchDomain(matcher, "sub.quoted-yaml.io")!.policyID) == "PROXY")
        #expect(rules.policyName(matchDomain(matcher, "sub.plus-quoted.co")!.policyID) == "PROXY")

        let ctxV4 = MatchContext(targetAddress: v4(0x0A0A_0102)) // 10.10.1.2
        #expect(rules.policyName(matcher.match(context: ctxV4)!.policyID) == "DIRECT")

        let ctxV6 = MatchContext(targetAddress: v6("20010DB8ABCD00000000000000000001"))
        #expect(rules.policyName(matcher.match(context: ctxV6)!.policyID) == "DIRECT")

        let ctxYamlCIDR = MatchContext(targetAddress: v4(0xAC10_0505)) // 172.16.5.5
        #expect(rules.policyName(matcher.match(context: ctxYamlCIDR)!.policyID) == "DIRECT")
    }

    @Test func ruleSetFileOrderPriority() throws {
        let rulesText = """
            DOMAIN,beat.com,HIGH_PRIO
            RULE-SET,mid-set,MID_PRIO
            DOMAIN,win.com,LOW_PRIO
            MATCH,FALLBACK
            """
        let midPayload = """
            DOMAIN,beat.com
            DOMAIN,win.com
            """
        let rules = try RuleCompiler.compile(rulesText, ruleSets: ["mid-set": midPayload])
        let matcher = Matcher(rules)

        let resBeat = matchDomain(matcher, "beat.com")
        #expect(resBeat?.ruleIndex == 0)
        #expect(rules.policyName(resBeat!.policyID) == "HIGH_PRIO")

        let resWin = matchDomain(matcher, "win.com")
        #expect(resWin?.ruleIndex == 1)
        #expect(rules.policyName(resWin!.policyID) == "MID_PRIO")
    }

    @Test func ruleSetInlinePolicyOverridden() throws {
        let rulesText = """
            RULE-SET,my-set,RULE_SET_TARGET
            """
        let payload = """
            DOMAIN,foo.com,INLINE_IGNORED
            """
        let rules = try RuleCompiler.compile(rulesText, ruleSets: ["my-set": payload])
        let matcher = Matcher(rules)
        let res = matchDomain(matcher, "foo.com")
        #expect(rules.policyName(res!.policyID) == "RULE_SET_TARGET")
    }

    @Test func ruleSetNested() throws {
        let rulesText = """
            RULE-SET,parent,PARENT_POLICY
            """
        let parentPayload = """
            DOMAIN,parent.com
            RULE-SET,child
            """
        let childPayload = """
            DOMAIN,child.com
            """
        let rules = try RuleCompiler.compile(rulesText, ruleSets: [
            "parent": parentPayload,
            "child": childPayload,
        ])
        let matcher = Matcher(rules)
        #expect(rules.policyName(matchDomain(matcher, "parent.com")!.policyID) == "PARENT_POLICY")
        #expect(rules.policyName(matchDomain(matcher, "child.com")!.policyID) == "PARENT_POLICY")
    }

    @Test func ruleSetWithLogic() throws {
        let rulesText = """
            RULE-SET,logic-set,LOGIC_TARGET
            MATCH,FINAL
            """
        let logicPayload = """
            AND,((DOMAIN,logic.com),(NETWORK,tcp))
            """
        let rules = try RuleCompiler.compile(rulesText, ruleSets: ["logic-set": logicPayload])
        let matcher = Matcher(rules)

        let dBytes = Array("logic.com".utf8)
        let resTCP = matcher.match(domain: dBytes.span, network: .tcp)
        #expect(resTCP?.ruleIndex == 0)
        #expect(rules.policyName(resTCP!.policyID) == "LOGIC_TARGET")

        let resUDP = matcher.match(domain: dBytes.span, network: .udp)
        #expect(resUDP?.ruleIndex == 1)
        #expect(rules.policyName(resUDP!.policyID) == "FINAL")
    }
}

// MARK: - Parser errors

@Suite struct ParserErrorTests {
    private func expectError(
        _ text: String, _ code: RuleParseError.Code, line: Int,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let bytes = Array(text.utf8)
        do {
            _ = try RuleCompiler.compile(bytes.span.bytes)
            Issue.record("expected error \(code) at line \(line), but compile succeeded", sourceLocation: sourceLocation)
        } catch {
            // compile is typed-throws, so `error` is a RuleParseError here.
            #expect(error.code == code, sourceLocation: sourceLocation)
            #expect(error.line == line, sourceLocation: sourceLocation)
        }
    }

    @Test func unknownRuleType() {
        expectError("UNKNOWN-TYPE,myset,DIRECT\n", .unknownRuleType, line: 1)
    }

    @Test func ipAsnUnsupported() {
        // IP-ASN 需 MMDB，当前不支持：显式锁死为 unknownRuleType。
        // 社区 fixture 已剔除 IP-ASN 行（如 telegram.list 头部注明的 5 条）。
        expectError("IP-ASN,1234,DIRECT\n", .unknownRuleType, line: 1)
    }

    @Test func unknownRuleSet() {
        expectError("RULE-SET,myset,DIRECT\n", .unknownRuleSet, line: 1)
    }

    @Test func circularRuleSet() {
        let rules = Array("RULE-SET,setA,DIRECT\n".utf8)
        let setA = "RULE-SET,setB\n"
        let setB = "RULE-SET,setA\n"
        do {
            _ = try RuleCompiler.compile(rules.span.bytes, ruleSets: [
                "setA": setA,
                "setB": setB,
            ])
            Issue.record("expected circularRuleSet error")
        } catch {
            #expect(error.code == .circularRuleSet)
        }
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

    @Test func invalidDSCP() {
        expectError("DSCP,64,DIRECT\n", .invalidArgument, line: 1)
        expectError("DSCP,abc,DIRECT\n", .invalidArgument, line: 1)
    }

    @Test func invalidNetwork() {
        expectError("NETWORK,icmp,DIRECT\n", .invalidArgument, line: 1)
        expectError("NETWORK,http,DIRECT\n", .invalidArgument, line: 1)
    }

    @Test func invalidGeoIP() {
        expectError("GEOIP,C,DIRECT\n", .invalidArgument, line: 1)
        expectError("GEOIP,TOOLONG,DIRECT\n", .invalidArgument, line: 1)
        expectError("GEOIP,12,DIRECT\n", .invalidArgument, line: 1)
    }

    @Test func invalidLogicRules() {
        expectError("AND,((DOMAIN,a.com)),DIRECT\n", .malformedLine, line: 1)
        expectError("OR,((DOMAIN,a.com)),DIRECT\n", .malformedLine, line: 1)
        expectError("NOT,((DOMAIN,a.com),(PORT,80)),DIRECT\n", .malformedLine, line: 1)
        expectError("AND,((DOMAIN,a.com),(INVALID-TYPE,x)),DIRECT\n", .unknownRuleType, line: 1)
        expectError("AND,((DOMAIN,a.com),(PORT,80)\n", .malformedLine, line: 1)
    }
}

// MARK: - RuleSetResolver contract

/// 覆盖 `RuleCompiler.compile(_:ruleSetResolver:)` 闭包借用路径及其调用约定。
@Suite struct RuleSetResolverTests {
    private static func bytes(_ span: Span<UInt8>) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(span.count)
        for b in span { out.append(b) }
        return out
    }

    /// 符合约定的字典 resolver：找到则恰好调用一次 body 并返回 true，否则返回 false。
    private func dictResolver(_ sets: [String: String]) -> RuleCompiler.RuleSetResolver {
        var map: [[UInt8]: [UInt8]] = [:]
        for (k, v) in sets { map[Array(k.utf8)] = Array(v.utf8) }
        return { (name: Span<UInt8>, body: (Span<UInt8>) throws(RuleParseError) -> Void) throws(RuleParseError) -> Bool in
            guard let payload = map[Self.bytes(name)] else { return false }
            try body(payload.span)
            return true
        }
    }

    private func compile(_ text: String, _ resolver: @escaping RuleCompiler.RuleSetResolver) throws(RuleParseError) -> CompiledRules {
        let input = Array(text.utf8)
        return try RuleCompiler.compile(input.span.bytes, ruleSetResolver: resolver)
    }

    private func compileError(
        _ text: String, _ resolver: @escaping RuleCompiler.RuleSetResolver,
        sourceLocation: SourceLocation = #_sourceLocation
    ) -> RuleParseError? {
        do {
            _ = try compile(text, resolver)
            Issue.record("expected compile to fail", sourceLocation: sourceLocation)
            return nil
        } catch {
            return error
        }
    }

    // MARK: 正常路径

    @Test func resolvesAndMatches() throws {
        let rules = try compile(
            "RULE-SET,my-set,PROXY\nMATCH,DIRECT\n",
            dictResolver(["my-set": "DOMAIN,foo.com\nDOMAIN-SUFFIX,bar.com\n"])
        )
        let matcher = Matcher(rules)
        let foo = matchDomain(matcher, "foo.com")
        #expect(foo?.ruleIndex == 0)
        #expect(rules.policyName(foo!.policyID) == "PROXY")
        #expect(rules.policyName(matchDomain(matcher, "a.bar.com")!.policyID) == "PROXY")
        #expect(rules.policyName(matchDomain(matcher, "other.com")!.policyID) == "DIRECT")
    }

    @Test func nestedRuleSetReentersResolver() throws {
        let rules = try compile(
            "RULE-SET,parent,PARENT\nMATCH,DIRECT\n",
            dictResolver([
                "parent": "DOMAIN,parent.com\nRULE-SET,child\n",
                "child": "DOMAIN,child.com\n",
            ])
        )
        let matcher = Matcher(rules)
        #expect(rules.policyName(matchDomain(matcher, "parent.com")!.policyID) == "PARENT")
        #expect(rules.policyName(matchDomain(matcher, "child.com")!.policyID) == "PARENT")
    }

    // MARK: 错误路径

    @Test func notFound() {
        let err = compileError("DOMAIN,a.com,DIRECT\nRULE-SET,missing,PROXY\n", dictResolver([:]))
        #expect(err?.code == .unknownRuleSet)
        #expect(err?.line == 2)
        #expect(err?.column == 10)
    }

    @Test func circularReference() {
        let err = compileError(
            "RULE-SET,setA,DIRECT\n",
            dictResolver(["setA": "RULE-SET,setB\n", "setB": "RULE-SET,setA\n"])
        )
        #expect(err?.code == .circularRuleSet)
    }

    @Test func hostLoadFailureIsStampedWithRuleSetLocation() {
        let resolver: RuleCompiler.RuleSetResolver = { _, _ throws(RuleParseError) in
            throw .ruleSetLoadFailed("disk unavailable")
        }
        let err = compileError("DOMAIN,a.com,DIRECT\nRULE-SET,remote,PROXY\n", resolver)
        #expect(err?.code == .ruleSetLoadFailed)
        #expect(err?.line == 2)
        #expect(err?.column == 10)
        #expect(err?.detail.contains("remote") == true)
        #expect(err?.detail.contains("disk unavailable") == true)
    }

    @Test func payloadParseErrorPropagatesUnchanged() {
        // 规则集内部第 2 行出错：行号应指向规则集内容，而非被 RULE-SET 行覆盖。
        let err = compileError(
            "RULE-SET,bad,PROXY\n",
            dictResolver(["bad": "DOMAIN,ok.com\nJUNK,x\n"])
        )
        #expect(err?.code == .unknownRuleType)
        #expect(err?.line == 2)
    }

    // MARK: 违反调用约定

    @Test func swallowedPayloadErrorIsRestored() {
        let payload = Array("JUNK,x\n".utf8)
        let resolver: RuleCompiler.RuleSetResolver = { _, body throws(RuleParseError) in
            do throws(RuleParseError) { try body(payload.span) } catch { /* 违规：吞掉错误 */ }
            return true
        }
        let err = compileError("RULE-SET,s,PROXY\n", resolver)
        #expect(err?.code == .unknownRuleType)
    }

    @Test func bodyInvokedTwice() {
        let payload = Array("DOMAIN,a.com\n".utf8)
        let resolver: RuleCompiler.RuleSetResolver = { _, body throws(RuleParseError) in
            try body(payload.span)
            try body(payload.span)
            return true
        }
        let err = compileError("RULE-SET,s,PROXY\n", resolver)
        #expect(err?.code == .invalidRuleSetResolver)
        #expect(err?.line == 1)
    }

    @Test func returnedTrueWithoutBody() {
        let resolver: RuleCompiler.RuleSetResolver = { _, _ throws(RuleParseError) in true }
        let err = compileError("RULE-SET,s,PROXY\n", resolver)
        #expect(err?.code == .invalidRuleSetResolver)
    }

    @Test func suppliedBodyButReturnedFalse() {
        let payload = Array("DOMAIN,a.com\n".utf8)
        let resolver: RuleCompiler.RuleSetResolver = { _, body throws(RuleParseError) in
            try body(payload.span)
            return false
        }
        let err = compileError("RULE-SET,s,PROXY\n", resolver)
        #expect(err?.code == .invalidRuleSetResolver)
    }
}
