import Testing
@testable import ClashRuleCore

@Suite struct MatchTraceTests {
    private static let rulesText = """
        DOMAIN,a.com,DIRECT
        DOMAIN-SUFFIX,com,PROXY
        DOMAIN-KEYWORD,ads,REJECT
        IP-CIDR,10.0.0.0/8,PROXY,no-resolve
        SRC-IP-CIDR,192.168.1.0/24,DIRECT
        DST-PORT,443,PROXY
        SRC-PORT,5000,DIRECT
        PROCESS-NAME,curl,DIRECT
        NETWORK,udp,UDP_POLICY
        DSCP,46,EF
        GEOIP,US,US_POLICY,no-resolve
        AND,((NETWORK,tcp),(DOMAIN-SUFFIX,logic.com)),LOGIC
        MATCH,FINAL
        """

    private func outcome(_ trace: MatchTrace, _ category: MatchCategory) -> [CategoryOutcome] {
        trace.categories.filter { $0.category == category }.map(\.outcome)
    }

    @Test func listsEveryCategoryWithoutPruning() throws {
        let matcher = Matcher(try RuleCompiler.compile(Self.rulesText))
        let trace = matcher.explain(domain: Array("a.com".utf8).span, targetPort: 443, network: .tcp)

        #expect(outcome(trace, .exactDomain) == [.hit(MatchResult(policyID: 0, ruleIndex: 0))])
        #expect(outcome(trace, .suffixDomain) == [.hit(MatchResult(policyID: 1, ruleIndex: 1))])
        #expect(outcome(trace, .destinationPort) == [.hit(MatchResult(policyID: 1, ruleIndex: 5))])
        #expect(outcome(trace, .keywordDomain) == [.noMatch])
        #expect(outcome(trace, .network) == [.noMatch])
        #expect(outcome(trace, .match) == [.hit(MatchResult(policyID: 7, ruleIndex: 12))])
        #expect(trace.categories.count == 14)
    }

    @Test func winnerIsLowestRuleIndexAndAgreesWithMatch() throws {
        let matcher = Matcher(try RuleCompiler.compile(Self.rulesText))
        let trace = matcher.explain(domain: Array("a.com".utf8).span, targetPort: 443, network: .tcp)

        #expect(trace.result == MatchResult(policyID: 0, ruleIndex: 0))
        #expect(trace.winningCategory == .exactDomain)
        #expect(trace.result == matcher.match(domain: Array("a.com".utf8).span, targetPort: 443, network: .tcp))
    }

    @Test func reportsLosingCandidatesBehindTheWinner() throws {
        let matcher = Matcher(try RuleCompiler.compile(Self.rulesText))
        let trace = matcher.explain(domain: Array("x.logic.com".utf8).span, network: .tcp)

        #expect(trace.result == MatchResult(policyID: 1, ruleIndex: 1))
        #expect(trace.winningCategory == .suffixDomain)
        #expect(outcome(trace, .logic) == [.hit(MatchResult(policyID: 6, ruleIndex: 11))])
    }

    @Test func missingInputsAreNotApplicable() throws {
        let matcher = Matcher(try RuleCompiler.compile(Self.rulesText))
        let trace = matcher.explain()

        #expect(outcome(trace, .exactDomain) == [.notApplicable])
        #expect(outcome(trace, .processName) == [.notApplicable])
        #expect(outcome(trace, .geoIP) == [.notApplicable])
        #expect(outcome(trace, .dscp) == [.notApplicable])
        #expect(trace.winningCategory == .match)
        #expect(trace.result == MatchResult(policyID: 7, ruleIndex: 12))
    }

    @Test func categoriesWithoutRulesReportNoRules() throws {
        let matcher = Matcher(try RuleCompiler.compile("DOMAIN,a.com,DIRECT\nMATCH,FINAL"))
        let trace = matcher.explain(domain: Array("a.com".utf8).span, dscp: 46, countryCode: 0x5553)

        #expect(outcome(trace, .dscp) == [.noRules])
        #expect(outcome(trace, .geoIP) == [.noRules])
        #expect(outcome(trace, .logic) == [.noRules])
        #expect(outcome(trace, .suffixDomain) == [.noRules])
        #expect(trace.winningCategory == .exactDomain)
    }

    @Test func explainAgreesWithMatchOnRepresentativeContexts() throws {
        let matcher = Matcher(try RuleCompiler.compile(Self.rulesText))
        let contexts: [MatchContext] = [
            MatchContext(domain: Array("a.com".utf8), targetPort: 443, network: .tcp),
            MatchContext(domain: Array("www.example.com".utf8), network: .udp),
            MatchContext(domain: Array("ads.example.net".utf8), targetPort: 80),
            MatchContext(domain: Array("x.logic.com".utf8), network: .tcp),
            MatchContext(domain: Array("nothing.org".utf8), sourcePort: 5000),
            MatchContext(targetAddress: parseIPAddress("10.1.2.3"), targetPort: 443),
            MatchContext(sourceAddress: parseIPAddress("192.168.1.9")),
            MatchContext(processName: Array("curl".utf8), dscp: 46),
            MatchContext(domain: Array("a.com".utf8), countryCode: 0x5553),
            MatchContext(),
        ]
        for context in contexts {
            let trace = matcher.explain(context: context)
            #expect(trace.result == matcher.match(context: context))
        }
    }
}
