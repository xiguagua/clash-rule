import Testing
@testable import ClashRuleCore

@Suite struct CompileReportTests {
    private func report(_ text: String, ruleSets: [String: String] = [:]) throws -> CompileReport {
        try RuleCompiler.compileWithReport(text, ruleSets: ruleSets).report
    }

    @Test func cleanConfigHasNoWarnings() throws {
        let report = try report("DOMAIN,a.com,DIRECT\nDOMAIN-SUFFIX,b.com,PROXY\nMATCH,PROXY")
        #expect(report.shadowedRules.isEmpty)
        #expect(report.unreachableRules.isEmpty)
        #expect(report.emptyRuleSets.isEmpty)
    }

    @Test func duplicateExactIsShadowedByEarlierRule() throws {
        let report = try report("DOMAIN,a.com,DIRECT\nDOMAIN,a.com,PROXY")
        #expect(report.shadowedRules == [
            ShadowedRule(
                rule: RuleLocation(ruleIndex: 1, line: 2),
                shadowedBy: RuleLocation(ruleIndex: 0, line: 1)
            ),
        ])
    }

    @Test func duplicateSuffixIsShadowed() throws {
        let report = try report("DOMAIN-SUFFIX,a.com,DIRECT\nDOMAIN-SUFFIX,a.com,PROXY")
        #expect(report.shadowedRules.map(\.rule.line) == [2])
    }

    @Test func duplicateKeywordIsShadowed() throws {
        let report = try report("DOMAIN-KEYWORD,ads,REJECT\nDOMAIN-KEYWORD,ADS,PROXY")
        #expect(report.shadowedRules.map(\.rule.line) == [2])
    }

    @Test func sameIPPrefixIsShadowedButDifferentPrefixIsNot() throws {
        let duplicate = try report("IP-CIDR,10.0.0.0/8,A\nIP-CIDR,10.0.0.0/8,B")
        #expect(duplicate.shadowedRules.map(\.rule.line) == [2])

        let different = try report("IP-CIDR,10.0.0.0/8,A\nIP-CIDR,10.0.0.0/16,B")
        #expect(different.shadowedRules.isEmpty)
    }

    @Test func identicalPortIntervalIsShadowedOnlyWhenWholeRuleIsCovered() throws {
        let duplicate = try report("DST-PORT,443,A\nDST-PORT,443,B")
        #expect(duplicate.shadowedRules.map(\.rule.line) == [2])

        let partial = try report("DST-PORT,443,A\nDST-PORT,400-500,B")
        #expect(partial.shadowedRules.isEmpty)

        let eitherSideNotCovered = try report("DST-PORT,443,A\nPORT,443,B")
        #expect(eitherSideNotCovered.shadowedRules.isEmpty)

        let eitherSideCovered = try report("PORT,443,A\nDST-PORT,443,B")
        #expect(eitherSideCovered.shadowedRules.map(\.rule.line) == [2])
    }

    @Test func duplicateProcessNetworkDSCPAndGeoIPAreShadowed() throws {
        let process = try report("PROCESS-NAME,curl,A\nPROCESS-NAME,curl,B")
        #expect(process.shadowedRules.map(\.rule.line) == [2])

        let network = try report("NETWORK,tcp,A\nNETWORK,tcp,B")
        #expect(network.shadowedRules.map(\.rule.line) == [2])

        let dscp = try report("DSCP,46,A\nDSCP,46,B")
        #expect(dscp.shadowedRules.map(\.rule.line) == [2])

        let geo = try report("GEOIP,CN,A\nGEOIP,CN,B")
        #expect(geo.shadowedRules.map(\.rule.line) == [2])
    }

    @Test func rulesAfterFirstMatchAreUnreachable() throws {
        let report = try report("DOMAIN,a.com,DIRECT\nMATCH,PROXY\nDOMAIN,b.com,X\nDOMAIN-SUFFIX,c.com,Y")
        #expect(report.firstMatch == RuleLocation(ruleIndex: 1, line: 2))
        #expect(report.unreachableRules == [
            RuleLocation(ruleIndex: 2, line: 3),
            RuleLocation(ruleIndex: 3, line: 4),
        ])
    }

    @Test func secondMatchIsUnreachableNotShadowed() throws {
        let report = try report("MATCH,A\nMATCH,B")
        #expect(report.unreachableRules == [RuleLocation(ruleIndex: 1, line: 2)])
        #expect(report.shadowedRules.isEmpty)
    }

    @Test func duplicateAfterMatchIsNotReportedAsShadowed() throws {
        let report = try report("DOMAIN,a.com,DIRECT\nMATCH,PROXY\nDOMAIN,a.com,X")
        #expect(report.shadowedRules.isEmpty)
        #expect(report.unreachableRules.map(\.line) == [3])
    }

    @Test func emptyRuleSetIsReported() throws {
        let report = try report(
            "RULE-SET,ads,REJECT\nMATCH,DIRECT",
            ruleSets: ["ads": "# nothing here\n\n"]
        )
        #expect(report.emptyRuleSets == [EmptyRuleSet(name: "ads", line: 1)])
    }

    @Test func nonEmptyRuleSetIsNotReported() throws {
        let report = try report(
            "RULE-SET,ads,REJECT\nMATCH,DIRECT",
            ruleSets: ["ads": "DOMAIN,a.com"]
        )
        #expect(report.emptyRuleSets.isEmpty)
    }

    @Test func duplicatesInsideRuleSetAreNotReported() throws {
        let report = try report(
            "RULE-SET,ads,REJECT",
            ruleSets: ["ads": "DOMAIN,a.com\nDOMAIN,a.com"]
        )
        #expect(report.shadowedRules.isEmpty)
    }

    @Test func topLevelRuleShadowedByRuleSetEntryPointsAtRuleSetLine() throws {
        let report = try report(
            "# header\nRULE-SET,ads,REJECT\nDOMAIN,a.com,DIRECT",
            ruleSets: ["ads": "DOMAIN,a.com"]
        )
        #expect(report.shadowedRules == [
            ShadowedRule(
                rule: RuleLocation(ruleIndex: 1, line: 3),
                shadowedBy: RuleLocation(ruleIndex: 0, line: 2)
            ),
        ])
    }

    @Test func ruleSetEntriesShadowedByEarlierRuleAreNotReportedPerLine() throws {
        let report = try report(
            "DOMAIN,a.com,DIRECT\nRULE-SET,ads,REJECT",
            ruleSets: ["ads": "DOMAIN,a.com\nDOMAIN,b.com"]
        )
        #expect(report.shadowedRules.isEmpty)
    }

    @Test func fingerprintFollowsConfigurationContent() throws {
        let base = try report("DOMAIN,a.com,DIRECT\nMATCH,PROXY")
        #expect(base.firstMatch == RuleLocation(ruleIndex: 1, line: 2))
        let same = try report("DOMAIN,a.com,DIRECT\nMATCH,PROXY")
        #expect(base.fingerprint == same.fingerprint)

        let changedRules = try report("DOMAIN,a.com,PROXY\nMATCH,PROXY")
        #expect(base.fingerprint != changedRules.fingerprint)

        let withSet = try report("RULE-SET,ads,REJECT", ruleSets: ["ads": "DOMAIN,a.com"])
        let changedSet = try report("RULE-SET,ads,REJECT", ruleSets: ["ads": "DOMAIN,b.com"])
        #expect(withSet.fingerprint != changedSet.fingerprint)
    }

    @Test func compileWithReportMatchesCompile() throws {
        let text = "DOMAIN,a.com,DIRECT\nDOMAIN,a.com,PROXY\nMATCH,PROXY"
        let plain = try RuleCompiler.compile(text)
        let reported = try RuleCompiler.compileWithReport(text).rules
        #expect(plain.ruleCount == reported.ruleCount)
        #expect(plain.policyCount == reported.policyCount)

        let hit = Matcher(reported).match(domain: Array("a.com".utf8).span)
        #expect(hit?.ruleIndex == 0)
    }
}
