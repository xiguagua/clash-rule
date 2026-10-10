#if Diagnostics
import Testing
@testable import ClashRuleCore

@Suite struct DiagnosticsTests {
    @Test func mapsRuleIndexToSourceLineSkippingCommentsAndBlanks() throws {
        let text = """
            # comment

            DOMAIN,a.com,DIRECT
            DOMAIN-SUFFIX,b.com,PROXY

            MATCH,DIRECT
            """
        let rules = try RuleCompiler.compile(text)

        #expect(rules.ruleCount == 3)
        #expect(rules.sourceLine(ofRule: 0) == 3)
        #expect(rules.sourceLine(ofRule: 1) == 4)
        #expect(rules.sourceLine(ofRule: 2) == 6)
        #expect(rules.sourceLine(ofRule: 3) == nil)
    }

    @Test func ruleSetInnerRulesShareOuterLine() throws {
        let text = """
            # comment
            RULE-SET,ads,REJECT
            DOMAIN,tail.com,DIRECT
            """
        let rules = try RuleCompiler.compile(
            text,
            ruleSets: ["ads": "DOMAIN,a.com\nDOMAIN,b.com"]
        )

        #expect(rules.ruleCount == 2)
        #expect(rules.sourceLine(ofRule: 0) == 2)
        #expect(rules.sourceLine(ofRule: 1) == 3)

        let hit = Matcher(rules).match(domain: Array("b.com".utf8).span)
        #expect(hit?.ruleIndex == 0)
        #expect(hit.flatMap { rules.sourceLine(ofRule: $0.ruleIndex) } == 2)
    }
}
#endif
