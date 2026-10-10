import Testing
import ClashRuleCAPI
import ClashRuleCAPIHeader
import ClashRuleCAPITestSupport
import ClashRuleCore

@Test func cConsumerCanCreateMatchAndReadPolicyName() {
    #expect(clash_rule_capi_smoke_test() == 0)
}

@Test func nullHandleIsRejectedAndDestroyIsNoOp() {
    var policyID: UInt16 = 0
    var ruleIndex: UInt32 = 0
    var req = clash_rule_request()
    #expect(clash_rule_engine_match(nil, &req, &policyID, &ruleIndex) == CLASH_RULE_STATUS_INVALID_ARGUMENT.rawValue)
    clash_rule_engine_destroy(nil)
}

@Test func safeSwiftClashRuleEngineRAII() throws {
    let compiled = try RuleCompiler.compile("DOMAIN,example.com,DIRECT\n")
    var rawHandle: UnsafeMutableRawPointer? = nil
    do {
        let engine = ClashRuleEngine(rules: compiled)
        #expect(engine.rules.ruleCount == 1)
        rawHandle = engine.intoRawHandle()
    }
    #expect(rawHandle != nil)

    // Adopt the raw handle back; it is released when `safeAgain` goes out of scope.
    if let safeAgain = ClashRuleEngine.fromRawHandle(rawHandle) {
        #expect(safeAgain.rules.ruleCount == 1)
    }
}
