import Testing
import ClashRuleCAPI
import ClashRuleCAPIHeader
import ClashRuleCAPITestSupport
import ClashRuleCore

@Test func cConsumerCanCreateMatchAndReadPolicyName() {
    #expect(clash_rule_capi_smoke_test() == 0)
}

@Test func handleSafetyDoubleDestroyDoesNotCrash() {
    let rules = "DOMAIN,foo.com,DIRECT\n"
    var error = clash_rule_error()
    let handle = rules.utf8CString.withUnsafeBytes { raw in
        clash_rule_engine_create(raw.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt(rules.utf8.count), &error)
    }
    #expect(handle != nil)
    #expect(error.code == CLASH_RULE_ERROR_NONE.rawValue)

    // First destroy destroys normally and poisons magic marker
    clash_rule_engine_destroy(handle)
    // Second destroy detects poisoned magic and safely no-ops without double-free
    clash_rule_engine_destroy(handle)
}

@Test func handleSafetyUseAfterFreeReturnsInvalidArgument() {
    let rules = "DOMAIN,foo.com,DIRECT\n"
    let handle = rules.utf8CString.withUnsafeBytes { raw in
        clash_rule_engine_create(raw.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt(rules.utf8.count), nil)
    }
    #expect(handle != nil)
    clash_rule_engine_destroy(handle)

    var policyID: UInt16 = 0
    var ruleIndex: UInt32 = 0
    var req = clash_rule_request()
    let status = clash_rule_engine_match(handle, &req, &policyID, &ruleIndex)
    #expect(status == CLASH_RULE_STATUS_INVALID_ARGUMENT.rawValue)

    var len: UInt = 0
    let nameStatus = clash_rule_engine_policy_name(handle, 0, nil, 0, &len)
    #expect(nameStatus == CLASH_RULE_STATUS_INVALID_ARGUMENT.rawValue)
}

@Test func handleSafetyBogusPointerRejected() {
    var fakeMemory: (UInt32, UInt32, UInt64) = (0x12345678, 0x90ABCDEF, 0)
    let bogus = withUnsafeMutablePointer(to: &fakeMemory) { UnsafeMutableRawPointer($0) }

    var policyID: UInt16 = 0
    var ruleIndex: UInt32 = 0
    var req = clash_rule_request()
    #expect(clash_rule_engine_match(bogus, &req, &policyID, &ruleIndex) == CLASH_RULE_STATUS_INVALID_ARGUMENT.rawValue)
    #expect(clash_rule_engine_match(nil, &req, &policyID, &ruleIndex) == CLASH_RULE_STATUS_INVALID_ARGUMENT.rawValue)

    // Destroy on invalid/NULL handle is safe no-op
    clash_rule_engine_destroy(bogus)
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

    // Adopt into safe Swift handle:
    if let safeAgain = ClashRuleEngine.fromRawHandle(rawHandle) {
        #expect(safeAgain.rules.ruleCount == 1)
        // safeAgain deinitializes here and cleans up the memory!
    }

    // Now rawHandle was safely deallocated and poisoned:
    if case .some = ClashRuleEngine.fromRawHandle(rawHandle) {
        Issue.record("Expected handle to be invalidated after destruction")
    }
}

