import ClashRuleCAPIHeader
import ClashRuleCore

private func status(_ code: clash_rule_status_code) -> Int32 {
    Int32(code.rawValue)
}

private func writeError(
    _ output: UnsafeMutablePointer<clash_rule_error>?,
    code: clash_rule_error_code,
    line: Int = 0,
    column: Int = 0
) {
    guard let output else { return }
    output.pointee.code = Int32(code.rawValue)
    output.pointee.line = line
    output.pointee.column = column
}

private func cErrorCode(_ code: RuleParseError.Code) -> clash_rule_error_code {
    switch code {
    case .unknownRuleType: return CLASH_RULE_ERROR_UNKNOWN_RULE_TYPE
    case .malformedLine: return CLASH_RULE_ERROR_MALFORMED_LINE
    case .invalidArgument: return CLASH_RULE_ERROR_INVALID_ARGUMENT
    case .invalidPort: return CLASH_RULE_ERROR_INVALID_PORT
    case .invalidAddress: return CLASH_RULE_ERROR_INVALID_ADDRESS
    case .unknownFlag: return CLASH_RULE_ERROR_UNKNOWN_FLAG
    case .policyTableFull: return CLASH_RULE_ERROR_POLICY_TABLE_FULL
    case .unknownRuleSet: return CLASH_RULE_ERROR_UNKNOWN_RULE_SET
    case .circularRuleSet: return CLASH_RULE_ERROR_CIRCULAR_RULE_SET
    case .ruleSetLoadFailed: return CLASH_RULE_ERROR_RULE_SET_LOAD_FAILED
    case .invalidRuleSetResolver: return CLASH_RULE_ERROR_INVALID_RULE_SET_RESOLVER
    }
}

private func parseAddress(hasAddress: UInt8, high: UInt64, low: UInt64) -> UInt128? {
    hasAddress == 1 ? (UInt128(high) << 64) | UInt128(low) : nil
}

/// Safe, non-copyable RAII handle for the compiled rule engine.
///
/// Owns the underlying storage and releases it in `deinit`, so Swift callers cannot
/// double-free or leak it.
public struct ClashRuleEngine: ~Copyable, @unchecked Sendable {
    private var storage: UnsafeMutablePointer<CompiledRules>?

    public init(rules: CompiledRules) {
        let ptr = UnsafeMutablePointer<CompiledRules>.allocate(capacity: 1)
        ptr.initialize(to: rules)
        self.storage = ptr
    }

    deinit {
        if let storage {
            storage.deinitialize(count: 1)
            storage.deallocate()
        }
    }

    /// Accesses the compiled rules from the safe engine handle.
    public var rules: CompiledRules {
        guard let storage else { fatalError("ClashRuleEngine handle already consumed") }
        return storage.pointee
    }

    /// Transfers ownership of the engine to a raw C ABI pointer (`clash_rule_engine_t`),
    /// consuming this safe handle and delegating lifetime destruction to `clash_rule_engine_destroy`.
    public consuming func intoRawHandle() -> UnsafeMutableRawPointer {
        guard let storage else { fatalError("ClashRuleEngine handle already consumed") }
        let raw = UnsafeMutableRawPointer(storage)
        discard self
        return raw
    }

    /// Adopts ownership of a raw engine handle into a safe RAII handle.
    ///
    /// The caller must pass a handle obtained from `intoRawHandle` or `clash_rule_engine_create`
    /// that has not been destroyed yet. Returns `nil` only for `nil`.
    public static func fromRawHandle(_ raw: UnsafeMutableRawPointer?) -> ClashRuleEngine? {
        guard let raw else { return nil }
        return ClashRuleEngine(adopting: raw.assumingMemoryBound(to: CompiledRules.self))
    }

    private init(adopting storage: UnsafeMutablePointer<CompiledRules>) {
        self.storage = storage
    }
}

@c
public func clash_rule_engine_create(
    _ ruleData: UnsafePointer<UInt8>?,
    _ ruleLength: UInt,
    _ outError: UnsafeMutablePointer<clash_rule_error>?
) -> UnsafeMutableRawPointer? {
    writeError(outError, code: CLASH_RULE_ERROR_NONE)
    guard let inputLength = Int(exactly: ruleLength), inputLength == 0 || ruleData != nil else {
        writeError(outError, code: CLASH_RULE_ERROR_API_ARGUMENT)
        return nil
    }

    let input = UnsafeRawBufferPointer(start: ruleData, count: inputLength)
    let rules: CompiledRules
    do throws(RuleParseError) {
        rules = try RuleCompiler.compile(RawSpan(_unsafeBytes: input))
    } catch {
        writeError(outError, code: cErrorCode(error.code), line: error.line, column: error.column)
        return nil
    }

    let engine = ClashRuleEngine(rules: rules)
    return engine.intoRawHandle()
}

@c
public func clash_rule_engine_destroy(_ engine: UnsafeMutableRawPointer?) {
    guard let engine else { return }
    let storage = engine.assumingMemoryBound(to: CompiledRules.self)
    storage.deinitialize(count: 1)
    storage.deallocate()
}

@c
public func clash_rule_engine_match(
    _ engine: UnsafeMutableRawPointer?,
    _ request: UnsafePointer<clash_rule_request>?,
    _ outPolicyID: UnsafeMutablePointer<UInt16>?,
    _ outRuleIndex: UnsafeMutablePointer<UInt32>?
) -> Int32 {
    guard let engine, let request, let outPolicyID, let outRuleIndex else {
        return status(CLASH_RULE_STATUS_INVALID_ARGUMENT)
    }
    outPolicyID.pointee = 0
    outRuleIndex.pointee = 0

    let value = request.pointee
    guard
        value.domain_length >= 0,
        value.process_name_length >= 0,
        value.process_path_length >= 0,
        value.domain_length == 0 || value.domain != nil,
        value.process_name_length == 0 || value.process_name != nil,
        value.process_path_length == 0 || value.process_path != nil,
        value.has_target_address <= 1,
        value.has_source_address <= 1,
        value.has_dscp <= 1,
        value.has_dscp == 0 || value.dscp < 64
    else {
        return status(CLASH_RULE_STATUS_INVALID_ARGUMENT)
    }

    let network: NetworkProtocol?
    switch value.network_protocol {
    case 0: network = nil
    case 1: network = .tcp
    case 2: network = .udp
    default: return status(CLASH_RULE_STATUS_INVALID_ARGUMENT)
    }

    let domain = Span(_unsafeElements: UnsafeBufferPointer(start: value.domain, count: value.domain_length))
    let processName = Span(_unsafeElements: UnsafeBufferPointer(start: value.process_name, count: value.process_name_length))
    let processPath = Span(_unsafeElements: UnsafeBufferPointer(start: value.process_path, count: value.process_path_length))

    let storage = engine.assumingMemoryBound(to: CompiledRules.self)
    let result = Matcher(storage.pointee).match(
        domain: domain,
        targetAddress: parseAddress(
            hasAddress: value.has_target_address,
            high: value.target_address_high,
            low: value.target_address_low
        ),
        targetPort: value.target_port,
        sourceAddress: parseAddress(
            hasAddress: value.has_source_address,
            high: value.source_address_high,
            low: value.source_address_low
        ),
        sourcePort: value.source_port,
        processName: processName,
        processPath: processPath,
        network: network,
        dscp: value.has_dscp == 1 ? value.dscp : nil,
        countryCode: value.country_code
    )

    guard let result else { return status(CLASH_RULE_STATUS_NO_MATCH) }
    outPolicyID.pointee = result.policyID
    outRuleIndex.pointee = result.ruleIndex
    return status(CLASH_RULE_STATUS_OK)
}

@c
public func clash_rule_engine_policy_name(
    _ engine: UnsafeMutableRawPointer?,
    _ policyID: UInt16,
    _ outName: UnsafeMutablePointer<UInt8>?,
    _ capacity: UInt,
    _ outLength: UnsafeMutablePointer<UInt>?
) -> Int32 {
    guard let engine, let outLength, let bufferCapacity = Int(exactly: capacity) else {
        return status(CLASH_RULE_STATUS_INVALID_ARGUMENT)
    }
    outLength.pointee = 0
    guard outName != nil || bufferCapacity == 0 else {
        return status(CLASH_RULE_STATUS_INVALID_ARGUMENT)
    }

    let storage = engine.assumingMemoryBound(to: CompiledRules.self)
    guard Int(policyID) < storage.pointee.policyCount else {
        return status(CLASH_RULE_STATUS_INVALID_ARGUMENT)
    }

    return storage.pointee.withPolicyNameBytes(policyID) { bytes in
        outLength.pointee = UInt(bytes.count)
        if bufferCapacity == 0 && outName == nil {
            return status(CLASH_RULE_STATUS_OK)
        }
        guard bufferCapacity >= bytes.count else {
            return status(CLASH_RULE_STATUS_BUFFER_TOO_SMALL)
        }
        if let outName, bytes.count > 0 {
            bytes.withUnsafeBufferPointer { buffer in
                outName.update(from: buffer.baseAddress!, count: buffer.count)
            }
        }
        return status(CLASH_RULE_STATUS_OK)
    }
}
