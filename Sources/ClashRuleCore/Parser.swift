/// Zero-copy line scanner over UTF-8 rule text.
///
/// Input is a `RawSpan` (SE-0447); no `String` is ever materialized. Validated
/// rules are handed to a `RuleSink` as borrowed byte ranges, which the sink
/// copies into compile-phase arenas (docs/PLAN.md §2.1, §6).
///
/// M1 parses: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6,
/// PORT, DST-PORT, SRC-PORT, MATCH. Unknown types fail fast (docs/PLAN.md §6).
struct RuleParser {
    // Rule-type literals as byte arrays (initialized once). `matchKind` compares
    // caller bytes case-insensitively against these without materializing or
    // hashing a per-line key — the old `kindTable` paid an `[UInt8]` alloc +
    // generic-hash lookup on every line.
    private static let kOR: [UInt8] = Array("OR".utf8)
    private static let kAND: [UInt8] = Array("AND".utf8)
    private static let kNOT: [UInt8] = Array("NOT".utf8)
    private static let kPORT: [UInt8] = Array("PORT".utf8)
    private static let kDSCP: [UInt8] = Array("DSCP".utf8)
    private static let kMATCH: [UInt8] = Array("MATCH".utf8)
    private static let kGEOIP: [UInt8] = Array("GEOIP".utf8)
    private static let kDOMAIN: [UInt8] = Array("DOMAIN".utf8)
    private static let kNETWORK: [UInt8] = Array("NETWORK".utf8)
    private static let kIPCIDR: [UInt8] = Array("IP-CIDR".utf8)
    private static let kDSTPORT: [UInt8] = Array("DST-PORT".utf8)
    private static let kSRCPORT: [UInt8] = Array("SRC-PORT".utf8)
    private static let kRULESET: [UInt8] = Array("RULE-SET".utf8)
    private static let kSUBRULE: [UInt8] = Array("SUB-RULE".utf8)
    private static let kIPCIDR6: [UInt8] = Array("IP-CIDR6".utf8)
    private static let kSRCIPCIDR: [UInt8] = Array("SRC-IP-CIDR".utf8)
    private static let kPROCESSNAME: [UInt8] = Array("PROCESS-NAME".utf8)
    private static let kPROCESSPATH: [UInt8] = Array("PROCESS-PATH".utf8)
    private static let kSRCIPCIDR6: [UInt8] = Array("SRC-IP-CIDR6".utf8)
    private static let kDOMAINSUFFIX: [UInt8] = Array("DOMAIN-SUFFIX".utf8)
    private static let kDOMAINKEYWORD: [UInt8] = Array("DOMAIN-KEYWORD".utf8)

    @inline(__always)
    private static func eqKind(_ raw: UnsafeRawBufferPointer, _ r: Range<Int>, _ lit: [UInt8]) -> Bool {
        guard r.count == lit.count else { return false }
        var i = r.lowerBound
        for b in lit {
            if upperByte(raw[i]) != b { return false }
            i += 1
        }
        return true
    }

    /// Case-insensitive rule-type dispatch without allocation or hashing.
    private static func matchKind(_ raw: UnsafeRawBufferPointer, _ r: Range<Int>) -> RuleKind? {
        switch r.count {
        case 2:
            if eqKind(raw, r, kOR) { return .or }
        case 3:
            if eqKind(raw, r, kAND) { return .and }
            if eqKind(raw, r, kNOT) { return .not }
        case 4:
            if eqKind(raw, r, kPORT) { return .port(.either) }
            if eqKind(raw, r, kDSCP) { return .dscp }
        case 5:
            if eqKind(raw, r, kMATCH) { return .match }
            if eqKind(raw, r, kGEOIP) { return .geoIP }
        case 6:
            if eqKind(raw, r, kDOMAIN) { return .domain }
        case 7:
            if eqKind(raw, r, kNETWORK) { return .network }
            if eqKind(raw, r, kIPCIDR) { return .ipCIDR(isIPv6: false) }
        case 8:
            if eqKind(raw, r, kDSTPORT) { return .port(.destination) }
            if eqKind(raw, r, kSRCPORT) { return .port(.source) }
            if eqKind(raw, r, kRULESET) { return .ruleSet }
            if eqKind(raw, r, kSUBRULE) { return .subRule }
            if eqKind(raw, r, kIPCIDR6) { return .ipCIDR(isIPv6: true) }
        case 11:
            if eqKind(raw, r, kSRCIPCIDR) { return .srcIPCIDR(isIPv6: false) }
        case 12:
            if eqKind(raw, r, kPROCESSNAME) { return .processName }
            if eqKind(raw, r, kPROCESSPATH) { return .processPath }
            if eqKind(raw, r, kSRCIPCIDR6) { return .srcIPCIDR(isIPv6: true) }
        case 13:
            if eqKind(raw, r, kDOMAINSUFFIX) { return .domainSuffix }
        case 14:
            if eqKind(raw, r, kDOMAINKEYWORD) { return .domainKeyword }
        default:
            break
        }
        return nil
    }

    static func parse(
        _ input: UnsafeRawBufferPointer,
        ruleSetResolver: ((UnsafeBufferPointer<UInt8>) -> UnsafeRawBufferPointer?)? = nil,
        byteRuleSets: [[UInt8]: [UInt8]]? = nil,
        into sink: inout RuleSink
    ) throws(RuleParseError) {
        var activeRuleSets: Set<[UInt8]> = []
        let n = input.count
        var i = 0
        var line = 1
        while true {
            var j = i
            while j < n && input[j] != UInt8(ascii: "\n") { j += 1 }
            var length = j - i
            if length > 0 && input[i + length - 1] == UInt8(ascii: "\r") { length -= 1 }
            try parseLine(
                input, i..<(i + length),
                line: line,
                ruleSetResolver: ruleSetResolver,
                byteRuleSets: byteRuleSets,
                activeRuleSets: &activeRuleSets,
                into: &sink
            )
            line += 1
            if j >= n { break }
            i = j + 1
        }
    }

    // MARK: - Line structure

    private static func parseLine(
        _ raw: UnsafeRawBufferPointer,
        _ range: Range<Int>,
        line: Int,
        ruleSetResolver: ((UnsafeBufferPointer<UInt8>) -> UnsafeRawBufferPointer?)?,
        byteRuleSets: [[UInt8]: [UInt8]]?,
        activeRuleSets: inout Set<[UInt8]>,
        into sink: inout RuleSink
    ) throws(RuleParseError) {
        let base = range.lowerBound
        var start = base
        var stop = range.upperBound
        while start < stop && isInlineSpace(raw[start]) { start += 1 }
        while stop > start && isInlineSpace(raw[stop - 1]) { stop -= 1 }
        if start == stop { return }
        if raw[start] == UInt8(ascii: "#") { return }

        // Split into comma segments, trimming whitespace around each one, respecting parentheses.
        var segments: [Range<Int>] = []
        var cursor = start
        var depth = 0
        while cursor < stop {
            var comma = cursor
            while comma < stop {
                let b = raw[comma]
                if b == UInt8(ascii: "(") { depth += 1 }
                else if b == UInt8(ascii: ")") && depth > 0 { depth -= 1 }
                else if b == UInt8(ascii: ",") && depth == 0 { break }
                comma += 1
            }
            var s = cursor, e = comma
            while s < e && isInlineSpace(raw[s]) { s += 1 }
            while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
            segments.append(s..<e)
            if comma >= stop { break }
            cursor = comma + 1
        }

        // Rule type name (case-insensitive, no allocation).
        guard let kind = matchKind(raw, segments[0]) else {
            throw RuleParseError(
                .unknownRuleType, line: line, column: 1,
                "unsupported rule type '\(String(decoding: [UInt8](raw[segments[0]]), as: UTF8.self))'"
            )
        }

        if case .match = kind {
            guard segments.count == 2, !segments[1].isEmpty else {
                throw RuleParseError(.malformedLine, line: line, column: 1, "MATCH requires exactly TYPE,POLICY")
            }
            let policyID = try sink.intern(raw, segments[1], line: line, base: base)
            sink.addMatch(policyID: policyID, ruleIndex: sink.nextRuleIndex)
            sink.commitLine()
            return
        }

        guard segments.count >= 3, !segments[1].isEmpty, !segments[2].isEmpty else {
            throw RuleParseError(.malformedLine, line: line, column: 1, "expected TYPE,ARG,POLICY")
        }
        let arg = segments[1]
        let ruleIndex = sink.nextRuleIndex

        // Flags: only `no-resolve` is accepted, and only on IP-CIDR/GEOIP/RULE-SET rules.
        var allowNoResolve = false
        switch kind {
        case .ipCIDR, .srcIPCIDR, .geoIP, .ruleSet:
            allowNoResolve = true
        default:
            break
        }
        var hasNoResolve = false
        for flagRange in segments[3...] {
            if flagRange.isEmpty { continue }
            guard allowNoResolve, isNoResolve(raw, flagRange) else {
                throw RuleParseError(
                    .unknownFlag, line: line, column: flagRange.lowerBound - base + 1,
                    "unsupported flag (only 'no-resolve' on IP-CIDR/GEOIP/RULE-SET is accepted)"
                )
            }
            hasNoResolve = true
        }

        let policyID = try sink.intern(raw, segments[2], line: line, base: base)

        switch kind {
        case .domain:
            try validateDomain(raw, arg, line: line, base: base)
            sink.addExact(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
        case .domainSuffix:
            try validateDomain(raw, arg, line: line, base: base)
            sink.addSuffix(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
        case .domainKeyword:
            try validateKeyword(raw, arg, line: line, base: base)
            sink.addKeyword(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
        case .ipCIDR:
            let parsed = try parseCIDR(raw, arg, line: line, base: base)
            sink.addIP(address: parsed.address, prefix: parsed.prefix, isIPv6: parsed.isIPv6, isSource: false, policyID: policyID, ruleIndex: ruleIndex)
        case .srcIPCIDR:
            let parsed = try parseCIDR(raw, arg, line: line, base: base)
            sink.addIP(address: parsed.address, prefix: parsed.prefix, isIPv6: parsed.isIPv6, isSource: true, policyID: policyID, ruleIndex: ruleIndex)
        case .port(let side):
            let intervals = try parsePortList(raw, arg, line: line, base: base)
            sink.addPort(intervals, side: side, policyID: policyID, ruleIndex: ruleIndex)
        case .processName:
            try validatePrintable(raw, arg, line: line, base: base, name: "process name")
            sink.addProcessName(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
        case .processPath:
            try validatePrintable(raw, arg, line: line, base: base, name: "process path")
            sink.addProcessPath(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
        case .network:
            let proto = try parseNetwork(raw, arg, line: line, base: base)
            sink.addNetwork(proto, policyID: policyID, ruleIndex: ruleIndex)
        case .dscp:
            let val = try parseDSCP(raw, arg, line: line, base: base)
            sink.addDSCP(val, policyID: policyID, ruleIndex: ruleIndex)
        case .geoIP:
            let code = try parseGeoIP(raw, arg, line: line, base: base)
            sink.addGeoIP(code, policyID: policyID, ruleIndex: ruleIndex)
        case .and:
            let root = try parseAndOrCondition(raw, arg, isAnd: true, line: line, base: base, into: &sink)
            sink.addLogicRule(rootNodeIndex: root, policyID: policyID, ruleIndex: ruleIndex)
        case .or:
            let root = try parseAndOrCondition(raw, arg, isAnd: false, line: line, base: base, into: &sink)
            sink.addLogicRule(rootNodeIndex: root, policyID: policyID, ruleIndex: ruleIndex)
        case .not:
            let root = try parseNotCondition(raw, arg, line: line, base: base, into: &sink)
            sink.addLogicRule(rootNodeIndex: root, policyID: policyID, ruleIndex: ruleIndex)
        case .subRule:
            let root = try parseSubRuleCondition(raw, arg, line: line, base: base, into: &sink)
            sink.addLogicRule(rootNodeIndex: root, policyID: policyID, ruleIndex: ruleIndex)
        case .ruleSet:
            let nameBytes = [UInt8](raw[arg])
            guard !activeRuleSets.contains(nameBytes) else {
                throw RuleParseError(.circularRuleSet, line: line, column: arg.lowerBound - base + 1, "circular reference to rule-set '\(String(decoding: nameBytes, as: UTF8.self))'")
            }
            if let byteMap = byteRuleSets, let data = byteMap[nameBytes] {
                activeRuleSets.insert(nameBytes)
                defer { activeRuleSets.remove(nameBytes) }
                try withBytes(data, line: line) { ruleSetBytes in
                    try parseRuleSetPayload(
                        ruleSetBytes,
                        policyID: policyID,
                        ruleIndex: ruleIndex,
                        inheritedNoResolve: hasNoResolve,
                        ruleSetResolver: ruleSetResolver,
                        byteRuleSets: byteRuleSets,
                        activeRuleSets: &activeRuleSets,
                        into: &sink
                    )
                }
            } else if let resolver = ruleSetResolver {
                let resolved: UnsafeRawBufferPointer? = nameBytes.withUnsafeBufferPointer { nameBuf in
                    resolver(nameBuf)
                }
                guard let ruleSetBytes = resolved else {
                    throw RuleParseError(.unknownRuleSet, line: line, column: arg.lowerBound - base + 1, "rule-set '\(String(decoding: nameBytes, as: UTF8.self))' not found")
                }
                activeRuleSets.insert(nameBytes)
                defer { activeRuleSets.remove(nameBytes) }
                try parseRuleSetPayload(
                    ruleSetBytes,
                    policyID: policyID,
                    ruleIndex: ruleIndex,
                    inheritedNoResolve: hasNoResolve,
                    ruleSetResolver: ruleSetResolver,
                    byteRuleSets: byteRuleSets,
                    activeRuleSets: &activeRuleSets,
                    into: &sink
                )
            } else {
                throw RuleParseError(.unknownRuleSet, line: line, column: arg.lowerBound - base + 1, "rule-set '\(String(decoding: nameBytes, as: UTF8.self))' not found")
            }
        case .match:
            break // handled above
        }
        sink.commitLine()
    }

    // MARK: - Rule-set payload parsing

    private static func withBytes<R>(
        _ data: [UInt8],
        line: Int,
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) throws(RuleParseError) -> R {
        do {
            return try data.withUnsafeBytes { raw in
                try body(raw)
            }
        } catch let err as RuleParseError {
            throw err
        } catch {
            throw RuleParseError(.malformedLine, line: line, column: 1, "\(error)")
        }
    }

    private static func parseRuleSetPayload(
        _ input: UnsafeRawBufferPointer,
        policyID: UInt16,
        ruleIndex: UInt32,
        inheritedNoResolve: Bool,
        ruleSetResolver: ((UnsafeBufferPointer<UInt8>) -> UnsafeRawBufferPointer?)?,
        byteRuleSets: [[UInt8]: [UInt8]]?,
        activeRuleSets: inout Set<[UInt8]>,
        into sink: inout RuleSink
    ) throws(RuleParseError) {
        let n = input.count
        var i = 0
        var line = 1
        while true {
            var j = i
            while j < n && input[j] != UInt8(ascii: "\n") { j += 1 }
            var length = j - i
            if length > 0 && input[i + length - 1] == UInt8(ascii: "\r") { length -= 1 }
            try parseRuleSetLine(
                input, i..<(i + length),
                line: line,
                policyID: policyID,
                ruleIndex: ruleIndex,
                inheritedNoResolve: inheritedNoResolve,
                ruleSetResolver: ruleSetResolver,
                byteRuleSets: byteRuleSets,
                activeRuleSets: &activeRuleSets,
                into: &sink
            )
            line += 1
            if j >= n { break }
            i = j + 1
        }
    }

    private static func parseRuleSetLine(
        _ raw: UnsafeRawBufferPointer,
        _ range: Range<Int>,
        line: Int,
        policyID: UInt16,
        ruleIndex: UInt32,
        inheritedNoResolve: Bool,
        ruleSetResolver: ((UnsafeBufferPointer<UInt8>) -> UnsafeRawBufferPointer?)?,
        byteRuleSets: [[UInt8]: [UInt8]]?,
        activeRuleSets: inout Set<[UInt8]>,
        into sink: inout RuleSink
    ) throws(RuleParseError) {
        let base = range.lowerBound
        var start = base
        var stop = range.upperBound
        while start < stop && isInlineSpace(raw[start]) { start += 1 }
        while stop > start && isInlineSpace(raw[stop - 1]) { stop -= 1 }
        if start == stop { return }
        if raw[start] == UInt8(ascii: "#") { return }
        if stop - start >= 2 && raw[start] == UInt8(ascii: "/") && raw[start + 1] == UInt8(ascii: "/") {
            return
        }

        // Support YAML list item prefix "- "
        if stop - start >= 2 && raw[start] == UInt8(ascii: "-") && isInlineSpace(raw[start + 1]) {
            start += 2
            while start < stop && isInlineSpace(raw[start]) { start += 1 }
        }
        // Support surrounding quotes '...' or "..."
        if stop - start >= 2 {
            let first = raw[start]
            let last = raw[stop - 1]
            if (first == UInt8(ascii: "'") && last == UInt8(ascii: "'")) ||
               (first == UInt8(ascii: "\"") && last == UInt8(ascii: "\"")) {
                start += 1
                stop -= 1
                while start < stop && isInlineSpace(raw[start]) { start += 1 }
                while stop > start && isInlineSpace(raw[stop - 1]) { stop -= 1 }
            }
        }
        if start == stop { return }

        // Split comma segments respecting parentheses
        var segments: [Range<Int>] = []
        var cursor = start
        var depth = 0
        while cursor < stop {
            var comma = cursor
            while comma < stop {
                let b = raw[comma]
                if b == UInt8(ascii: "(") { depth += 1 }
                else if b == UInt8(ascii: ")") && depth > 0 { depth -= 1 }
                else if b == UInt8(ascii: ",") && depth == 0 { break }
                comma += 1
            }
            var s = cursor, e = comma
            while s < e && isInlineSpace(raw[s]) { s += 1 }
            while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
            segments.append(s..<e)
            if comma >= stop { break }
            cursor = comma + 1
        }
        if segments.isEmpty || segments[0].isEmpty { return }

        if let kind = matchKind(raw, segments[0]) {
            guard segments.count >= 2, !segments[1].isEmpty else {
                throw RuleParseError(.malformedLine, line: line, column: 1, "expected TYPE,ARG in rule-set")
            }
            let arg = segments[1]
            var hasNoResolve = inheritedNoResolve
            if segments.count >= 3 {
                for seg in segments[2...] {
                    if seg.isEmpty { continue }
                    if isNoResolve(raw, seg) {
                        hasNoResolve = true
                    } else if segments.count == 3 {
                        // Inline policy in rule-provider line (e.g. DOMAIN,foo.com,DIRECT); ignored
                        continue
                    } else {
                        throw RuleParseError(
                            .unknownFlag, line: line, column: seg.lowerBound - base + 1,
                            "unsupported flag in rule-set"
                        )
                    }
                }
            }

            switch kind {
            case .domain:
                try validateDomain(raw, arg, line: line, base: base)
                sink.addExact(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
            case .domainSuffix:
                try validateDomain(raw, arg, line: line, base: base)
                sink.addSuffix(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
            case .domainKeyword:
                try validateKeyword(raw, arg, line: line, base: base)
                sink.addKeyword(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
            case .ipCIDR:
                let parsed = try parseCIDR(raw, arg, line: line, base: base)
                sink.addIP(address: parsed.address, prefix: parsed.prefix, isIPv6: parsed.isIPv6, isSource: false, policyID: policyID, ruleIndex: ruleIndex)
            case .srcIPCIDR:
                let parsed = try parseCIDR(raw, arg, line: line, base: base)
                sink.addIP(address: parsed.address, prefix: parsed.prefix, isIPv6: parsed.isIPv6, isSource: true, policyID: policyID, ruleIndex: ruleIndex)
            case .port(let side):
                let intervals = try parsePortList(raw, arg, line: line, base: base)
                sink.addPort(intervals, side: side, policyID: policyID, ruleIndex: ruleIndex)
            case .processName:
                try validatePrintable(raw, arg, line: line, base: base, name: "process name")
                sink.addProcessName(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
            case .processPath:
                try validatePrintable(raw, arg, line: line, base: base, name: "process path")
                sink.addProcessPath(raw, arg, policyID: policyID, ruleIndex: ruleIndex)
            case .network:
                let proto = try parseNetwork(raw, arg, line: line, base: base)
                sink.addNetwork(proto, policyID: policyID, ruleIndex: ruleIndex)
            case .dscp:
                let val = try parseDSCP(raw, arg, line: line, base: base)
                sink.addDSCP(val, policyID: policyID, ruleIndex: ruleIndex)
            case .geoIP:
                let code = try parseGeoIP(raw, arg, line: line, base: base)
                sink.addGeoIP(code, policyID: policyID, ruleIndex: ruleIndex)
            case .and:
                let root = try parseAndOrCondition(raw, arg, isAnd: true, line: line, base: base, into: &sink)
                sink.addLogicRule(rootNodeIndex: root, policyID: policyID, ruleIndex: ruleIndex)
            case .or:
                let root = try parseAndOrCondition(raw, arg, isAnd: false, line: line, base: base, into: &sink)
                sink.addLogicRule(rootNodeIndex: root, policyID: policyID, ruleIndex: ruleIndex)
            case .not:
                let root = try parseNotCondition(raw, arg, line: line, base: base, into: &sink)
                sink.addLogicRule(rootNodeIndex: root, policyID: policyID, ruleIndex: ruleIndex)
            case .subRule:
                let root = try parseSubRuleCondition(raw, arg, line: line, base: base, into: &sink)
                sink.addLogicRule(rootNodeIndex: root, policyID: policyID, ruleIndex: ruleIndex)
            case .ruleSet:
                let nestedName = [UInt8](raw[arg])
                guard !activeRuleSets.contains(nestedName) else {
                    throw RuleParseError(.circularRuleSet, line: line, column: arg.lowerBound - base + 1, "circular reference to rule-set '\(String(decoding: nestedName, as: UTF8.self))'")
                }
                if let byteMap = byteRuleSets, let data = byteMap[nestedName] {
                    activeRuleSets.insert(nestedName)
                    defer { activeRuleSets.remove(nestedName) }
                    try withBytes(data, line: line) { ruleSetBytes in
                        try parseRuleSetPayload(
                            ruleSetBytes,
                            policyID: policyID,
                            ruleIndex: ruleIndex,
                            inheritedNoResolve: hasNoResolve,
                            ruleSetResolver: ruleSetResolver,
                            byteRuleSets: byteRuleSets,
                            activeRuleSets: &activeRuleSets,
                            into: &sink
                        )
                    }
                } else if let resolver = ruleSetResolver {
                    let resolved: UnsafeRawBufferPointer? = nestedName.withUnsafeBufferPointer { nameBuf in
                        resolver(nameBuf)
                    }
                    guard let nestedBytes = resolved else {
                        throw RuleParseError(.unknownRuleSet, line: line, column: arg.lowerBound - base + 1, "rule-set '\(String(decoding: nestedName, as: UTF8.self))' not found")
                    }
                    activeRuleSets.insert(nestedName)
                    defer { activeRuleSets.remove(nestedName) }
                    try parseRuleSetPayload(
                        nestedBytes,
                        policyID: policyID,
                        ruleIndex: ruleIndex,
                        inheritedNoResolve: hasNoResolve,
                        ruleSetResolver: ruleSetResolver,
                        byteRuleSets: byteRuleSets,
                        activeRuleSets: &activeRuleSets,
                        into: &sink
                    )
                } else {
                    throw RuleParseError(.unknownRuleSet, line: line, column: arg.lowerBound - base + 1, "rule-set '\(String(decoding: nestedName, as: UTF8.self))' not found")
                }
            case .match:
                throw RuleParseError(.malformedLine, line: line, column: 1, "MATCH is not allowed inside a RULE-SET")
            }
        } else {
            // Check for domain-only or ipcidr-only format (e.g. behavior: domain or behavior: ipcidr)
            guard segments.count == 1 else {
                throw RuleParseError(
                    .unknownRuleType, line: line, column: 1,
                    "unsupported rule type '\(String(decoding: [UInt8](raw[segments[0]]), as: UTF8.self))'"
                )
            }
            let token = segments[0]
            var hasSlash = false
            for i in token where raw[i] == UInt8(ascii: "/") {
                hasSlash = true
                break
            }
            if hasSlash {
                let parsed = try parseCIDR(raw, token, line: line, base: base)
                sink.addIP(address: parsed.address, prefix: parsed.prefix, isIPv6: parsed.isIPv6, isSource: false, policyID: policyID, ruleIndex: ruleIndex)
            } else if raw[token.lowerBound] == UInt8(ascii: ".") {
                let sub = (token.lowerBound + 1)..<token.upperBound
                try validateDomain(raw, sub, line: line, base: base)
                sink.addSuffix(raw, sub, policyID: policyID, ruleIndex: ruleIndex)
            } else if token.count >= 2 && raw[token.lowerBound] == UInt8(ascii: "+") && raw[token.lowerBound + 1] == UInt8(ascii: ".") {
                let sub = (token.lowerBound + 2)..<token.upperBound
                try validateDomain(raw, sub, line: line, base: base)
                sink.addSuffix(raw, sub, policyID: policyID, ruleIndex: ruleIndex)
            } else {
                try validateDomain(raw, token, line: line, base: base)
                sink.addExact(raw, token, policyID: policyID, ruleIndex: ruleIndex)
            }
        }
    }

    // MARK: - Validators

    private static func isInlineSpace(_ b: UInt8) -> Bool {
        b == 0x20 || b == 0x09
    }

    private static let noResolvePattern: [UInt8] = [0x6E, 0x6F, 0x2D, 0x72, 0x65, 0x73, 0x6F, 0x6C, 0x76, 0x65] // "no-resolve"

    private static func isNoResolve(_ raw: UnsafeRawBufferPointer, _ r: Range<Int>) -> Bool {
        guard r.count == 10 else { return false }
        for (k, i) in zip(noResolvePattern, r) where raw[i] != k { return false }
        return true
    }

    private static func validateDomain(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) {
        guard !r.isEmpty else {
            throw RuleParseError(.invalidArgument, line: line, column: 1, "empty domain")
        }
        let dot = UInt8(ascii: ".")
        if raw[r.lowerBound] == dot || raw[r.upperBound - 1] == dot {
            throw RuleParseError(.invalidArgument, line: line, column: r.lowerBound - base + 1, "domain has leading/trailing dot")
        }
        var previousWasDot = false
        for i in r {
            let b = raw[i]
            let isLabelChar = (b >= 0x61 && b <= 0x7A) || (b >= 0x41 && b <= 0x5A)
                || (b >= 0x30 && b <= 0x39)
                || b == dot || b == UInt8(ascii: "-") || b == UInt8(ascii: "_")
            guard isLabelChar else {
                throw RuleParseError(.invalidArgument, line: line, column: i - base + 1, "invalid character in domain")
            }
            if b == dot {
                guard !previousWasDot else {
                    throw RuleParseError(.invalidArgument, line: line, column: i - base + 1, "consecutive dots in domain")
                }
                previousWasDot = true
            } else {
                previousWasDot = false
            }
        }
    }

    private static func validateKeyword(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) {
        guard !r.isEmpty else {
            throw RuleParseError(.invalidArgument, line: line, column: 1, "empty keyword")
        }
        for i in r {
            // Printable or any non-ASCII byte (multi-byte UTF-8 keywords allowed).
            guard raw[i] >= 0x21 else {
                throw RuleParseError(.invalidArgument, line: line, column: i - base + 1, "invalid character in keyword")
            }
        }
    }

    private static func validatePrintable(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int, name: String
    ) throws(RuleParseError) {
        guard !r.isEmpty else {
            throw RuleParseError(.invalidArgument, line: line, column: 1, "empty \(name)")
        }
        for i in r {
            guard raw[i] >= 0x20 else {
                throw RuleParseError(.invalidArgument, line: line, column: i - base + 1, "invalid character in \(name)")
            }
        }
    }

    private static func parseNetwork(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> NetworkProtocol {
        if r.count == 3 {
            let b0 = upperByte(raw[r.lowerBound])
            let b1 = upperByte(raw[r.lowerBound + 1])
            let b2 = upperByte(raw[r.lowerBound + 2])
            if b0 == UInt8(ascii: "T") && b1 == UInt8(ascii: "C") && b2 == UInt8(ascii: "P") {
                return .tcp
            }
            if b0 == UInt8(ascii: "U") && b1 == UInt8(ascii: "D") && b2 == UInt8(ascii: "P") {
                return .udp
            }
        }
        throw RuleParseError(.invalidArgument, line: line, column: r.lowerBound - base + 1, "invalid network protocol (expected TCP or UDP)")
    }

    private static func parseDSCP(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> UInt8 {
        let val = try parseDecimal(raw, r, max: 63, what: "DSCP value", errorCode: .invalidArgument, line: line, base: base)
        return UInt8(val)
    }

    private static func parseGeoIP(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> UInt32 {
        guard r.count >= 2 && r.count <= 4 else {
            throw RuleParseError(.invalidArgument, line: line, column: r.lowerBound - base + 1, "invalid country code length (expected 2..4 letters)")
        }
        var code: UInt32 = 0
        for i in r {
            let b = raw[i]
            let isLetter = (b >= UInt8(ascii: "A") && b <= UInt8(ascii: "Z")) || (b >= UInt8(ascii: "a") && b <= UInt8(ascii: "z"))
            guard isLetter else {
                throw RuleParseError(.invalidArgument, line: line, column: i - base + 1, "invalid character in country code")
            }
            code = (code << 8) | UInt32(upperByte(b))
        }
        return code
    }

    // MARK: - Address / port parsing

    private static func parseCIDR(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> (address: UInt128, prefix: UInt8, isIPv6: Bool) {
        var slash: Int? = nil
        var i = r.lowerBound
        while i < r.upperBound {
            if raw[i] == UInt8(ascii: "/") { slash = i; break }
            i += 1
        }
        guard let s = slash, s > r.lowerBound, s + 1 < r.upperBound else {
            throw RuleParseError(.invalidAddress, line: line, column: r.lowerBound - base + 1, "expected ADDRESS/PREFIX")
        }
        let addressRange = r.lowerBound..<s
        let prefixRange = s + 1..<r.upperBound
        var hasColon = false
        for i in addressRange where raw[i] == UInt8(ascii: ":") { hasColon = true; break }
        let prefix = try parseDecimal(raw, prefixRange, max: UInt32(hasColon ? 128 : 32), what: "prefix length", line: line, base: base)
        let address = hasColon
            ? try parseIPv6(raw, addressRange, line: line, base: base)
            : try parseIPv4(raw, addressRange, line: line, base: base)
        return (address, UInt8(prefix), hasColon)
    }

    private static func parseDecimal(
        _ raw: UnsafeRawBufferPointer,
        _ r: Range<Int>,
        max: UInt32,
        what: String,
        errorCode: RuleParseError.Code = .invalidArgument,
        line: Int,
        base: Int
    ) throws(RuleParseError) -> UInt32 {
        guard !r.isEmpty else {
            throw RuleParseError(errorCode, line: line, column: r.lowerBound - base + 1, "empty \(what)")
        }
        var value: UInt32 = 0
        for i in r {
            let b = raw[i]
            guard b >= 0x30 && b <= 0x39 else {
                throw RuleParseError(errorCode, line: line, column: i - base + 1, "non-digit in \(what)")
            }
            value = value &* 10 &+ UInt32(b - 0x30)
            if value > max {
                throw RuleParseError(errorCode, line: line, column: i - base + 1, "\(what) exceeds \(max)")
            }
        }
        return value
    }

    private static func parseIPv4(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> UInt128 {
        var octets: [UInt32] = []
        var current: UInt32 = 0
        var hasDigit = false
        for i in r {
            let b = raw[i]
            if b == UInt8(ascii: ".") {
                guard hasDigit else {
                    throw RuleParseError(.invalidAddress, line: line, column: i - base + 1, "empty octet")
                }
                octets.append(current)
                current = 0
                hasDigit = false
            } else if b >= 0x30 && b <= 0x39 {
                current = current &* 10 &+ UInt32(b - 0x30)
                if current > 255 {
                    throw RuleParseError(.invalidAddress, line: line, column: i - base + 1, "octet exceeds 255")
                }
                hasDigit = true
            } else {
                throw RuleParseError(.invalidAddress, line: line, column: i - base + 1, "invalid character in IPv4 address")
            }
        }
        guard hasDigit else {
            throw RuleParseError(.invalidAddress, line: line, column: r.upperBound - base, "empty octet")
        }
        octets.append(current)
        guard octets.count == 4 else {
            throw RuleParseError(.invalidAddress, line: line, column: r.lowerBound - base + 1, "IPv4 address needs exactly 4 octets")
        }
        let value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        return UInt128(value)
    }

    private static func parseIPv6(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> UInt128 {
        // Locate "::" (compressed zero run). Two occurrences are an error.
        var doubleColon: Int? = nil
        var i = r.lowerBound
        while i + 1 < r.upperBound {
            if raw[i] == UInt8(ascii: ":") && raw[i + 1] == UInt8(ascii: ":") {
                guard doubleColon == nil else {
                    throw RuleParseError(.invalidAddress, line: line, column: i - base + 1, "multiple '::' in IPv6 address")
                }
                doubleColon = i
                i += 2
            } else {
                i += 1
            }
        }

        if let dc = doubleColon {
            let head = try parseGroups(raw, r.lowerBound..<dc, line: line, base: base)
            let tail = try parseGroups(raw, dc + 2..<r.upperBound, line: line, base: base)
            let total = head.count + tail.count
            guard total <= 7 else {
                throw RuleParseError(.invalidAddress, line: line, column: r.lowerBound - base + 1, "too many groups around '::'")
            }
            var value: UInt128 = 0
            for g in head { value = (value << 16) | UInt128(g) }
            value <<= 16 * (8 - total)
            for g in tail { value = (value << 16) | UInt128(g) }
            return value
        } else {
            let groups = try parseGroups(raw, r, line: line, base: base)
            guard groups.count == 8 else {
                throw RuleParseError(.invalidAddress, line: line, column: r.lowerBound - base + 1, "IPv6 address needs exactly 8 groups")
            }
            var value: UInt128 = 0
            for g in groups { value = (value << 16) | UInt128(g) }
            return value
        }
    }

    private static func parseGroups(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> [UInt32] {
        // An entirely empty range is legal (head/tail of "::"); an empty
        // token *inside* a non-empty range is not.
        guard !r.isEmpty else { return [] }
        var groups: [UInt32] = []
        var tokenStart = r.lowerBound
        var i = r.lowerBound
        while true {
            let atEnd = i == r.upperBound
            if atEnd || raw[i] == UInt8(ascii: ":") {
                let token = tokenStart..<i
                guard !token.isEmpty else {
                    throw RuleParseError(.invalidAddress, line: line, column: i - base + 1, "empty group")
                }
                guard token.count <= 4 else {
                    throw RuleParseError(.invalidAddress, line: line, column: token.lowerBound - base + 1, "group longer than 4 hex digits")
                }
                var value: UInt32 = 0
                for j in token {
                    let b = raw[j]
                    let digit: UInt32
                    if b >= 0x30 && b <= 0x39 { digit = UInt32(b - 0x30) }
                    else if b >= 0x61 && b <= 0x66 { digit = UInt32(b - 0x61 + 10) }
                    else if b >= 0x41 && b <= 0x46 { digit = UInt32(b - 0x41 + 10) }
                    else {
                        throw RuleParseError(.invalidAddress, line: line, column: j - base + 1, "invalid hex digit in IPv6 address")
                    }
                    value = (value << 4) | digit
                }
                groups.append(value)
                if atEnd { break }
                tokenStart = i + 1
            }
            i += 1
        }
        return groups
    }

    private static func parsePortList(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> [(low: UInt16, high: UInt16)] {
        var result: [(low: UInt16, high: UInt16)] = []
        var tokenStart = r.lowerBound
        var i = r.lowerBound
        while true {
            let atEnd = i == r.upperBound
            if atEnd || raw[i] == UInt8(ascii: "/") {
                let token = tokenStart..<i
                guard !token.isEmpty else {
                    throw RuleParseError(.invalidPort, line: line, column: i - base + 1, "empty port token")
                }
                var dash: Int? = nil
                for j in token where raw[j] == UInt8(ascii: "-") { dash = j; break }
                if let d = dash {
                    let lo = try parsePortValue(raw, token.lowerBound..<d, line: line, base: base)
                    let hi = try parsePortValue(raw, d + 1..<token.upperBound, line: line, base: base)
                    guard lo <= hi else {
                        throw RuleParseError(.invalidPort, line: line, column: token.lowerBound - base + 1, "port range low > high")
                    }
                    result.append((low: UInt16(lo), high: UInt16(hi)))
                } else {
                    let p = try parsePortValue(raw, token, line: line, base: base)
                    result.append((low: UInt16(p), high: UInt16(p)))
                }
                if atEnd { break }
                tokenStart = i + 1
            }
            i += 1
        }
        return result
    }

    private static func parsePortValue(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> UInt32 {
        try parseDecimal(raw, r, max: 65535, what: "port", errorCode: .invalidPort, line: line, base: base)
    }

    // MARK: - Logic rules parsing

    private static func parseAndOrCondition(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, isAnd: Bool, line: Int, base: Int, into sink: inout RuleSink
    ) throws(RuleParseError) -> UInt32 {
        var s = r.lowerBound
        var e = r.upperBound
        while s < e && isInlineSpace(raw[s]) { s += 1 }
        while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
        guard e - s >= 2, raw[s] == UInt8(ascii: "("), raw[e - 1] == UInt8(ascii: ")") else {
            throw RuleParseError(.malformedLine, line: line, column: s - base + 1, "expected (condition-list)")
        }
        let inner = (s + 1)..<(e - 1)
        let childRanges = try splitCommaRanges(raw, inner, line: line, base: base)
        guard childRanges.count >= 2 else {
            throw RuleParseError(.malformedLine, line: line, column: s - base + 1, "\(isAnd ? "AND" : "OR") requires at least 2 conditions")
        }
        var childIndices: [UInt32] = []
        childIndices.reserveCapacity(childRanges.count)
        for cr in childRanges {
            let childNode = try parseCondition(raw, cr, line: line, base: base, into: &sink)
            childIndices.append(childNode)
        }
        let firstIndex = sink.addLogicChildIndices(childIndices)
        return sink.addLogicNode(LogicNode(
            op: isAnd ? LogicOp.and.rawValue : LogicOp.or.rawValue,
            childCount: UInt16(childIndices.count),
            firstChildIndex: firstIndex
        ))
    }

    private static func parseNotCondition(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int, into sink: inout RuleSink
    ) throws(RuleParseError) -> UInt32 {
        var s = r.lowerBound
        var e = r.upperBound
        while s < e && isInlineSpace(raw[s]) { s += 1 }
        while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
        guard e - s >= 2, raw[s] == UInt8(ascii: "("), raw[e - 1] == UInt8(ascii: ")") else {
            throw RuleParseError(.malformedLine, line: line, column: s - base + 1, "expected (condition)")
        }
        let inner = (s + 1)..<(e - 1)
        let childRanges = try splitCommaRanges(raw, inner, line: line, base: base)
        guard childRanges.count == 1 else {
            throw RuleParseError(.malformedLine, line: line, column: s - base + 1, "NOT requires exactly 1 condition")
        }
        let childNode = try parseCondition(raw, childRanges[0], line: line, base: base, into: &sink)
        return sink.addLogicNode(LogicNode(
            op: LogicOp.not.rawValue,
            childCount: 1,
            firstChildIndex: childNode
        ))
    }

    private static func parseSubRuleCondition(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int, into sink: inout RuleSink
    ) throws(RuleParseError) -> UInt32 {
        var s = r.lowerBound
        var e = r.upperBound
        while s < e && isInlineSpace(raw[s]) { s += 1 }
        while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
        if e - s >= 2 && raw[s] == UInt8(ascii: "(") && raw[e - 1] == UInt8(ascii: ")") {
            return try parseCondition(raw, (s + 1)..<(e - 1), line: line, base: base, into: &sink)
        }
        return try parseCondition(raw, s..<e, line: line, base: base, into: &sink)
    }

    private static func parseCondition(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int, into sink: inout RuleSink
    ) throws(RuleParseError) -> UInt32 {
        var s = r.lowerBound
        var e = r.upperBound
        while s < e && isInlineSpace(raw[s]) { s += 1 }
        while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
        if e - s >= 2 && raw[s] == UInt8(ascii: "(") && raw[e - 1] == UInt8(ascii: ")") {
            s += 1
            e -= 1
            while s < e && isInlineSpace(raw[s]) { s += 1 }
            while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
        }
        guard s < e else {
            throw RuleParseError(.invalidArgument, line: line, column: s - base + 1, "empty condition")
        }

        let parts = try splitCommaRanges(raw, s..<e, line: line, base: base)
        guard parts.count >= 2 else {
            throw RuleParseError(.malformedLine, line: line, column: s - base + 1, "expected (TYPE,ARG) condition")
        }

        guard let kind = matchKind(raw, parts[0]) else {
            throw RuleParseError(
                .unknownRuleType, line: line, column: parts[0].lowerBound - base + 1,
                "unsupported rule type '\(String(decoding: [UInt8](raw[parts[0]]), as: UTF8.self))' in condition"
            )
        }

        let arg = parts[1]
        switch kind {
        case .and:
            return try parseAndOrCondition(raw, arg, isAnd: true, line: line, base: base, into: &sink)
        case .or:
            return try parseAndOrCondition(raw, arg, isAnd: false, line: line, base: base, into: &sink)
        case .not:
            return try parseNotCondition(raw, arg, line: line, base: base, into: &sink)
        case .domain:
            try validateDomain(raw, arg, line: line, base: base)
            let (off, len) = sink.addLogicString(raw, arg)
            return sink.addLogicNode(LogicNode(op: LogicOp.domain.rawValue, argOffset: off, argLength: len))
        case .domainSuffix:
            try validateDomain(raw, arg, line: line, base: base)
            let (off, len) = sink.addLogicString(raw, arg)
            return sink.addLogicNode(LogicNode(op: LogicOp.domainSuffix.rawValue, argOffset: off, argLength: len))
        case .domainKeyword:
            try validateKeyword(raw, arg, line: line, base: base)
            let (off, len) = sink.addLogicString(raw, arg)
            return sink.addLogicNode(LogicNode(op: LogicOp.domainKeyword.rawValue, argOffset: off, argLength: len))
        case .ipCIDR:
            let parsed = try parseCIDR(raw, arg, line: line, base: base)
            return sink.addLogicNode(LogicNode(
                op: LogicOp.ipCIDR.rawValue,
                flags: parsed.isIPv6 ? 1 : 0,
                addressLow: UInt64(parsed.address & 0xFFFF_FFFF_FFFF_FFFF),
                addressHigh: UInt64(parsed.address >> 64),
                prefix: parsed.prefix
            ))
        case .srcIPCIDR:
            let parsed = try parseCIDR(raw, arg, line: line, base: base)
            return sink.addLogicNode(LogicNode(
                op: LogicOp.ipCIDR.rawValue,
                flags: (parsed.isIPv6 ? 1 : 0) | 2,
                addressLow: UInt64(parsed.address & 0xFFFF_FFFF_FFFF_FFFF),
                addressHigh: UInt64(parsed.address >> 64),
                prefix: parsed.prefix
            ))
        case .port(let side):
            let intervals = try parsePortList(raw, arg, line: line, base: base)
            let flag: UInt8 = (side == .destination) ? 1 : (side == .source ? 2 : 0)
            if intervals.count == 1 {
                return sink.addLogicNode(LogicNode(
                    op: LogicOp.port.rawValue,
                    flags: flag,
                    argLength: intervals[0].high,
                    portLow: intervals[0].low
                ))
            } else {
                var childNodes: [UInt32] = []
                for interval in intervals {
                    let n = sink.addLogicNode(LogicNode(
                        op: LogicOp.port.rawValue,
                        flags: flag,
                        argLength: interval.high,
                        portLow: interval.low
                    ))
                    childNodes.append(n)
                }
                let firstIndex = sink.addLogicChildIndices(childNodes)
                return sink.addLogicNode(LogicNode(
                    op: LogicOp.or.rawValue,
                    childCount: UInt16(childNodes.count),
                    firstChildIndex: firstIndex
                ))
            }
        case .processName:
            try validatePrintable(raw, arg, line: line, base: base, name: "process name")
            let (off, len) = sink.addLogicString(raw, arg)
            return sink.addLogicNode(LogicNode(op: LogicOp.processName.rawValue, argOffset: off, argLength: len))
        case .processPath:
            try validatePrintable(raw, arg, line: line, base: base, name: "process path")
            let (off, len) = sink.addLogicString(raw, arg)
            return sink.addLogicNode(LogicNode(op: LogicOp.processPath.rawValue, argOffset: off, argLength: len))
        case .network:
            let proto = try parseNetwork(raw, arg, line: line, base: base)
            return sink.addLogicNode(LogicNode(op: LogicOp.network.rawValue, networkProto: proto.rawValue))
        case .dscp:
            let val = try parseDSCP(raw, arg, line: line, base: base)
            return sink.addLogicNode(LogicNode(op: LogicOp.dscp.rawValue, portLow: UInt16(val)))
        case .geoIP:
            let code = try parseGeoIP(raw, arg, line: line, base: base)
            return sink.addLogicNode(LogicNode(op: LogicOp.geoIP.rawValue, countryCode: code))
        case .subRule, .match, .ruleSet:
            throw RuleParseError(.malformedLine, line: line, column: parts[0].lowerBound - base + 1, "cannot nest \(String(decoding: [UInt8](raw[parts[0]]), as: UTF8.self)) inside condition")
        }
    }

    private static func splitCommaRanges(
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, line: Int, base: Int
    ) throws(RuleParseError) -> [Range<Int>] {
        var segments: [Range<Int>] = []
        var cursor = r.lowerBound
        var depth = 0
        while cursor < r.upperBound {
            var comma = cursor
            while comma < r.upperBound {
                let b = raw[comma]
                if b == UInt8(ascii: "(") { depth += 1 }
                else if b == UInt8(ascii: ")") {
                    guard depth > 0 else {
                        throw RuleParseError(.malformedLine, line: line, column: comma - base + 1, "unmatched ')'")
                    }
                    depth -= 1
                }
                else if b == UInt8(ascii: ",") && depth == 0 { break }
                comma += 1
            }
            guard depth == 0 else {
                throw RuleParseError(.malformedLine, line: line, column: cursor - base + 1, "unclosed '('")
            }
            var s = cursor, e = comma
            while s < e && isInlineSpace(raw[s]) { s += 1 }
            while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
            segments.append(s..<e)
            if comma >= r.upperBound { break }
            cursor = comma + 1
        }
        return segments
    }
}
