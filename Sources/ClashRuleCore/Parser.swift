/// Zero-copy line scanner over UTF-8 rule text.
///
/// Input is a `RawSpan` (SE-0447); no `String` is ever materialized. Validated
/// rules are handed to a `RuleSink` as borrowed byte ranges, which the sink
/// copies into compile-phase arenas (docs/PLAN.md §2.1, §6).
///
/// M1 parses: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6,
/// PORT, DST-PORT, SRC-PORT, MATCH. Unknown types fail fast (docs/PLAN.md §6).
struct RuleParser {
    private static let kindTable: [[UInt8]: RuleKind] = {
        var table: [[UInt8]: RuleKind] = [:]
        func add(_ name: String, _ kind: RuleKind) {
            table[[UInt8](name.uppercased().utf8)] = kind
        }
        add("DOMAIN", .domain)
        add("DOMAIN-SUFFIX", .domainSuffix)
        add("DOMAIN-KEYWORD", .domainKeyword)
        add("IP-CIDR", .ipCIDR(isIPv6: false))
        add("IP-CIDR6", .ipCIDR(isIPv6: true))
        add("PORT", .port(.either))
        add("DST-PORT", .port(.destination))
        add("SRC-PORT", .port(.source))
        add("MATCH", .match)
        return table
    }()

    static func parse(_ input: UnsafeRawBufferPointer, into sink: inout RuleSink) throws(RuleParseError) {
        let n = input.count
        var i = 0
        var line = 1
        while true {
            var j = i
            while j < n && input[j] != UInt8(ascii: "\n") { j += 1 }
            var length = j - i
            if length > 0 && input[i + length - 1] == UInt8(ascii: "\r") { length -= 1 }
            try parseLine(input, i..<(i + length), line: line, into: &sink)
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
        into sink: inout RuleSink
    ) throws(RuleParseError) {
        let base = range.lowerBound
        var start = base
        var stop = range.upperBound
        while start < stop && isInlineSpace(raw[start]) { start += 1 }
        while stop > start && isInlineSpace(raw[stop - 1]) { stop -= 1 }
        if start == stop { return }
        if raw[start] == UInt8(ascii: "#") { return }

        // Split into comma segments, trimming whitespace around each one.
        var segments: [Range<Int>] = []
        var cursor = start
        while true {
            var comma = cursor
            while comma < stop && raw[comma] != UInt8(ascii: ",") { comma += 1 }
            var s = cursor, e = comma
            while s < e && isInlineSpace(raw[s]) { s += 1 }
            while e > s && isInlineSpace(raw[e - 1]) { e -= 1 }
            segments.append(s..<e)
            if comma == stop { break }
            cursor = comma + 1
        }

        // Rule type name (case-insensitive).
        var typeName = [UInt8]()
        typeName.reserveCapacity(segments[0].count)
        for i in segments[0] { typeName.append(upperByte(raw[i])) }
        guard let kind = kindTable[typeName] else {
            throw RuleParseError(
                .unknownRuleType, line: line, column: 1,
                "unsupported rule type '\(String(decoding: typeName, as: UTF8.self))' (M1 supports DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6, PORT, DST-PORT, SRC-PORT, MATCH)"
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

        // Flags: only `no-resolve` is accepted, and only on IP-CIDR rules.
        var allowNoResolve = false
        if case .ipCIDR = kind { allowNoResolve = true }
        for flagRange in segments[3...] {
            if flagRange.isEmpty { continue }
            guard allowNoResolve, isNoResolve(raw, flagRange) else {
                throw RuleParseError(
                    .unknownFlag, line: line, column: flagRange.lowerBound - base + 1,
                    "unsupported flag (only 'no-resolve' on IP-CIDR is accepted)"
                )
            }
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
            sink.addIP(address: parsed.address, prefix: parsed.prefix, isIPv6: parsed.isIPv6, policyID: policyID, ruleIndex: ruleIndex)
        case .port(let side):
            let intervals = try parsePortList(raw, arg, line: line, base: base)
            sink.addPort(intervals, side: side, policyID: policyID, ruleIndex: ruleIndex)
        case .match:
            break // handled above
        }
        sink.commitLine()
    }

    // MARK: - Validators

    private static func isInlineSpace(_ b: UInt8) -> Bool {
        b == 0x20 || b == 0x09
    }

    private static func isNoResolve(_ raw: UnsafeRawBufferPointer, _ r: Range<Int>) -> Bool {
        guard r.count == 10 else { return false }
        let pattern: [UInt8] = [0x6E, 0x6F, 0x2D, 0x72, 0x65, 0x73, 0x6F, 0x6C, 0x76, 0x65] // "no-resolve"
        for (k, i) in zip(pattern, r) where raw[i] != k { return false }
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
        _ raw: UnsafeRawBufferPointer, _ r: Range<Int>, max: UInt32, what: String, line: Int, base: Int
    ) throws(RuleParseError) -> UInt32 {
        guard !r.isEmpty else {
            throw RuleParseError(.invalidArgument, line: line, column: r.lowerBound - base + 1, "empty \(what)")
        }
        var value: UInt32 = 0
        for i in r {
            let b = raw[i]
            guard b >= 0x30 && b <= 0x39 else {
                throw RuleParseError(.invalidArgument, line: line, column: i - base + 1, "non-digit in \(what)")
            }
            value = value &* 10 &+ UInt32(b - 0x30)
            if value > max {
                throw RuleParseError(.invalidArgument, line: line, column: i - base + 1, "\(what) exceeds \(max)")
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
        guard !r.isEmpty else {
            throw RuleParseError(.invalidPort, line: line, column: r.lowerBound - base + 1, "empty port")
        }
        var value: UInt32 = 0
        for i in r {
            let b = raw[i]
            guard b >= 0x30 && b <= 0x39 else {
                throw RuleParseError(.invalidPort, line: line, column: i - base + 1, "non-digit in port")
            }
            value = value &* 10 &+ UInt32(b - 0x30)
            if value > 65535 {
                throw RuleParseError(.invalidPort, line: line, column: i - base + 1, "port exceeds 65535")
            }
        }
        return value
    }
}
