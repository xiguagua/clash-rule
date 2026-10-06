/// Swift 便捷接口（非热路径，允许分配）。
///
/// 核心 `RuleCompiler.compile(RawSpan)` / `Matcher.match(domain: Span<UInt8>)`
/// 是零分配热路径，调用繁琐是有意为之。本文件只做薄封装：
/// String/Data -> 字节 -> 调用核心，方便业务层直接使用。

// MARK: - 编译

extension RuleCompiler {
    /// 从规则文本编译，`String` 便捷重载。
    public static func compile(
        _ text: String,
        ruleSets: [String: String] = [:]
    ) throws -> CompiledRules {
        if ruleSets.isEmpty {
            return try compile(text.utf8.span.bytes)
        } else {
            return try compile(text.utf8.span.bytes, ruleSets: ruleSets)
        }
    }
}

// MARK: - IP 解析

/// 把 "10.0.0.1" / "2001:db8::1" 解析为内部 `UInt128`（IPv4 占低 32 位）。
/// 解析失败返回 nil。便捷层专用，热路径请直接传 `UInt128`。
public func parseIPAddress(_ string: String) -> UInt128? {
    parseIPAddressUTF8(string.utf8.span)
}

private func parseIPAddressUTF8(_ bytes: Span<UInt8>) -> UInt128? {
    var hasColon = false
    var doubleColon: Int? = nil
    var i = 0
    while i < bytes.count {
        if bytes[i] == UInt8(ascii: ":") {
            hasColon = true
            if i + 1 < bytes.count && bytes[i + 1] == UInt8(ascii: ":") {
                guard doubleColon == nil else { return nil }
                doubleColon = i
                i += 2
            } else {
                i += 1
            }
        } else {
            i += 1
        }
    }
    if hasColon {
        return parseIPv6String(bytes, doubleColon: doubleColon)
    }
    return parseIPv4String(bytes)
}

private func parseIPv4String(_ bytes: Span<UInt8>) -> UInt128? {
    var octetCount = 0
    var packed: UInt32 = 0
    var current: UInt32 = 0
    var hasDigit = false
    for b in bytes {
        if b == UInt8(ascii: ".") {
            guard hasDigit, octetCount < 4 else { return nil }
            packed = (packed << 8) | current
            octetCount += 1
            current = 0
            hasDigit = false
        } else if b >= 0x30 && b <= 0x39 {
            let digit = UInt32(b - 0x30)
            guard current <= (255 - digit) / 10 else { return nil }
            current = current * 10 + digit
            hasDigit = true
        } else {
            return nil
        }
    }
    guard hasDigit, octetCount == 3 else { return nil }
    packed = (packed << 8) | current
    return UInt128(packed)
}

private func parseIPv6String(
    _ bytes: Span<UInt8>, doubleColon: Int?
) -> UInt128? {
    if let dc = doubleColon {
        guard let head = parseIPv6Groups(bytes, 0..<dc),
              let tail = parseIPv6Groups(bytes, (dc + 2)..<bytes.count) else { return nil }
        let total = head.count + tail.count
        guard total <= 7 else { return nil }
        var value = head.value
        value <<= 16 * (8 - total)
        value = (value << (16 * tail.count)) | tail.value
        return value
    } else {
        guard let groups = parseIPv6Groups(bytes, 0..<bytes.count), groups.count == 8 else { return nil }
        return groups.value
    }
}

private func parseIPv6Groups(
    _ bytes: Span<UInt8>, _ range: Range<Int>
) -> (value: UInt128, count: Int)? {
    guard !range.isEmpty else { return (0, 0) }

    var packed: UInt128 = 0
    var groupCount = 0
    var tokenStart = range.lowerBound
    var i = range.lowerBound
    while true {
        let atEnd = i == range.upperBound
        if atEnd || bytes[i] == UInt8(ascii: ":") {
            let tokenLength = i - tokenStart
            guard tokenLength > 0, tokenLength <= 4 else { return nil }

            var group: UInt32 = 0
            for j in tokenStart..<i {
                let b = bytes[j]
                let digit: UInt32
                if b >= 0x30 && b <= 0x39 { digit = UInt32(b - 0x30) }
                else if b >= 0x61 && b <= 0x66 { digit = UInt32(b - 0x61 + 10) }
                else if b >= 0x41 && b <= 0x46 { digit = UInt32(b - 0x41 + 10) }
                else { return nil }
                group = (group << 4) | digit
            }

            packed = (packed << 16) | UInt128(group)
            groupCount += 1
            if atEnd { break }
            tokenStart = i + 1
        }
        i += 1
    }
    return (packed, groupCount)
}

// MARK: - 匹配

extension Matcher {
    /// 最常用的查询：给域名/IP/端口，直接拿策略名。
    ///
    /// ```swift
    /// let policy: String? = matcher.policy(forDomain: "www.example.com")
    /// let policy2: String? = matcher.policy(forIP: "10.1.2.3", port: 443)
    /// ```
    /// - Note: 域名和进程名直接以 UTF-8 span 传入，不显式创建字节数组；IP
    ///   字符串解析和策略名字符串返回仍可能分配。超高频场景请复用 `[UInt8]`
    ///   缓冲，并直接调用 `match(domain: buffer.span)` 热路径接口。
    public func policy(
        forDomain domain: String = "",
        targetIP: String? = nil,
        targetPort: UInt16 = 0,
        sourceIP: String? = nil,
        sourcePort: UInt16 = 0,
        processName: String? = nil,
        network: NetworkProtocol? = nil,
        country: String? = nil
    ) -> String? {
        guard let result = match(
            forDomain: domain,
            targetIP: targetIP,
            targetPort: targetPort,
            sourceIP: sourceIP,
            sourcePort: sourcePort,
            processName: processName,
            network: network,
            country: country
        ) else { return nil }
        return rules.policyName(result.policyID)
    }

    /// `String` 版 match，返回原始 `MatchResult`（含 `policyID` + `ruleIndex`）。
    public func match(
        forDomain domain: String = "",
        targetIP: String? = nil,
        targetPort: UInt16 = 0,
        sourceIP: String? = nil,
        sourcePort: UInt16 = 0,
        processName: String? = nil,
        network: NetworkProtocol? = nil,
        country: String? = nil
    ) -> MatchResult? {
        let targetAddress = targetIP.flatMap(parseIPAddress)
        let sourceAddress = sourceIP.flatMap(parseIPAddress)
        let countryCode: UInt32 = country.map(packCountryCode) ?? 0
        if let processName {
            return match(
                domain: domain.utf8.span,
                targetAddress: targetAddress,
                targetPort: targetPort,
                sourceAddress: sourceAddress,
                sourcePort: sourcePort,
                processName: processName.utf8.span,
                network: network,
                countryCode: countryCode
            )
        }
        return match(
            domain: domain.utf8.span,
            targetAddress: targetAddress,
            targetPort: targetPort,
            sourceAddress: sourceAddress,
            sourcePort: sourcePort,
            network: network,
            countryCode: countryCode
        )
    }
}
