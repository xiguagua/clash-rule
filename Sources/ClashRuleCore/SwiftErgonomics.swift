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
        let bytes = Array(text.utf8)
        if ruleSets.isEmpty {
            return try compile(bytes.span.bytes)
        } else {
            return try compile(bytes.span.bytes, ruleSets: ruleSets)
        }
    }
}

// MARK: - IP 解析

/// 把 "10.0.0.1" / "2001:db8::1" 解析为内部 `UInt128`（IPv4 占低 32 位）。
/// 解析失败返回 nil。便捷层专用，热路径请直接传 `UInt128`。
public func parseIPAddress(_ string: String) -> UInt128? {
    let bytes = Array(string.utf8)
    if bytes.contains(UInt8(ascii: ":")) {
        return parseIPv6String(bytes)
    }
    return parseIPv4String(bytes)
}

private func parseIPv4String(_ bytes: [UInt8]) -> UInt128? {
    var octets: [UInt32] = []
    octets.reserveCapacity(4)
    var current: UInt32 = 0
    var hasDigit = false
    func flush() -> Bool {
        guard hasDigit else { return false }
        octets.append(current)
        current = 0
        hasDigit = false
        return true
    }
    for b in bytes {
        if b == UInt8(ascii: ".") {
            guard flush() else { return nil }
        } else if b >= 0x30 && b <= 0x39 {
            current = current &* 10 &+ UInt32(b - 0x30)
            guard current <= 255 else { return nil }
            hasDigit = true
        } else {
            return nil
        }
    }
    guard flush(), octets.count == 4 else { return nil }
    let value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    return UInt128(value)
}

private func parseIPv6String(_ bytes: [UInt8]) -> UInt128? {
    // 找 "::"，最多出现一次。
    var doubleColon: Int? = nil
    var i = 0
    while i + 1 < bytes.count {
        if bytes[i] == UInt8(ascii: ":") && bytes[i + 1] == UInt8(ascii: ":") {
            guard doubleColon == nil else { return nil }
            doubleColon = i
            i += 2
        } else {
            i += 1
        }
    }
    func groups(_ slice: ArraySlice<UInt8>) -> [UInt32]? {
        if slice.isEmpty { return [] }
        var out: [UInt32] = []
        var token: [UInt8] = []
        func flushToken() -> Bool {
            guard !token.isEmpty, token.count <= 4 else { return false }
            var v: UInt32 = 0
            for b in token {
                let d: UInt32
                if b >= 0x30 && b <= 0x39 { d = UInt32(b - 0x30) }
                else if b >= 0x61 && b <= 0x66 { d = UInt32(b - 0x61 + 10) }
                else if b >= 0x41 && b <= 0x46 { d = UInt32(b - 0x41 + 10) }
                else { return false }
                v = (v << 4) | d
            }
            out.append(v)
            token.removeAll(keepingCapacity: true)
            return true
        }
        for b in slice {
            if b == UInt8(ascii: ":") {
                guard flushToken() else { return nil }
            } else {
                token.append(b)
            }
        }
        guard flushToken() else { return nil }
        return out
    }
    if let dc = doubleColon {
        guard let head = groups(bytes[..<dc]), let tail = groups(bytes[(dc + 2)...]) else { return nil }
        let total = head.count + tail.count
        guard total <= 7 else { return nil }
        var value: UInt128 = 0
        for g in head { value = (value << 16) | UInt128(g) }
        value <<= 16 * (8 - total)
        for g in tail { value = (value << 16) | UInt128(g) }
        return value
    } else {
        guard let g = groups(bytes[...]), g.count == 8 else { return nil }
        var value: UInt128 = 0
        for x in g { value = (value << 16) | UInt128(x) }
        return value
    }
}

// MARK: - 匹配

extension Matcher {
    /// 最常用的查询：给域名/IP/端口，直接拿策略名。
    ///
    /// ```swift
    /// let policy: String? = matcher.policy(forDomain: "www.example.com")
    /// let policy2: String? = matcher.policy(forIP: "10.1.2.3", port: 443)
    /// ```
    /// - Note: 每次调用会有一次 UTF-8 转字节分配。超高频场景请复用
    ///   `[UInt8]` 缓冲并直接调用 `match(domain: buffer.span)` 热路径接口。
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
        let domainBytes = Array(domain.utf8)
        let processBytes = processName.map { Array($0.utf8) } ?? []
        let targetAddress = targetIP.flatMap(parseIPAddress)
        let sourceAddress = sourceIP.flatMap(parseIPAddress)
        let countryCode: UInt32 = country.map(packCountryCode) ?? 0
        return match(
            domain: domainBytes.span,
            targetAddress: targetAddress,
            targetPort: targetPort,
            sourceAddress: sourceAddress,
            sourcePort: sourcePort,
            processName: processBytes.span,
            network: network,
            countryCode: countryCode
        )
    }
}
