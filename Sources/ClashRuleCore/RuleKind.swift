/// Rule categories supported by clash-rule.
public enum RuleKind: Sendable, Equatable {
    case domain
    case domainSuffix
    case domainKeyword
    case ipCIDR(isIPv6: Bool)
    case srcIPCIDR(isIPv6: Bool)
    case port(PortSide)
    case processName
    case processPath
    case network
    case dscp
    case geoIP
    case and
    case or
    case not
    case subRule
    case match
}

/// Which port a `PORT`-family rule consults.
public enum PortSide: Sendable, Equatable {
    case destination   // DST-PORT
    case source        // SRC-PORT
    case either        // PORT (matches source or destination)
}

/// Network protocol for `NETWORK` rules.
public enum NetworkProtocol: UInt8, Sendable, Equatable {
    case tcp = 1
    case udp = 2
}
