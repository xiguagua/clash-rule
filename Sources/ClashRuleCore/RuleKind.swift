/// Rule categories supported by this build (M1 subset, docs/PLAN.md §8).
public enum RuleKind: Sendable, Equatable {
    case domain
    case domainSuffix
    case domainKeyword
    case ipCIDR(isIPv6: Bool)
    case port(PortSide)
    case match
}

/// Which port a `PORT`-family rule consults.
public enum PortSide: Sendable, Equatable {
    case destination   // DST-PORT
    case source        // SRC-PORT
    case either        // PORT (matches source or destination)
}
