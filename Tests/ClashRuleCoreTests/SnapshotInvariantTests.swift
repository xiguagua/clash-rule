import Testing
@testable import ClashRuleCore

@Suite struct SnapshotInvariantTests {
    /// 覆盖各类别的样例：每个会被不变量检查的结构至少出现一次。
    private static let sample = """
        DOMAIN,exact.com,P1
        DOMAIN-SUFFIX,example.com,P2
        DOMAIN-KEYWORD,ab,P3
        DOMAIN-KEYWORD,cd,P4
        IP-CIDR,10.0.0.0/8,P5
        IP-CIDR6,2001:db8::/32,P6
        SRC-IP-CIDR,192.168.0.0/16,P7
        DST-PORT,443,P8
        SRC-PORT,1000-2000,P9
        PROCESS-NAME,curl,P10
        PROCESS-PATH,/usr/bin/wget,P11
        NETWORK,udp,P12
        DSCP,46,P13
        GEOIP,US,P14
        AND,((DOMAIN-SUFFIX,x.com),(PORT,80)),P15
        MATCH,P16
        """

    @Test func compiledSnapshotsSatisfyInvariants() throws {
        for text in [Self.sample, "", "MATCH,DIRECT", "DOMAIN,a.com,DIRECT\nDOMAIN,a.com,PROXY"] {
            let rules = try RuleCompiler.compile(text)
            #expect(rules.invariantViolations().isEmpty, "\(text)")
        }
    }

    private func violations(after mutate: (inout CompiledRules) -> Void) throws -> [String] {
        var rules = try RuleCompiler.compile(Self.sample)
        #expect(rules.invariantViolations().isEmpty)
        mutate(&rules)
        return rules.invariantViolations()
    }

    @Test func detectsRuleIndexOutOfRange() throws {
        let found = try violations { rules in
            let slot = rules.exactEntries.firstIndex { $0.keyLength != 0 }!
            rules.exactEntries[slot].ruleIndex = 9999
        }
        #expect(!found.isEmpty)
    }

    @Test func detectsPolicyNameOverflow() throws {
        let found = try violations { rules in
            rules.policyNameRefs[0].length = 60000
        }
        #expect(!found.isEmpty)
    }

    @Test func detectsTrieChildOutOfRange() throws {
        let found = try violations { rules in
            rules.trieChildIndices[0] = UInt32(rules.trieNodes.count)
        }
        #expect(!found.isEmpty)
    }

    @Test func detectsTrieCycle() throws {
        let found = try violations { rules in
            let first = Int(rules.trieNodes[0].firstChildEntry)
            rules.trieChildIndices[first] = 0
        }
        #expect(!found.isEmpty)
    }

    @Test func detectsBrokenIPTrieLink() throws {
        let found = try violations { rules in
            rules.ipv4Nodes[0].left = 0
        }
        #expect(!found.isEmpty)
    }

    @Test func detectsStalePortMaxHigh() throws {
        let found = try violations { rules in
            rules.portEntries[0].maxHigh = 0
        }
        #expect(!found.isEmpty)
    }

    @Test func detectsKeywordOrderViolation() throws {
        let found = try violations { rules in
            rules.keywordEntries.swapAt(0, 1)
        }
        #expect(!found.isEmpty)
    }

    @Test func detectsStaleCategoryBounds() throws {
        let found = try violations { rules in
            rules._bounds.minExactRule = 99
        }
        #expect(!found.isEmpty)
    }

    @Test func detectsMatchPolicyOutOfRange() throws {
        let found = try violations { rules in
            rules.matchPolicy = 999
        }
        #expect(!found.isEmpty)
    }
}
