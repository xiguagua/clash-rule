import Testing
@testable import ClashRuleTool

@Suite struct ClashRuleToolTests {
    private struct MissingFile: Error {}

    private func reader(_ files: [String: String]) -> (String) throws -> String {
        { path in
            guard let contents = files[path] else { throw MissingFile() }
            return contents
        }
    }

    @Test func noArgumentsPrintsUsage() {
        let result = ClashRuleTool.run([], readFile: reader([:]))
        #expect(result.exitCode == 0)
        #expect(result.stdout.contains("用法"))
    }

    @Test func unknownSubcommandIsUsageError() {
        let result = ClashRuleTool.run(["frobnicate"], readFile: reader([:]))
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("未知子命令：frobnicate"))
    }

    @Test func checkReportsRuleAndPolicyCounts() {
        let files = ["rules.txt": "DOMAIN,a.com,DIRECT\nMATCH,PROXY"]
        let result = ClashRuleTool.run(["check", "rules.txt"], readFile: reader(files))
        #expect(result.exitCode == 0)
        #expect(result.stdout.contains("规则数：2"))
        #expect(result.stdout.contains("策略数：2"))
    }

    @Test func checkReportsCompileErrorWithLocation() {
        let files = ["rules.txt": "DOMAIN,a.com,DIRECT\nBOGUS,x,Y"]
        let result = ClashRuleTool.run(["check", "rules.txt"], readFile: reader(files))
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("rules.txt:2:1"))
    }

    @Test func missingRulesFileIsFailure() {
        let result = ClashRuleTool.run(["check", "absent.txt"], readFile: reader([:]))
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("无法读取文件 absent.txt"))
    }

    @Test func checkResolvesRuleSetFromFile() {
        let files = [
            "rules.txt": "RULE-SET,ads,REJECT\nMATCH,DIRECT",
            "ads.txt": "DOMAIN,a.com",
        ]
        let result = ClashRuleTool.run(
            ["check", "rules.txt", "--rule-set", "ads=ads.txt"],
            readFile: reader(files)
        )
        #expect(result.exitCode == 0)
    }

    @Test func explainShowsWinnerAndMarksCoveredHits() {
        let files = ["rules.txt": "DOMAIN-SUFFIX,a.com,PROXY\nDOMAIN-KEYWORD,a,DIRECT"]
        let result = ClashRuleTool.run(
            ["explain", "rules.txt", "--domain", "a.com"],
            readFile: reader(files)
        )
        #expect(result.exitCode == 0)
        #expect(result.stdout.contains("[胜出]"))
        #expect(result.stdout.contains("[被 #0"))
        #expect(result.stdout.contains("结果：命中 #0"))
        #expect(result.stdout.contains("→ PROXY"))
        #if Diagnostics
        #expect(result.stdout.contains("[被 #0（第 1 行）覆盖]"))
        #endif
    }

    @Test func explainReportsNoMatch() {
        let files = ["rules.txt": "DOMAIN,b.com,DIRECT"]
        let result = ClashRuleTool.run(
            ["explain", "rules.txt", "--domain", "a.com"],
            readFile: reader(files)
        )
        #expect(result.exitCode == 0)
        #expect(result.stdout.contains("结果：未命中"))
    }

    @Test func explainResolvesRuleSetHit() {
        let files = [
            "rules.txt": "RULE-SET,ads,REJECT\nMATCH,DIRECT",
            "ads.txt": "DOMAIN,a.com",
        ]
        let result = ClashRuleTool.run(
            ["explain", "rules.txt", "--domain", "a.com", "--rule-set", "ads=ads.txt"],
            readFile: reader(files)
        )
        #expect(result.exitCode == 0)
        #expect(result.stdout.contains("结果：命中 #0"))
        #expect(result.stdout.contains("→ REJECT"))
    }

    @Test func explainAcceptsIPPortAndNetwork() {
        let files = ["rules.txt": "IP-CIDR,10.0.0.0/8,PROXY\nDST-PORT,443,TLS\nNETWORK,tcp,TCP\nMATCH,DIRECT"]
        let result = ClashRuleTool.run(
            ["explain", "rules.txt", "--ip", "10.1.2.3", "--port", "443", "--network", "tcp"],
            readFile: reader(files)
        )
        #expect(result.exitCode == 0)
        #expect(result.stdout.contains("IP=10.1.2.3"))
        #expect(result.stdout.contains("结果：命中 #0"))
        #expect(result.stdout.contains("→ PROXY"))
    }

    @Test func explainRejectsInvalidOptionValues() {
        let rules = reader(["rules.txt": "MATCH,DIRECT"])
        #expect(ClashRuleTool.run(["explain", "rules.txt", "--ip", "999.1.1.1"], readFile: rules).exitCode == 2)
        #expect(ClashRuleTool.run(["explain", "rules.txt", "--port", "70000"], readFile: rules).exitCode == 2)
        #expect(ClashRuleTool.run(["explain", "rules.txt", "--dscp", "64"], readFile: rules).exitCode == 2)
        #expect(ClashRuleTool.run(["explain", "rules.txt", "--network", "icmp"], readFile: rules).exitCode == 2)
        #expect(ClashRuleTool.run(["explain", "rules.txt", "--country", "USA"], readFile: rules).exitCode == 2)
        #expect(ClashRuleTool.run(["explain", "rules.txt", "--domain"], readFile: rules).exitCode == 2)
        #expect(ClashRuleTool.run(["explain", "rules.txt", "--bogus", "x"], readFile: rules).exitCode == 2)
    }

    @Test func ruleSetOptionRequiresNameAndPath() {
        let rules = reader(["rules.txt": "MATCH,DIRECT"])
        #expect(ClashRuleTool.run(["check", "rules.txt", "--rule-set", "ads"], readFile: rules).exitCode == 2)
        #expect(ClashRuleTool.run(["check", "rules.txt", "--rule-set", "=ads.txt"], readFile: rules).exitCode == 2)
    }

    @Test func sourceLineIsShownOnlyWithDiagnostics() {
        let files = ["rules.txt": "# comment\nDOMAIN-SUFFIX,a.com,PROXY"]
        let result = ClashRuleTool.run(
            ["explain", "rules.txt", "--domain", "a.com"],
            readFile: reader(files)
        )
        #if Diagnostics
        #expect(result.stdout.contains("第 2 行：DOMAIN-SUFFIX,a.com,PROXY"))
        #expect(!result.stdout.contains("Diagnostics trait"))
        #else
        #expect(!result.stdout.contains("第 2 行"))
        #expect(result.stdout.contains("--traits Diagnostics"))
        #endif
    }
}
