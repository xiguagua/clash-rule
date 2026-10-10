import ClashRuleCore
import Foundation

public struct ToolResult: Equatable, Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
}

/// `clash-rule` 命令行的可测试入口。文件读取通过 `readFile` 注入，便于测试。
public enum ClashRuleTool {
    public static func run(
        _ arguments: [String],
        readFile: (String) throws -> String = { try String(contentsOfFile: $0, encoding: .utf8) }
    ) -> ToolResult {
        let command: Command
        do {
            command = try ArgumentParser.parse(arguments)
        } catch {
            return ToolResult(exitCode: 2, stdout: "", stderr: "错误：\(error.message)\n\n\(usage)")
        }

        switch command {
        case .help:
            return ToolResult(exitCode: 0, stdout: usage, stderr: "")
        case .check(let options):
            return check(options, readFile: readFile)
        case .explain(let options):
            return explain(options, readFile: readFile)
        }
    }

    private static func check(_ options: CheckOptions, readFile: (String) throws -> String) -> ToolResult {
        do {
            let loaded = try load(options.rulesPath, ruleSets: options.ruleSets, readFile: readFile)
            let lines = [
                "编译通过：\(loaded.path)",
                "规则数：\(loaded.rules.ruleCount)",
                "策略数：\(loaded.rules.policyCount)",
                "快照大小：\(loaded.rules.approximateMemoryBytes) 字节",
            ]
            return ToolResult(exitCode: 0, stdout: lines.joined(separator: "\n") + "\n", stderr: "")
        } catch {
            return ToolResult(exitCode: 1, stdout: "", stderr: error.message + "\n")
        }
    }

    private static func explain(_ options: ExplainOptions, readFile: (String) throws -> String) -> ToolResult {
        do {
            let loaded = try load(options.rulesPath, ruleSets: options.ruleSets, readFile: readFile)
            let context = MatchContext(
                domain: Array((options.domain ?? "").utf8),
                targetAddress: options.targetIP.flatMap(parseIPAddress),
                targetPort: options.targetPort ?? 0,
                sourceAddress: options.sourceIP.flatMap(parseIPAddress),
                sourcePort: options.sourcePort ?? 0,
                processName: Array((options.processName ?? "").utf8),
                processPath: Array((options.processPath ?? "").utf8),
                network: options.network,
                dscp: options.dscp,
                countryCode: options.country.map(packCountryCode) ?? 0
            )
            let trace = Matcher(loaded.rules).explain(context: context)
            let stdout = renderExplain(
                loaded: loaded,
                request: describeRequest(options),
                trace: trace
            )
            return ToolResult(exitCode: 0, stdout: stdout, stderr: "")
        } catch {
            return ToolResult(exitCode: 1, stdout: "", stderr: error.message + "\n")
        }
    }

    private static func load(
        _ path: String,
        ruleSets: [RuleSetFile],
        readFile: (String) throws -> String
    ) throws(ToolFailure) -> LoadedRules {
        var contents: [String: String] = [:]
        for ruleSet in ruleSets {
            contents[ruleSet.name] = try read(ruleSet.path, readFile: readFile)
        }
        let text = try read(path, readFile: readFile)
        do {
            let rules = try RuleCompiler.compile(text, ruleSets: contents)
            return LoadedRules(path: path, text: text, rules: rules)
        } catch {
            throw ToolFailure("\(path):\(error)")
        }
    }

    private static func read(_ path: String, readFile: (String) throws -> String) throws(ToolFailure) -> String {
        do {
            return try readFile(path)
        } catch {
            throw ToolFailure("无法读取文件 \(path)：\(error.localizedDescription)")
        }
    }

    private static func describeRequest(_ options: ExplainOptions) -> [String] {
        var parts: [String] = []
        if let domain = options.domain { parts.append("域名=\(domain)") }
        if let ip = options.targetIP { parts.append("IP=\(ip)") }
        if let port = options.targetPort { parts.append("端口=\(port)") }
        if let ip = options.sourceIP { parts.append("源IP=\(ip)") }
        if let port = options.sourcePort { parts.append("源端口=\(port)") }
        if let name = options.processName { parts.append("进程名=\(name)") }
        if let path = options.processPath { parts.append("进程路径=\(path)") }
        if let network = options.network { parts.append("网络=\(network == .tcp ? "tcp" : "udp")") }
        if let dscp = options.dscp { parts.append("DSCP=\(dscp)") }
        if let country = options.country { parts.append("国家=\(country)") }
        return parts
    }
}

struct ToolFailure: Error {
    let message: String

    init(_ message: String) {
        self.message = message
    }
}

struct LoadedRules {
    let path: String
    let text: String
    let rules: CompiledRules
}

private let usage = """
用法：
  clash-rule check <规则文件> [--rule-set 名称=路径]...
      编译规则文件，输出规则数与快照大小。
  clash-rule explain <规则文件> [选项] [--rule-set 名称=路径]...
      对一个请求逐类别求值，说明命中、未命中以及被覆盖的原因。
  clash-rule help
      显示本帮助。

explain 选项：
  --domain <域名>          请求域名
  --ip <地址>              目标 IP（IPv4 或 IPv6）
  --port <端口>            目标端口
  --src-ip <地址>          源 IP
  --src-port <端口>        源端口
  --process-name <名称>    进程名
  --process-path <路径>    进程路径
  --network <tcp|udp>      网络协议
  --dscp <0-63>            DSCP
  --country <国家码>        两位国家码，例如 US

退出码：0 成功（含未命中）；1 规则或文件错误；2 参数错误。

"""
