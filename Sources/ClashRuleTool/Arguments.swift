import ClashRuleCore

struct UsageError: Error, Equatable {
    let message: String

    init(_ message: String) {
        self.message = message
    }
}

enum Command: Equatable {
    case help
    case check(CheckOptions)
    case explain(ExplainOptions)
}

struct RuleSetFile: Equatable {
    let name: String
    let path: String
}

struct CheckOptions: Equatable {
    var rulesPath: String
    var ruleSets: [RuleSetFile] = []
}

struct ExplainOptions: Equatable {
    var rulesPath: String
    var ruleSets: [RuleSetFile] = []
    var domain: String?
    var targetIP: String?
    var targetPort: UInt16?
    var sourceIP: String?
    var sourcePort: UInt16?
    var processName: String?
    var processPath: String?
    var network: NetworkProtocol?
    var dscp: UInt8?
    var country: String?
}

enum ArgumentParser {
    static func parse(_ arguments: [String]) throws(UsageError) -> Command {
        guard let subcommand = arguments.first else { return .help }
        let rest = Array(arguments.dropFirst())
        switch subcommand {
        case "help", "-h", "--help":
            return .help
        case "check":
            return .check(try parseCheck(rest))
        case "explain":
            return .explain(try parseExplain(rest))
        default:
            throw UsageError("未知子命令：\(subcommand)")
        }
    }

    private static func parseCheck(_ arguments: [String]) throws(UsageError) -> CheckOptions {
        let split = try splitOptions(arguments)
        guard split.positional.count == 1 else {
            throw UsageError("check 需要且只能指定一个规则文件")
        }
        var options = CheckOptions(rulesPath: split.positional[0])
        for (flag, value) in split.options {
            switch flag {
            case "--rule-set":
                options.ruleSets.append(try parseRuleSet(value))
            default:
                throw UsageError("check 不支持选项：\(flag)")
            }
        }
        return options
    }

    private static func parseExplain(_ arguments: [String]) throws(UsageError) -> ExplainOptions {
        let split = try splitOptions(arguments)
        guard split.positional.count == 1 else {
            throw UsageError("explain 需要且只能指定一个规则文件")
        }
        var options = ExplainOptions(rulesPath: split.positional[0])
        for (flag, value) in split.options {
            switch flag {
            case "--rule-set": options.ruleSets.append(try parseRuleSet(value))
            case "--domain": options.domain = value
            case "--ip": options.targetIP = try parseAddress(value, flag: flag)
            case "--port": options.targetPort = try parsePort(value, flag: flag)
            case "--src-ip": options.sourceIP = try parseAddress(value, flag: flag)
            case "--src-port": options.sourcePort = try parsePort(value, flag: flag)
            case "--process-name": options.processName = value
            case "--process-path": options.processPath = value
            case "--network": options.network = try parseNetwork(value)
            case "--dscp": options.dscp = try parseDSCP(value)
            case "--country": options.country = try parseCountry(value)
            default: throw UsageError("explain 不支持选项：\(flag)")
            }
        }
        return options
    }

    private static func splitOptions(
        _ arguments: [String]
    ) throws(UsageError) -> (positional: [String], options: [(flag: String, value: String)]) {
        var positional: [String] = []
        var options: [(flag: String, value: String)] = []
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if argument.hasPrefix("--") {
                guard index + 1 < arguments.count else {
                    throw UsageError("选项 \(argument) 缺少参数")
                }
                options.append((flag: argument, value: arguments[index + 1]))
                index += 2
            } else {
                positional.append(argument)
                index += 1
            }
        }
        return (positional, options)
    }

    private static func parseRuleSet(_ value: String) throws(UsageError) -> RuleSetFile {
        guard let separator = value.firstIndex(of: "="),
              separator != value.startIndex,
              value.index(after: separator) != value.endIndex
        else {
            throw UsageError("--rule-set 格式应为 名称=路径：\(value)")
        }
        return RuleSetFile(
            name: String(value[..<separator]),
            path: String(value[value.index(after: separator)...])
        )
    }

    private static func parseAddress(_ value: String, flag: String) throws(UsageError) -> String {
        guard parseIPAddress(value) != nil else {
            throw UsageError("\(flag) 不是合法的 IP 地址：\(value)")
        }
        return value
    }

    private static func parsePort(_ value: String, flag: String) throws(UsageError) -> UInt16 {
        guard let port = UInt16(value) else {
            throw UsageError("\(flag) 不是合法端口（0-65535）：\(value)")
        }
        return port
    }

    private static func parseNetwork(_ value: String) throws(UsageError) -> NetworkProtocol {
        switch value.lowercased() {
        case "tcp": return .tcp
        case "udp": return .udp
        default: throw UsageError("--network 只能是 tcp 或 udp：\(value)")
        }
    }

    private static func parseDSCP(_ value: String) throws(UsageError) -> UInt8 {
        guard let dscp = UInt8(value), dscp < 64 else {
            throw UsageError("--dscp 必须是 0-63 之间的整数：\(value)")
        }
        return dscp
    }

    private static func parseCountry(_ value: String) throws(UsageError) -> String {
        guard value.count == 2, value.allSatisfy({ $0.isASCII && $0.isLetter }) else {
            throw UsageError("--country 必须是两位字母国家码，例如 US：\(value)")
        }
        return value
    }
}
