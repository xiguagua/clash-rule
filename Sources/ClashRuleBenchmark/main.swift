import Foundation
import ClashRuleCore

// MARK: - CLI Parsing & DTOs

struct BenchQuery: Decodable {
    let name: String
    let description: String
    let domain: String?
    let target_ip: String?
    let target_port: UInt16?
    let source_ip: String?
    let source_port: UInt16?
    let process_name: String?
    let process_path: String?
    let network: String?
    let dscp: UInt8?
    let geoip: String?
    let expect_hit: Bool
}

struct QueryResult: Encodable {
    let name: String
    let description: String
    let iters: Int
    let total_ms: Double
    let ns_per_op: Double
    let matched: Bool
    let policy: String
}

struct BenchmarkReport: Encodable {
    let engine: String
    let rule_count: Int
    let rule_file: String
    let parse_time_ms: Double
    let parse_runs: Int
    let snapshot_size_mb: Double
    let query_results: [QueryResult]
    let mixed_ns_per_op: Double
    let mixed_ops_per_s: Double
}

private func parseIP(_ str: String) -> UInt128? {
    var sin = sockaddr_in()
    if inet_pton(AF_INET, str, &sin.sin_addr) == 1 {
        let v = UInt32(bigEndian: sin.sin_addr.s_addr)
        return UInt128(v)
    }
    var sin6 = sockaddr_in6()
    if inet_pton(AF_INET6, str, &sin6.sin6_addr) == 1 {
        let b = withUnsafeBytes(of: &sin6.sin6_addr) { Array($0) }
        var v: UInt128 = 0
        for byte in b {
            v = (v << 8) | UInt128(byte)
        }
        return v
    }
    return nil
}

private func parseCountryCode(_ str: String) -> UInt32 {
    guard str.count >= 2 else { return 0 }
    var code: UInt32 = 0
    for b in str.utf8 {
        let upper: UInt8 = (b >= UInt8(ascii: "a") && b <= UInt8(ascii: "z")) ? (b - 32) : b
        code = (code << 8) | UInt32(upper)
    }
    return code
}

func main() throws {
    var rulePath = "Tools/benchmark/data/bench_100k.rules"
    var workloadPath = "Tools/benchmark/data/workload.json"
    var iters = 50_000
    var jsonOutput = false

    let args = CommandLine.arguments
    var i = 1
    while i < args.count {
        switch args[i] {
        case "--rules":
            if i + 1 < args.count { rulePath = args[i + 1]; i += 1 }
        case "--workload":
            if i + 1 < args.count { workloadPath = args[i + 1]; i += 1 }
        case "--iters":
            if i + 1 < args.count, let v = Int(args[i + 1]) { iters = v; i += 1 }
        case "--json":
            jsonOutput = true
        default:
            break
        }
        i += 1
    }

    let ruleData = try Data(contentsOf: URL(fileURLWithPath: rulePath))
    let workloadData = try Data(contentsOf: URL(fileURLWithPath: workloadPath))
    let queries = try JSONDecoder().decode([BenchQuery].self, from: workloadData)

    // 1. Measure Parse / Compile Time
    let clock = ContinuousClock()
    let parseRuns = 5
    var parseDurations: [Duration] = []
    var compiledSnapshot: CompiledRules?

    // Warmup parse
    try ruleData.withUnsafeBytes { raw in
        _ = try RuleCompiler.compile(raw)
    }

    // Timed parse runs
    for _ in 0..<parseRuns {
        let start = clock.now
        let compiled = try ruleData.withUnsafeBytes { raw in
            try RuleCompiler.compile(raw)
        }
        let elapsed = clock.now - start
        parseDurations.append(elapsed)
        compiledSnapshot = compiled
    }

    guard let snapshot = compiledSnapshot else {
        fatalError("Compilation failed")
    }

    let totalParseNs = parseDurations.reduce(0) { $0 + Double($1.components.attoseconds) / 1e9 }
    let meanParseMs = (totalParseNs / Double(parseRuns)) / 1e6

    // Calculate in-memory snapshot size:
    let snapshotBytes = snapshot.approximateMemoryBytes
    let snapshotMB = Double(snapshotBytes) / (1024.0 * 1024.0)

    let matcher = Matcher(snapshot)

    // 2. Prepare Match Contexts for each query
    struct PreparedContext {
        let name: String
        let description: String
        let domainBytes: [UInt8]
        let processBytes: [UInt8]
        let targetAddr: UInt128?
        let targetPort: UInt16
        let sourceAddr: UInt128?
        let sourcePort: UInt16
        let netProto: NetworkProtocol?
        let dscp: UInt8?
        let countryCode: UInt32
    }

    let prepared = queries.map { q in
        PreparedContext(
            name: q.name,
            description: q.description,
            domainBytes: [UInt8]((q.domain ?? "").utf8),
            processBytes: [UInt8]((q.process_name ?? "").utf8),
            targetAddr: q.target_ip.flatMap(parseIP),
            targetPort: q.target_port ?? 0,
            sourceAddr: q.source_ip.flatMap(parseIP),
            sourcePort: q.source_port ?? 0,
            netProto: q.network?.lowercased() == "tcp" ? .tcp : (q.network?.lowercased() == "udp" ? .udp : nil),
            dscp: q.dscp,
            countryCode: q.geoip.map(parseCountryCode) ?? 0
        )
    }

    // 3. Measure Match Latency for Each Query
    var queryResults: [QueryResult] = []
    let emptyBytes = [UInt8]()

    for prep in prepared {
        // Warmup
        for _ in 0..<5000 {
            prep.domainBytes.withUnsafeBufferPointer { dBuf in
                prep.processBytes.withUnsafeBufferPointer { pBuf in
                    emptyBytes.withUnsafeBufferPointer { eBuf in
                        let ctx = MatchContext(
                            domain: dBuf,
                            targetAddress: prep.targetAddr,
                            targetPort: prep.targetPort,
                            sourceAddress: prep.sourceAddr,
                            sourcePort: prep.sourcePort,
                            processName: pBuf,
                            processPath: eBuf,
                            network: prep.netProto,
                            dscp: prep.dscp,
                            countryCode: prep.countryCode
                        )
                        _ = matcher.match(context: ctx)
                    }
                }
            }
        }

        // Timed loop
        var lastMatched = false
        var lastPolicy = ""

        let matchStart = clock.now
        prep.domainBytes.withUnsafeBufferPointer { dBuf in
            prep.processBytes.withUnsafeBufferPointer { pBuf in
                emptyBytes.withUnsafeBufferPointer { eBuf in
                    let ctx = MatchContext(
                        domain: dBuf,
                        targetAddress: prep.targetAddr,
                        targetPort: prep.targetPort,
                        sourceAddress: prep.sourceAddr,
                        sourcePort: prep.sourcePort,
                        processName: pBuf,
                        processPath: eBuf,
                        network: prep.netProto,
                        dscp: prep.dscp,
                        countryCode: prep.countryCode
                    )
                    var lastResult: MatchResult? = nil
                    for _ in 0..<iters {
                        if let res = matcher.match(context: ctx) {
                            lastResult = res
                        }
                    }
                    if let res = lastResult {
                        lastMatched = true
                        lastPolicy = snapshot.policyName(res.policyID)
                    } else {
                        lastMatched = false
                    }
                }
            }
        }
        let matchElapsed = clock.now - matchStart
        let elapsedNs = Double(matchElapsed.components.attoseconds) / 1e9
        let nsPerOp = elapsedNs / Double(iters)

        queryResults.append(QueryResult(
            name: prep.name,
            description: prep.description,
            iters: iters,
            total_ms: elapsedNs / 1e6,
            ns_per_op: nsPerOp,
            matched: lastMatched,
            policy: lastPolicy
        ))
    }

    // 4. Mixed Traffic Workload (Round-Robin)
    let mixedIters = 100_000
    let mixedStart = clock.now
    for k in 0..<mixedIters {
        let prep = prepared[k % prepared.count]
        prep.domainBytes.withUnsafeBufferPointer { dBuf in
            prep.processBytes.withUnsafeBufferPointer { pBuf in
                emptyBytes.withUnsafeBufferPointer { eBuf in
                    let ctx = MatchContext(
                        domain: dBuf,
                        targetAddress: prep.targetAddr,
                        targetPort: prep.targetPort,
                        sourceAddress: prep.sourceAddr,
                        sourcePort: prep.sourcePort,
                        processName: pBuf,
                        processPath: eBuf,
                        network: prep.netProto,
                        dscp: prep.dscp,
                        countryCode: prep.countryCode
                    )
                    _ = matcher.match(context: ctx)
                }
            }
        }
    }
    let mixedElapsed = clock.now - mixedStart
    let mixedElapsedNs = Double(mixedElapsed.components.attoseconds) / 1e9
    let mixedNsPerOp = mixedElapsedNs / Double(mixedIters)
    let mixedOpsPerS = Double(mixedIters) / (mixedElapsedNs / 1e9)

    let report = BenchmarkReport(
        engine: "ClashRuleCore (Swift 6.4 Zero-Alloc)",
        rule_count: snapshot.ruleCount,
        rule_file: rulePath,
        parse_time_ms: meanParseMs,
        parse_runs: parseRuns,
        snapshot_size_mb: snapshotMB,
        query_results: queryResults,
        mixed_ns_per_op: mixedNsPerOp,
        mixed_ops_per_s: mixedOpsPerS
    )

    if jsonOutput {
        let data = try JSONEncoder().encode(report)
        print(String(decoding: data, as: UTF8.self))
        return
    }

    print("================================================================================")
    print("  Engine: \(report.engine)")
    print("  Rules Loaded: \(report.rule_count) (from \(report.rule_file))")
    print(String(format: "  Parse/Compile Time: %.2f ms (avg of %d runs)", report.parse_time_ms, report.parse_runs))
    print(String(format: "  Snapshot RAM Size:  %.2f MB", report.snapshot_size_mb))
    print(String(format: "  Mixed Throughput:   %.0f ops/sec (%.1f ns/op)", report.mixed_ops_per_s, report.mixed_ns_per_op))
    func pad(_ s: String, _ w: Int) -> String {
        if s.count >= w { return s }
        return s + String(repeating: " ", count: w - s.count)
    }
    func padLeft(_ s: String, _ w: Int) -> String {
        if s.count >= w { return s }
        return String(repeating: " ", count: w - s.count) + s
    }

    print("--------------------------------------------------------------------------------")
    print("  \(pad("Query ID", 18)) | \(pad("Description", 36)) | \(padLeft("Latency", 10)) | Policy")
    print("--------------------------------------------------------------------------------")
    for qr in report.query_results {
        let nsStr = String(format: "%.1f ns", qr.ns_per_op)
        print("  \(pad(qr.name, 18)) | \(pad(qr.description, 36)) | \(padLeft(nsStr, 10)) | \(qr.policy)")
    }
    print("================================================================================")
}

try main()
