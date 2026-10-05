package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
)

type BenchQuery struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Domain      string `json:"domain,omitempty"`
	TargetIP    string `json:"target_ip,omitempty"`
	TargetPort  uint16 `json:"target_port,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
	SourcePort  uint16 `json:"source_port,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
	Network     string `json:"network,omitempty"`
	DSCP        uint8  `json:"dscp,omitempty"`
	GeoIP       string `json:"geoip,omitempty"`
	ExpectHit   bool   `json:"expect_hit"`
}

type QueryResult struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Iters       int     `json:"iters"`
	TotalMs     float64 `json:"total_ms"`
	NsPerOp     float64 `json:"ns_per_op"`
	Matched     bool    `json:"matched"`
	Policy      string  `json:"policy"`
}

type BenchmarkReport struct {
	Engine        string        `json:"engine"`
	RuleCount     int           `json:"rule_count"`
	RuleFile      string        `json:"rule_file"`
	ParseTimeMs   float64       `json:"parse_time_ms"`
	ParseRuns     int           `json:"parse_runs"`
	AllocBytesMB  float64       `json:"alloc_bytes_mb"`
	QueryResults  []QueryResult `json:"query_results"`
	MixedNsPerOp  float64       `json:"mixed_ns_per_op"`
	MixedOpsPerS  float64       `json:"mixed_ops_per_s"`
}

func splitRuleParts(s string) []string {
	// 与 golden-oracle 一致：括号内的逗号不切分（AND/OR/NOT 逻辑规则）
	var parts []string
	var cur strings.Builder
	depth := 0
	for _, c := range s {
		switch c {
		case '(':
			depth++
			cur.WriteRune(c)
		case ')':
			if depth > 0 {
				depth--
			}
			cur.WriteRune(c)
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(cur.String()))
				cur.Reset()
			} else {
				cur.WriteRune(c)
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, strings.TrimSpace(cur.String()))
	}
	return parts
}

func parseRuleLine(line string) (constant.Rule, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "- ") {
		trimmed = strings.TrimSpace(trimmed[2:])
	}
	parts := splitRuleParts(trimmed)
	if len(parts) == 0 {
		return nil, nil
	}
	tp := strings.ToUpper(parts[0])
	if tp == "MATCH" {
		if len(parts) < 2 {
			return nil, fmt.Errorf("MATCH requires policy")
		}
		return rules.ParseRule("MATCH", "", parts[1], nil, nil)
	}
	if len(parts) < 3 {
		return nil, fmt.Errorf("line '%s' has fewer than 3 segments", trimmed)
	}
	payload := parts[1]
	target := parts[2]
	var params []string
	if len(parts) > 3 {
		params = parts[3:]
	}
	switch tp {
	case "PORT":
		tp = "DST-PORT"
	case "SRC-IP-CIDR6":
		tp = "SRC-IP-CIDR"
	}
	return rules.ParseRule(tp, payload, target, params, nil)
}

func buildMetadata(req BenchQuery) (*constant.Metadata, error) {
	md := &constant.Metadata{
		Host:        strings.ToLower(req.Domain),
		DstPort:     req.TargetPort,
		SrcPort:     req.SourcePort,
		Process:     req.ProcessName,
		ProcessPath: req.ProcessPath,
	}
	if req.TargetIP != "" {
		ip, err := netip.ParseAddr(req.TargetIP)
		if err != nil {
			return nil, err
		}
		md.DstIP = ip
	}
	if req.SourceIP != "" {
		ip, err := netip.ParseAddr(req.SourceIP)
		if err != nil {
			return nil, err
		}
		md.SrcIP = ip
	}
	switch strings.ToLower(req.Network) {
	case "tcp":
		md.NetWork = constant.TCP
	case "udp":
		md.NetWork = constant.UDP
	}
	if req.DSCP > 0 {
		md.DSCP = req.DSCP
	}
	if req.GeoIP != "" {
		md.DstGeoIP = []string{strings.ToLower(req.GeoIP), strings.ToUpper(req.GeoIP)}
	}
	return md, nil
}

func main() {
	ruleFile := flag.String("rules", "Tools/benchmark/data/bench_100k.rules", "Path to rules file")
	workloadFile := flag.String("workload", "Tools/benchmark/data/workload.json", "Path to workload queries")
	matchIters := flag.Int("iters", 50000, "Match iterations per query")
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	flag.Parse()

	content, err := os.ReadFile(*ruleFile)
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(content), "\n")

	workloadBytes, err := os.ReadFile(*workloadFile)
	if err != nil {
		panic(err)
	}
	var queries []BenchQuery
	if err := json.Unmarshal(workloadBytes, &queries); err != nil {
		panic(err)
	}

	// 1. Measure Parse / Compile Time
	var parseTimes []time.Duration
	var parsedRules []constant.Rule
	var allocatedBytes uint64

	// Warmup parse
	for _, l := range lines {
		r, err := parseRuleLine(l)
		if err != nil {
			panic(fmt.Sprintf("parse rule line %q: %v", l, err))
		}
		if r != nil {
			parsedRules = append(parsedRules, r)
		}
	}

	// Timed parses
	parseRuns := 3
	for run := 0; run < parseRuns; run++ {
		runtime.GC()
		var m1, m2 runtime.MemStats
		runtime.ReadMemStats(&m1)

		start := time.Now()
		var curRules []constant.Rule
		for _, l := range lines {
			r, err := parseRuleLine(l)
			if err != nil {
				panic(fmt.Sprintf("parse rule line %q: %v", l, err))
			}
			if r != nil {
				curRules = append(curRules, r)
			}
		}
		elapsed := time.Since(start)
		runtime.ReadMemStats(&m2)
		parseTimes = append(parseTimes, elapsed)
		if run == 0 {
			if m2.Alloc > m1.Alloc {
				allocatedBytes = m2.Alloc - m1.Alloc
			}
			parsedRules = curRules
		}
	}

	var totalParseNs int64
	for _, t := range parseTimes {
		totalParseNs += t.Nanoseconds()
	}
	meanParseMs := float64(totalParseNs) / float64(parseRuns) / 1e6
	allocMB := float64(allocatedBytes) / (1024 * 1024)

	// 2. Measure Match Latency for Each Query
	var queryResults []QueryResult
	for _, q := range queries {
		md, err := buildMetadata(q)
		if err != nil {
			panic(err)
		}

		// Warmup
		for i := 0; i < 5000; i++ {
			for _, r := range parsedRules {
				if m, _ := r.Match(md); m {
					break
				}
			}
		}

		// Timed run
		iters := *matchIters
		var lastMatched bool
		var lastPolicy string

		start := time.Now()
		for i := 0; i < iters; i++ {
			for _, r := range parsedRules {
				if m, a := r.Match(md); m {
					lastMatched = true
					if a != "" {
						lastPolicy = a
					} else {
						lastPolicy = r.Adapter()
					}
					break
				}
			}
		}
		elapsed := time.Since(start)
		nsPerOp := float64(elapsed.Nanoseconds()) / float64(iters)

		queryResults = append(queryResults, QueryResult{
			Name:        q.Name,
			Description: q.Description,
			Iters:       iters,
			TotalMs:     float64(elapsed.Milliseconds()),
			NsPerOp:     nsPerOp,
			Matched:     lastMatched,
			Policy:      lastPolicy,
		})
	}

	// 3. Mixed Workload Throughput (Round-Robin across all 10 queries)
	var metadatas []*constant.Metadata
	for _, q := range queries {
		md, _ := buildMetadata(q)
		metadatas = append(metadatas, md)
	}

	mixedIters := 100000
	startMixed := time.Now()
	for i := 0; i < mixedIters; i++ {
		md := metadatas[i%len(metadatas)]
		for _, r := range parsedRules {
			if m, _ := r.Match(md); m {
				break
			}
		}
	}
	mixedElapsed := time.Since(startMixed)
	mixedNsPerOp := float64(mixedElapsed.Nanoseconds()) / float64(mixedIters)
	mixedOpsPerS := float64(mixedIters) / mixedElapsed.Seconds()

	report := BenchmarkReport{
		Engine:        "mihomo (Go v1.19.2)",
		RuleCount:     len(parsedRules),
		RuleFile:      *ruleFile,
		ParseTimeMs:   meanParseMs,
		ParseRuns:     parseRuns,
		AllocBytesMB:  allocMB,
		QueryResults:  queryResults,
		MixedNsPerOp:  mixedNsPerOp,
		MixedOpsPerS:  mixedOpsPerS,
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return
	}

	fmt.Printf("================================================================================\n")
	fmt.Printf("  Engine: %s\n", report.Engine)
	fmt.Printf("  Rules Loaded: %d (from %s)\n", report.RuleCount, report.RuleFile)
	fmt.Printf("  Parse/Compile Time: %.2f ms (avg of %d runs)\n", report.ParseTimeMs, report.ParseRuns)
	fmt.Printf("  Memory Allocated:   %.2f MB\n", report.AllocBytesMB)
	fmt.Printf("  Mixed Throughput:   %.0f ops/sec (%.1f ns/op)\n", report.MixedOpsPerS, report.MixedNsPerOp)
	fmt.Printf("--------------------------------------------------------------------------------\n")
	fmt.Printf("  %-18s | %-32s | %-12s | %s\n", "Query ID", "Description", "Latency (ns)", "Policy")
	fmt.Printf("--------------------------------------------------------------------------------\n")
	for _, qr := range report.QueryResults {
		fmt.Printf("  %-18s | %-32s | %8.1f ns | %s\n", qr.Name, qr.Description, qr.NsPerOp, qr.Policy)
	}
	fmt.Printf("================================================================================\n")
}
