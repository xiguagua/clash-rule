package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func generateRules(total int, outPath string) error {
	file, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer file.Close()
	w := bufio.NewWriter(file)

	// Percentages:
	// DOMAIN-SUFFIX: 45%
	// DOMAIN: 20%
	// IP-CIDR (v4): 15%
	// IP-CIDR6 (v6): 5%
	// DOMAIN-KEYWORD: 5%
	// PORT / DST-PORT: 3%
	// PROCESS: 3%
	// LOGIC (AND/OR/NOT): 2%
	// GEOIP/NETWORK/DSCP: 2%
	// MATCH: 1 line

	numSuffix := total * 45 / 100
	numExact := total * 20 / 100
	numIPv4 := total * 15 / 100
	numIPv6 := total * 5 / 100
	numKeyword := total * 5 / 100
	numPort := total * 3 / 100
	numProcess := total * 3 / 100
	numLogic := total * 2 / 100
	numOther := total * 2 / 100

	// Benchmark targets to explicitly match queries:
	w.WriteString("# Key benchmark target rules (placed at strategic positions)\n")
	w.WriteString("DOMAIN,exact-target.benchmark.test,DIRECT\n")
	w.WriteString("DOMAIN-SUFFIX,suffix-target.benchmark.test,PROXY\n")
	w.WriteString("DOMAIN-KEYWORD,keywordtarget,REJECT\n")
	w.WriteString("IP-CIDR,198.51.100.0/24,LAN-DIRECT,no-resolve\n")
	w.WriteString("IP-CIDR6,2001:db8:beef::/48,IPV6-DIRECT,no-resolve\n")
	w.WriteString("DST-PORT,8080,HTTP-PROXY\n")
	w.WriteString("PROCESS-NAME,curl-bench,CLI-PROXY\n")
	w.WriteString("AND,((NETWORK,tcp),(DST-PORT,443),(DOMAIN-SUFFIX,secure.bank)),BANKING-DIRECT\n")
	w.WriteString("GEOIP,CN,CN-DIRECT\n")

	written := 9

	// 1. DOMAIN-SUFFIX
	for i := 0; i < numSuffix; i++ {
		w.WriteString(fmt.Sprintf("DOMAIN-SUFFIX,sub%d.domain%d.org,PROXY\n", i%100, i))
		written++
	}

	// 2. DOMAIN (exact)
	for i := 0; i < numExact; i++ {
		w.WriteString(fmt.Sprintf("DOMAIN,service%d.host%d.net,DIRECT\n", i%100, i))
		written++
	}

	// 3. IP-CIDR (IPv4)
	for i := 0; i < numIPv4; i++ {
		b2 := (i >> 8) & 0xFF
		b3 := i & 0xFF
		w.WriteString(fmt.Sprintf("IP-CIDR,10.%d.%d.0/24,LAN,no-resolve\n", b2, b3))
		written++
	}

	// 4. IP-CIDR6 (IPv6)
	for i := 0; i < numIPv6; i++ {
		w.WriteString(fmt.Sprintf("IP-CIDR6,2400:cb00:%x::/48,IPV6-PROXY,no-resolve\n", i))
		written++
	}

	// 5. DOMAIN-KEYWORD
	for i := 0; i < numKeyword; i++ {
		w.WriteString(fmt.Sprintf("DOMAIN-KEYWORD,kw%dterm,KEYWORD-BLOCK\n", i))
		written++
	}

	// 6. PORT
	for i := 0; i < numPort; i++ {
		port := 10000 + (i % 50000)
		w.WriteString(fmt.Sprintf("DST-PORT,%d,PORT-POLICY\n", port))
		written++
	}

	// 7. PROCESS
	for i := 0; i < numProcess; i++ {
		w.WriteString(fmt.Sprintf("PROCESS-NAME,proc_%d.bin,PROCESS-POLICY\n", i))
		written++
	}

	// 8. LOGIC (AND/OR/NOT)
	for i := 0; i < numLogic; i++ {
		switch i % 3 {
		case 0:
			w.WriteString(fmt.Sprintf("AND,((NETWORK,tcp),(DOMAIN-SUFFIX,logic%d.com)),LOGIC-AND\n", i))
		case 1:
			w.WriteString(fmt.Sprintf("OR,((DOMAIN,or1_%d.net),(DOMAIN,or2_%d.net)),LOGIC-OR\n", i, i))
		case 2:
			w.WriteString(fmt.Sprintf("NOT,((DOMAIN-SUFFIX,exclude%d.org)),LOGIC-NOT\n", i))
		}
		written++
	}

	// 9. Other (GEOIP, DSCP, NETWORK)
	for i := 0; i < numOther; i++ {
		switch i % 3 {
		case 0:
			w.WriteString(fmt.Sprintf("GEOIP,US,US-POLICY\n"))
		case 1:
			w.WriteString(fmt.Sprintf("NETWORK,udp,UDP-POLICY\n"))
		case 2:
			w.WriteString(fmt.Sprintf("DSCP,%d,DSCP-POLICY\n", (i%63)+1))
		}
		written++
	}

	// Finally, MATCH fallback
	w.WriteString("MATCH,FINAL-FALLBACK\n")
	written++

	w.Flush()
	fmt.Printf("Generated %s: %d total rules\n", outPath, written)
	return nil
}

func main() {
	outDir := "Tools/benchmark/data"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	os.MkdirAll(outDir, 0755)

	err := generateRules(10000, filepath.Join(outDir, "bench_10k.rules"))
	if err != nil {
		panic(err)
	}

	err = generateRules(100000, filepath.Join(outDir, "bench_100k.rules"))
	if err != nil {
		panic(err)
	}

	// Queries that evaluate specific matcher subsystems
	workload := []BenchQuery{
		{
			Name:        "exact_hit",
			Description: "Exact Domain Hash Lookup",
			Domain:      "exact-target.benchmark.test",
			ExpectHit:   true,
		},
		{
			Name:        "suffix_hit",
			Description: "Deep Suffix Trie Traversal (3 labels)",
			Domain:      "deep.api.suffix-target.benchmark.test",
			ExpectHit:   true,
		},
		{
			Name:        "keyword_hit",
			Description: "Domain Keyword Scan",
			Domain:      "prefix-keywordtarget-suffix.com",
			ExpectHit:   true,
		},
		{
			Name:        "ipv4_cidr_hit",
			Description: "IPv4 Radix Trie Prefix Match (/24)",
			TargetIP:    "198.51.100.42",
			ExpectHit:   true,
		},
		{
			Name:        "ipv6_cidr_hit",
			Description: "IPv6 Radix Trie Prefix Match (/48)",
			TargetIP:    "2001:db8:beef:1234::1",
			ExpectHit:   true,
		},
		{
			Name:        "port_hit",
			Description: "Destination Port Lookup",
			TargetPort:  8080,
			ExpectHit:   true,
		},
		{
			Name:        "process_hit",
			Description: "Process Name Lookup",
			ProcessName: "curl-bench",
			ExpectHit:   true,
		},
		{
			Name:        "logic_and_hit",
			Description: "Composite Logic AND Rule Evaluation",
			Domain:      "my.secure.bank",
			Network:     "tcp",
			TargetPort:  443,
			ExpectHit:   true,
		},
		{
			Name:        "geoip_hit",
			Description: "GeoIP Country Index Match",
			TargetIP:    "114.114.114.114",
			GeoIP:       "CN",
			ExpectHit:   true,
		},
		{
			Name:        "fallback_miss",
			Description: "Full Category Miss -> MATCH Fallback",
			Domain:      "unmatched-random-domain-xyz123.com",
			TargetIP:    "192.0.2.1",
			TargetPort:  9999,
			Network:     "udp",
			ProcessName: "unknown-proc",
			ExpectHit:   false,
		},
	}

	workloadBytes, err := json.MarshalIndent(workload, "", "  ")
	if err != nil {
		panic(err)
	}

	workloadPath := filepath.Join(outDir, "workload.json")
	err = os.WriteFile(workloadPath, workloadBytes, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated workload queries: %s (%d test queries)\n", workloadPath, len(workload))
}
