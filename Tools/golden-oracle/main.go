package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
)

// TestCase defines a test query and the oracle's expected outcome
type TestCase struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	RuleSet     string            `json:"rule_set"`
	Request     RequestDTO        `json:"request"`
	Expected    ExpectedResultDTO `json:"expected"`
}

type RequestDTO struct {
	Domain      string `json:"domain,omitempty"`
	TargetIP    string `json:"target_ip,omitempty"`
	TargetPort  uint16 `json:"target_port,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
	SourcePort  uint16 `json:"source_port,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
	Network     string `json:"network,omitempty"`
	DSCP        *uint8 `json:"dscp,omitempty"`
	GeoIP       string `json:"geoip,omitempty"`
}

type ExpectedResultDTO struct {
	Matched  bool   `json:"matched"`
	Policy   string `json:"policy"`
	RuleType string `json:"rule_type,omitempty"`
}

func parseRuleLine(line string) (constant.Rule, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "- ") {
		trimmed = strings.TrimSpace(trimmed[2:])
	}
	// Split by commas respecting parentheses
	var parts []string
	var cur strings.Builder
	depth := 0
	for _, c := range trimmed {
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

	// Normalise for mihomo:
	switch tp {
	case "PORT":
		tp = "DST-PORT"
	case "SRC-IP-CIDR6":
		tp = "SRC-IP-CIDR"
	}

	return rules.ParseRule(tp, payload, target, params, nil)
}

func buildMetadata(req RequestDTO) (*constant.Metadata, error) {
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
			return nil, fmt.Errorf("invalid target_ip %s: %w", req.TargetIP, err)
		}
		md.DstIP = ip
	}

	if req.SourceIP != "" {
		ip, err := netip.ParseAddr(req.SourceIP)
		if err != nil {
			return nil, fmt.Errorf("invalid source_ip %s: %w", req.SourceIP, err)
		}
		md.SrcIP = ip
	}

	switch strings.ToLower(req.Network) {
	case "tcp":
		md.NetWork = constant.TCP
	case "udp":
		md.NetWork = constant.UDP
	}

	if req.DSCP != nil {
		md.DSCP = *req.DSCP
	}

	if req.GeoIP != "" {
		md.DstGeoIP = []string{strings.ToLower(req.GeoIP), strings.ToUpper(req.GeoIP)}
	}

	return md, nil
}

func evaluateRules(ruleList []constant.Rule, req RequestDTO) (ExpectedResultDTO, error) {
	md, err := buildMetadata(req)
	if err != nil {
		return ExpectedResultDTO{}, err
	}

	for _, r := range ruleList {
		if matched, adapter := r.Match(md); matched {
			if adapter == "" {
				adapter = r.Adapter()
			}
			return ExpectedResultDTO{
				Matched:  true,
				Policy:   adapter,
				RuleType: r.RuleType().String(),
			}, nil
		}
	}

	return ExpectedResultDTO{
		Matched: false,
		Policy:  "",
	}, nil
}

func ptrUInt8(v uint8) *uint8 {
	return &v
}

func findFixturesDir() string {
	candidates := []string{
		"Tests/GoldenTests/Fixtures",
		"../../Tests/GoldenTests/Fixtures",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return "Tests/GoldenTests/Fixtures"
}

func main() {
	fixturesDir := findFixturesDir()
	oracleRulesPath := filepath.Join(fixturesDir, "oracle/synthetic_oracle.rules")

	syntheticRulesText := `# Comprehensive Synthetic Oracle Rule Set
# Tests ordering, edge cases, and all rule types for mihomo parity

DOMAIN,exact.apple.com,APPLE-DIRECT
DOMAIN-SUFFIX,google.com,GOOGLE-PROXY
DOMAIN-KEYWORD,facebook,FB-PROXY
DOMAIN-SUFFIX,sub.service.internal,INTERNAL-DIRECT

IP-CIDR,192.168.1.0/24,PRIVATE-LAN,no-resolve
IP-CIDR,10.0.0.0/8,CORP-VPN,no-resolve
IP-CIDR,10.1.2.0/24,OVERRIDE-SUBNET,no-resolve
IP-CIDR,1.1.1.1/32,CLOUDFLARE-DNS,no-resolve
IP-CIDR6,2001:db8::/32,IPV6-TEST,no-resolve
IP-CIDR6,2001:db8:85a3::1/128,IPV6-HOST,no-resolve

SRC-IP-CIDR,172.16.0.0/16,SRC-MGMT,no-resolve
SRC-IP-CIDR,fd00::/8,SRC-ULA,no-resolve

DST-PORT,80,HTTP-TRAFFIC
DST-PORT,8080,HTTP-PROXY
SRC-PORT,68,DHCP-BOOTP
DST-PORT,22,SSH-DIRECT

PROCESS-NAME,curl,CLI-PROXY
PROCESS-PATH,/usr/local/bin/wget,WGET-POLICY

NETWORK,udp,UDP-MEDIA
DSCP,46,VOIP-EXPEDITED

GEOIP,CN,DIRECT
GEOIP,JP,JP-PROXY

AND,((NETWORK,tcp),(DST-PORT,443),(DOMAIN-SUFFIX,banking.com)),SECURE-BANKING
OR,((DOMAIN,service1.local),(DOMAIN,service2.local)),LOCAL-SERVICE
NOT,((DOMAIN-SUFFIX,blocked.org)),ALLOWED-CONTENT

MATCH,FALLBACK-DEFAULT
`

	err := os.WriteFile(oracleRulesPath, []byte(syntheticRulesText), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wrote %s\n", oracleRulesPath)

	// Parse synthetic rules with mihomo
	lines := strings.Split(syntheticRulesText, "\n")
	var parsedSynthetic []constant.Rule
	for idx, line := range lines {
		r, err := parseRuleLine(line)
		if err != nil {
			panic(fmt.Sprintf("Failed parsing synthetic line %d: %s (%v)", idx+1, line, err))
		}
		if r != nil {
			parsedSynthetic = append(parsedSynthetic, r)
		}
	}
	fmt.Printf("Mihomo successfully parsed %d synthetic rules\n", len(parsedSynthetic))

	// Define test cases across all categories and edge behaviors
	testQueries := []struct {
		desc string
		req  RequestDTO
	}{
		// Domain Exact
		{
			desc: "Exact domain matches APPLE-DIRECT",
			req:  RequestDTO{Domain: "exact.apple.com"},
		},
		{
			desc: "Subdomain of exact domain does not match exact rule",
			req:  RequestDTO{Domain: "sub.exact.apple.com"},
		},
		{
			desc: "Exact domain case insensitivity",
			req:  RequestDTO{Domain: "EXACT.APPLE.COM"},
		},

		// Domain Suffix
		{
			desc: "Domain suffix match apex google.com",
			req:  RequestDTO{Domain: "google.com"},
		},
		{
			desc: "Domain suffix match subdomain mail.google.com",
			req:  RequestDTO{Domain: "mail.google.com"},
		},
		{
			desc: "Domain suffix deep subdomain a.b.c.google.com",
			req:  RequestDTO{Domain: "a.b.c.google.com"},
		},
		{
			desc: "Domain suffix boundary check: notgoogle.com should not match google.com",
			req:  RequestDTO{Domain: "notgoogle.com"},
		},

		// Domain Keyword
		{
			desc: "Domain keyword facebook in mid domain",
			req:  RequestDTO{Domain: "my-facebook-feed.org"},
		},
		{
			desc: "Domain keyword case insensitivity",
			req:  RequestDTO{Domain: "Static.FaceBook.Net"},
		},

		// IP CIDR
		{
			desc: "IPv4 CIDR match 192.168.1.50 -> PRIVATE-LAN",
			req:  RequestDTO{TargetIP: "192.168.1.50"},
		},
		{
			desc: "IPv4 CIDR /32 single host match 1.1.1.1 -> CLOUDFLARE-DNS",
			req:  RequestDTO{TargetIP: "1.1.1.1"},
		},
		{
			desc: "IPv4 CIDR file order priority: 10.1.2.5 matches 10.0.0.0/8 before 10.1.2.0/24",
			req:  RequestDTO{TargetIP: "10.1.2.5"},
		},
		{
			desc: "IPv4 CIDR non-matching IP falls through to MATCH",
			req:  RequestDTO{TargetIP: "8.8.8.8"},
		},
		{
			desc: "IPv6 CIDR /32 match 2001:db8:ffff::1 -> IPV6-TEST",
			req:  RequestDTO{TargetIP: "2001:db8:ffff::1"},
		},
		{
			desc: "IPv6 CIDR non-matching host falls through",
			req:  RequestDTO{TargetIP: "2400:cb00::1"},
		},

		// Source IP CIDR
		{
			desc: "Source IP CIDR match 172.16.5.10 -> SRC-MGMT",
			req:  RequestDTO{SourceIP: "172.16.5.10"},
		},
		{
			desc: "Source IPv6 CIDR match fd00::1234 -> SRC-ULA",
			req:  RequestDTO{SourceIP: "fd00::1234"},
		},

		// Ports
		{
			desc: "Destination port 80 -> HTTP-TRAFFIC",
			req:  RequestDTO{TargetPort: 80},
		},
		{
			desc: "Destination port 8080 -> HTTP-PROXY",
			req:  RequestDTO{TargetPort: 8080},
		},
		{
			desc: "Source port 68 -> DHCP-BOOTP",
			req:  RequestDTO{SourcePort: 68},
		},
		{
			desc: "Port 22 -> SSH-DIRECT",
			req:  RequestDTO{TargetPort: 22},
		},

		// Process
		{
			desc: "Process name curl -> CLI-PROXY",
			req:  RequestDTO{ProcessName: "curl"},
		},
		{
			desc: "Process path /usr/local/bin/wget -> WGET-POLICY",
			req:  RequestDTO{ProcessPath: "/usr/local/bin/wget"},
		},

		// Network & DSCP
		{
			desc: "Network udp -> UDP-MEDIA",
			req:  RequestDTO{Network: "udp"},
		},
		{
			desc: "DSCP 46 -> VOIP-EXPEDITED",
			req:  RequestDTO{DSCP: ptrUInt8(46)},
		},

		// GeoIP
		{
			desc: "GeoIP CN -> DIRECT",
			req:  RequestDTO{TargetIP: "223.5.5.5", GeoIP: "CN"},
		},
		{
			desc: "GeoIP JP -> JP-PROXY",
			req:  RequestDTO{TargetIP: "133.1.1.1", GeoIP: "JP"},
		},

		// Logic Rules (AND / OR / NOT)
		{
			desc: "AND rule satisfied: tcp + 443 + banking.com",
			req: RequestDTO{
				Domain:     "my.banking.com",
				Network:    "tcp",
				TargetPort: 443,
			},
		},
		{
			desc: "AND rule partially satisfied (missing port 443) does not match AND rule",
			req: RequestDTO{
				Domain:     "my.banking.com",
				Network:    "tcp",
				TargetPort: 8081,
			},
		},
		{
			desc: "OR rule satisfied by first item service1.local",
			req:  RequestDTO{Domain: "service1.local"},
		},
		{
			desc: "OR rule satisfied by second item service2.local",
			req:  RequestDTO{Domain: "service2.local"},
		},
		{
			desc: "NOT rule satisfied when not blocked.org",
			req:  RequestDTO{Domain: "free-site.org"},
		},

		// Multi-attribute priority arbitration
		{
			desc: "Domain rule beats lower port rule even when port matches",
			req: RequestDTO{
				Domain:     "mail.google.com",
				TargetPort: 80,
			},
		},
		{
			desc: "IP rule beats later process rule",
			req: RequestDTO{
				TargetIP:    "192.168.1.10",
				ProcessName: "curl",
			},
		},
		{
			desc: "Fallback MATCH triggered when nothing else matches",
			req: RequestDTO{
				Domain:     "random-unmatched-domain.xyz",
				TargetIP:   "185.199.108.153",
				TargetPort: 9999,
				Network:    "tcp",
			},
		},
	}

	var testCases []TestCase
	for i, tq := range testQueries {
		res, err := evaluateRules(parsedSynthetic, tq.req)
		if err != nil {
			panic(fmt.Sprintf("Evaluation error on %s: %v", tq.desc, err))
		}
		tc := TestCase{
			ID:          "synthetic_" + strconv.Itoa(i+1),
			Description: tq.desc,
			RuleSet:     "oracle/synthetic_oracle.rules",
			Request:     tq.req,
			Expected:    res,
		}
		testCases = append(testCases, tc)
	}

	// Helper to load and evaluate community rule files with a default policy
	evaluateListFile := func(relPath string, defaultPolicy string, prefix string, queries []struct {
		desc string
		req  RequestDTO
	}) {
		fullPath := filepath.Join(fixturesDir, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			fmt.Printf("Warning: could not read %s: %v\n", fullPath, err)
			return
		}
		var parsed []constant.Rule
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.HasPrefix(trimmed, "- ") {
				trimmed = strings.TrimSpace(trimmed[2:])
			}
			parts := strings.Split(trimmed, ",")
			if len(parts) == 0 {
				continue
			}
			if len(parts) == 2 && defaultPolicy != "" {
				trimmed = trimmed + "," + defaultPolicy
			} else if len(parts) == 3 && strings.TrimSpace(parts[2]) == "no-resolve" && defaultPolicy != "" {
				trimmed = parts[0] + "," + parts[1] + "," + defaultPolicy + ",no-resolve"
			}
			r, err := parseRuleLine(trimmed)
			if err == nil && r != nil {
				parsed = append(parsed, r)
			}
		}
		fmt.Printf("Mihomo parsed %d rules from %s\n", len(parsed), relPath)

		for idx, q := range queries {
			res, err := evaluateRules(parsed, q.req)
			if err != nil {
				panic(err)
			}
			testCases = append(testCases, TestCase{
				ID:          fmt.Sprintf("%s_%d", prefix, idx+1),
				Description: q.desc,
				RuleSet:     relPath,
				Request:     q.req,
				Expected:    res,
			})
		}
	}

	// 1. Blackmatrix7 Telegram
	evaluateListFile("community/blackmatrix7_telegram.list", "PROXY", "telegram", []struct {
		desc string
		req  RequestDTO
	}{
		{desc: "Telegram exact domain api.imem.app", req: RequestDTO{Domain: "api.imem.app"}},
		{desc: "Telegram suffix t.me", req: RequestDTO{Domain: "t.me"}},
		{desc: "Telegram suffix subdomain web.telegram.org", req: RequestDTO{Domain: "web.telegram.org"}},
		{desc: "Telegram keyword nicegram", req: RequestDTO{Domain: "app.nicegram.xyz"}},
		{desc: "Telegram IPv4 CIDR 91.108.4.1", req: RequestDTO{TargetIP: "91.108.4.1"}},
		{desc: "Telegram IPv6 CIDR 2001:67c:4e8::5", req: RequestDTO{TargetIP: "2001:67c:4e8::5"}},
		{desc: "Telegram process name Telegram.exe", req: RequestDTO{ProcessName: "Telegram.exe"}},
	})

	// 2. Blackmatrix7 Apple
	evaluateListFile("community/blackmatrix7_apple.list", "DIRECT", "apple", []struct {
		desc string
		req  RequestDTO
	}{
		{desc: "Apple exact domain icons.axm-usercontent-apple.com", req: RequestDTO{Domain: "icons.axm-usercontent-apple.com"}},
		{desc: "Apple suffix apple.com", req: RequestDTO{Domain: "store.apple.com"}},
		{desc: "Apple suffix icloud.com", req: RequestDTO{Domain: "www.icloud.com"}},
		{desc: "Apple suffix aaplimg.com", req: RequestDTO{Domain: "images.aaplimg.com"}},
	})

	// 3. ACL4SSR LAN
	evaluateListFile("community/acl4ssr_lan.list", "DIRECT", "acl_lan", []struct {
		desc string
		req  RequestDTO
	}{
		{desc: "ACL LAN suffix localhost", req: RequestDTO{Domain: "localhost"}},
		{desc: "ACL LAN suffix ip6-localhost", req: RequestDTO{Domain: "ip6-localhost"}},
		{desc: "ACL LAN IPv4 10.0.0.1 in 10.0.0.0/8", req: RequestDTO{TargetIP: "10.0.0.1"}},
		{desc: "ACL LAN IPv4 192.168.1.1 in 192.168.0.0/16", req: RequestDTO{TargetIP: "192.168.1.1"}},
		{desc: "ACL LAN IPv4 172.20.0.1 in 172.16.0.0/12", req: RequestDTO{TargetIP: "172.20.0.1"}},
		{desc: "ACL LAN IPv4 127.0.0.1 in 127.0.0.0/8", req: RequestDTO{TargetIP: "127.0.0.1"}},
	})

	// 4. ACL4SSR ProxyLite
	evaluateListFile("community/acl4ssr_proxylite.list", "PROXY", "acl_proxy", []struct {
		desc string
		req  RequestDTO
	}{
		{desc: "ACL ProxyLite suffix 1password.com", req: RequestDTO{Domain: "my.1password.com"}},
		{desc: "ACL ProxyLite suffix reddit.com", req: RequestDTO{Domain: "old.reddit.com"}},
		{desc: "ACL ProxyLite suffix notion.so", req: RequestDTO{Domain: "www.notion.so"}},
		{desc: "ACL ProxyLite suffix linkedin.com", req: RequestDTO{Domain: "api.linkedin.com"}},
	})

	// Output golden_cases.json
	outJsonPath := filepath.Join(fixturesDir, "golden_cases.json")
	jsonBytes, err := json.MarshalIndent(testCases, "", "  ")
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(outJsonPath, jsonBytes, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Successfully generated %d golden test cases in %s!\n", len(testCases), outJsonPath)
}
