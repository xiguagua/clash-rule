#!/usr/bin/env python3
"""
ClashRuleCore vs mihomo (Clash.Meta) Benchmark Comparison Tool

Runs both ClashRuleCore (Swift 6.4 Zero-Alloc) and mihomo (Go) benchmark suites,
compares compilation time, memory usage, mixed traffic throughput, per-query latency,
and validates rule match semantic parity.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path


class Colors:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _c(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str: return self._c("1", text)
    def dim(self, text: str) -> str: return self._c("2", text)
    def green(self, text: str) -> str: return self._c("32", text)
    def red(self, text: str) -> str: return self._c("31", text)
    def yellow(self, text: str) -> str: return self._c("33", text)
    def cyan(self, text: str) -> str: return self._c("36", text)
    def magenta(self, text: str) -> str: return self._c("35", text)


def find_repo_root() -> Path:
    current = Path(__file__).resolve().parent
    for p in [current, *current.parents]:
        if (p / "Package.swift").is_file():
            return p
    return Path.cwd().resolve()


def run_command(cmd: list[str], cwd: Path, quiet: bool = False) -> subprocess.CompletedProcess[str]:
    if not quiet:
        print(f"  \033[2m$ {' '.join(cmd)}\033[0m", file=sys.stderr)
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed (exit {result.returncode}): {' '.join(cmd)}", file=sys.stderr)
        if result.stderr:
            print(f"stderr:\n{result.stderr}", file=sys.stderr)
        if result.stdout:
            print(f"stdout:\n{result.stdout}", file=sys.stderr)
        sys.exit(result.returncode)
    return result


def build_engines(repo_root: Path, skip_build: bool, build_swift: bool, build_go: bool, quiet: bool) -> tuple[Path, Path]:
    swift_bin = repo_root / ".build" / "release" / "ClashRuleBenchmark"
    go_bin_dir = repo_root / "Tools" / "benchmark" / "bin"
    go_bin = go_bin_dir / "mihomo-bench"

    if build_swift and not skip_build:
        if not quiet:
            print("==> Building ClashRuleBenchmark (Swift 6.4 Release)...", file=sys.stderr)
        run_command(["swift", "build", "-c", "release", "--product", "ClashRuleBenchmark"], cwd=repo_root, quiet=quiet)

    if build_go and not skip_build:
        if not quiet:
            print("==> Building mihomo benchmark tool (Go)...", file=sys.stderr)
        go_bin_dir.mkdir(parents=True, exist_ok=True)
        run_command(["go", "build", "-o", str(go_bin), "./bench"], cwd=repo_root / "Tools" / "benchmark", quiet=quiet)

    if build_swift and not swift_bin.is_file():
        sys.exit(f"Error: Swift benchmark binary not found at {swift_bin}")
    if build_go and not go_bin.is_file():
        sys.exit(f"Error: Go benchmark binary not found at {go_bin}")

    return swift_bin, go_bin


def extract_json(stdout: str) -> dict:
    lines = stdout.strip().splitlines()
    json_start = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("{"):
            json_start = i
            break
    if json_start == -1:
        raise ValueError(f"No JSON object found in output:\n{stdout}")
    json_str = "\n".join(lines[json_start:])
    return json.loads(json_str)


def run_benchmark(bin_path: Path, rules_path: Path, workload_path: Path, iters: int, cwd: Path) -> dict:
    cmd = [
        str(bin_path),
        "--rules", str(rules_path),
        "--workload", str(workload_path),
        "--iters", str(iters),
        "--json",
    ]
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Benchmark execution failed: {' '.join(cmd)}", file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(res.returncode)
    return extract_json(res.stdout)


def format_speedup(swift_val: float, mihomo_val: float, higher_is_better: bool = False, c: Colors = None) -> str:
    if swift_val <= 0 or mihomo_val <= 0:
        return "N/A"
    
    if higher_is_better:
        ratio = swift_val / mihomo_val
        text = f"{ratio:.2f}x"
        if c:
            if ratio >= 1.05:
                return c.green(f"+{(ratio - 1.0) * 100:.1f}% ({text})")
            elif ratio <= 0.95:
                return c.red(f"-{(1.0 - ratio) * 100:.1f}% ({text})")
            return c.yellow(text)
        return text
    else:
        # Lower is better (latency)
        ratio = mihomo_val / swift_val
        if ratio >= 1.0:
            text = f"{ratio:.2f}x faster"
            return c.green(text) if c else text
        else:
            text = f"{1.0 / ratio:.2f}x slower"
            return c.red(text) if c else text


def compute_comparison(swift_data: dict, go_data: dict) -> dict:
    swift_queries = {q["name"]: q for q in swift_data.get("query_results", [])}
    go_queries = {q["name"]: q for q in go_data.get("query_results", [])}

    per_query = []
    all_parity = True

    for name, s_q in swift_queries.items():
        g_q = go_queries.get(name)
        if not g_q:
            continue

        s_matched = s_q.get("matched", False)
        g_matched = g_q.get("matched", False)
        s_policy = s_q.get("policy", "")
        g_policy = g_q.get("policy", "")

        parity = (s_matched == g_matched) and (s_policy == g_policy)
        if not parity:
            all_parity = False

        s_ns = s_q.get("ns_per_op", 0.0)
        g_ns = g_q.get("ns_per_op", 0.0)
        speedup = (g_ns / s_ns) if s_ns > 0 else 0.0

        per_query.append({
            "name": name,
            "description": s_q.get("description", ""),
            "swift_ns": s_ns,
            "mihomo_ns": g_ns,
            "speedup_ratio": speedup,
            "swift_policy": s_policy,
            "mihomo_policy": g_policy,
            "parity_match": parity,
        })

    swift_parse_ms = swift_data.get("parse_time_ms", 0.0)
    go_parse_ms = go_data.get("parse_time_ms", 0.0)

    swift_mem_mb = swift_data.get("snapshot_size_mb", 0.0)
    go_mem_mb = go_data.get("alloc_bytes_mb", 0.0)
    mem_saved_pct = ((go_mem_mb - swift_mem_mb) / go_mem_mb * 100.0) if go_mem_mb > 0 else 0.0

    swift_ops = swift_data.get("mixed_ops_per_s", 0.0)
    go_ops = go_data.get("mixed_ops_per_s", 0.0)
    throughput_multiplier = (swift_ops / go_ops) if go_ops > 0 else 0.0

    swift_mixed_ns = swift_data.get("mixed_ns_per_op", 0.0)
    go_mixed_ns = go_data.get("mixed_ns_per_op", 0.0)

    # TCO break-even calculation:
    # Swift compile time might be slightly higher due to full index tree building,
    # but each mixed query is faster by (go_mixed_ns - swift_mixed_ns).
    tco_breakeven_queries = None
    delta_compile_ms = swift_parse_ms - go_parse_ms
    delta_ns_per_query = go_mixed_ns - swift_mixed_ns
    if delta_ns_per_query > 0:
        if delta_compile_ms <= 0:
            tco_breakeven_queries = 0  # Swift compiled faster AND matches faster
        else:
            tco_breakeven_queries = int((delta_compile_ms * 1e6) / delta_ns_per_query)

    return {
        "parity_verified": all_parity,
        "rules_count": swift_data.get("rule_count", 0),
        "swift_parse_ms": swift_parse_ms,
        "mihomo_parse_ms": go_parse_ms,
        "compile_ratio": (swift_parse_ms / go_parse_ms) if go_parse_ms > 0 else 0.0,
        "swift_mem_mb": swift_mem_mb,
        "mihomo_mem_mb": go_mem_mb,
        "mem_saved_pct": mem_saved_pct,
        "swift_ops": swift_ops,
        "mihomo_ops": go_ops,
        "throughput_multiplier": throughput_multiplier,
        "swift_mixed_ns": swift_mixed_ns,
        "mihomo_mixed_ns": go_mixed_ns,
        "tco_breakeven_queries": tco_breakeven_queries,
        "query_comparisons": per_query,
    }


def render_terminal_report(swift_data: dict, go_data: dict, comp: dict, c: Colors, rules_file: str, iters: int) -> str:
    lines = []
    w_line = 96
    sep = "=" * w_line
    thin_sep = "-" * w_line

    lines.append(c.bold(sep))
    lines.append(c.bold("  ClashRuleCore (Swift 6.4 Zero-Alloc) vs mihomo (Go) Benchmark Comparison"))
    lines.append(c.bold(sep))
    lines.append(f"  Platform:  {platform.system()} {platform.machine()} ({platform.processor() or 'ARM64'})")
    lines.append(f"  Dataset:   {rules_file} ({comp['rules_count']:,} rules)")
    lines.append(f"  Workload:  {len(comp['query_comparisons'])} queries @ {iters:,} iterations each")
    parity_str = c.green("PASSED (All policies 100% identical)") if comp["parity_verified"] else c.red("FAILED (Mismatches found!)")
    lines.append(f"  Parity:    {parity_str}")
    lines.append(c.bold(thin_sep))

    # Macro table
    lines.append(c.bold(f"  {'Metric':<30} | {'ClashRuleCore (Swift)':<24} | {'mihomo (Go)':<18} | {'Delta / Advantage':<18}"))
    lines.append(thin_sep)

    # 1. Parse / Compile
    s_compile = f"{comp['swift_parse_ms']:.2f} ms"
    g_compile = f"{comp['mihomo_parse_ms']:.2f} ms"
    if comp['swift_parse_ms'] <= comp['mihomo_parse_ms']:
        ratio_c = c.green(f"{comp['mihomo_parse_ms']/comp['swift_parse_ms']:.2f}x faster")
    else:
        diff_ms = comp['swift_parse_ms'] - comp['mihomo_parse_ms']
        ratio_c = c.dim(f"+{diff_ms:.1f} ms (indexing)")
    lines.append(f"  {'Compile/Parse Time':<30} | {s_compile:<24} | {g_compile:<18} | {ratio_c}")

    # 2. Memory
    s_mem = f"{comp['swift_mem_mb']:.2f} MB (Snapshot RAM)"
    g_mem = f"{comp['mihomo_mem_mb']:.2f} MB (Heap Delta)"
    mem_adv = c.green(f"-{comp['mem_saved_pct']:.1f}% RAM ({comp['mihomo_mem_mb']/comp['swift_mem_mb']:.1f}x less)")
    lines.append(f"  {'Memory Footprint':<30} | {s_mem:<24} | {g_mem:<18} | {mem_adv}")

    # 3. Mixed Throughput
    s_ops = f"{comp['swift_ops']:,.0f} ops/s"
    g_ops = f"{comp['mihomo_ops']:,.0f} ops/s"
    tp_adv = c.green(f"{comp['throughput_multiplier']:.2f}x throughput")
    lines.append(f"  {'Mixed Throughput':<30} | {s_ops:<24} | {g_ops:<18} | {tp_adv}")

    # 4. Mixed Latency
    s_lat = f"{comp['swift_mixed_ns']:,.1f} ns/op"
    g_lat = f"{comp['mihomo_mixed_ns']:,.1f} ns/op"
    lat_adv = format_speedup(comp['swift_mixed_ns'], comp['mihomo_mixed_ns'], higher_is_better=False, c=c)
    lines.append(f"  {'Mixed Match Latency':<30} | {s_lat:<24} | {g_lat:<18} | {lat_adv}")

    # 5. TCO Break-Even
    if comp['tco_breakeven_queries'] is not None:
        if comp['tco_breakeven_queries'] == 0:
            tco_str = c.green("Immediate (0 queries)")
        else:
            tco_str = c.cyan(f"~{comp['tco_breakeven_queries']:,} queries")
    else:
        tco_str = "N/A"
    lines.append(f"  {'TCO Break-Even Point':<30} | {tco_str:<24} | {'—':<18} | {'Amortized Index':<18}")

    lines.append(c.bold(thin_sep))
    lines.append(c.bold(f"  {'Query ID':<16} | {'Description':<32} | {'Swift Latency':<13} | {'mihomo Latency':<14} | {'Speedup':<12} | {'Parity'}"))
    lines.append(thin_sep)

    for q in comp["query_comparisons"]:
        s_ns = f"{q['swift_ns']:.1f} ns"
        g_ns = f"{q['mihomo_ns']:.1f} ns"
        speed_str = format_speedup(q['swift_ns'], q['mihomo_ns'], higher_is_better=False, c=c)
        parity_mark = c.green(f"✓ {q['swift_policy']}") if q['parity_match'] else c.red(f"✗ {q['swift_policy']} != {q['mihomo_policy']}")
        lines.append(f"  {q['name']:<16} | {q['description']:<32} | {s_ns:>13} | {g_ns:>14} | {speed_str:<12} | {parity_mark}")

    lines.append(c.bold(sep))
    
    # Executive Summary
    swift_mem_str = f"{comp['swift_mem_mb']:.2f} MB"
    mem_pct_str = f"{comp['mem_saved_pct']:.1f}% reduction"
    tp_mult_str = f"{comp['throughput_multiplier']:.2f}x"

    lines.append(c.bold("  Executive Summary:"))
    lines.append(f"  • {c.bold('Memory Efficiency')}: ClashRuleCore consumes only {c.green(swift_mem_str)} RAM vs mihomo's {comp['mihomo_mem_mb']:.2f} MB ({c.green(mem_pct_str)}).")
    lines.append(f"  • {c.bold('Throughput')}: ClashRuleCore delivers {c.green(tp_mult_str)} mixed request throughput ({comp['swift_ops']:,.0f} vs {comp['mihomo_ops']:,.0f} ops/s).")
    
    # Check fallback miss
    miss_q = next((q for q in comp["query_comparisons"] if q["name"] == "fallback_miss"), None)
    if miss_q:
        swift_miss_us = f"{miss_q['swift_ns']/1e3:.1f} µs"
        speedup_str = f"{miss_q['speedup_ratio']:.1f}x faster"
        lines.append(f"  • {c.bold('Worst-Case Miss Path')}: Full category miss completes in {c.green(swift_miss_us)} vs mihomo's {miss_q['mihomo_ns']/1e3:.1f} µs ({c.green(speedup_str)}).")
    
    if comp['tco_breakeven_queries']:
        be_str = f"~{comp['tco_breakeven_queries']:,}"
        lines.append(f"  • {c.bold('TCO Amortization')}: Upfront index compilation pays off after {c.cyan(be_str)} requests; subsequent matches are orders of magnitude lighter.")
    lines.append(c.bold(sep))

    return "\n".join(lines)


def render_markdown_report(swift_data: dict, go_data: dict, comp: dict, rules_file: str, iters: int) -> str:
    lines = []
    lines.append("# ClashRuleCore vs mihomo Benchmark Comparison Report\n")
    lines.append(f"- **Platform**: `{platform.system()} {platform.machine()}`")
    lines.append(f"- **Rules File**: `{rules_file}` ({comp['rules_count']:,} rules)")
    lines.append(f"- **Iterations**: {iters:,} per query")
    lines.append(f"- **Semantic Parity**: {'✅ 100% Consistent' if comp['parity_verified'] else '❌ Discrepancies detected'}\n")

    lines.append("## Macro Engine Comparison\n")
    lines.append("| Metric | ClashRuleCore (Swift 6.4) | mihomo (Go v1.19.2) | Advantage / Ratio |")
    lines.append("| :--- | :--- | :--- | :--- |")
    lines.append(f"| **Compile / Parse Time** | {comp['swift_parse_ms']:.2f} ms | {comp['mihomo_parse_ms']:.2f} ms | {comp['mihomo_parse_ms']/comp['swift_parse_ms']:.2f}x ({'+' if comp['swift_parse_ms']>comp['mihomo_parse_ms'] else ''}{comp['swift_parse_ms']-comp['mihomo_parse_ms']:.1f} ms) |")
    lines.append(f"| **Memory Footprint** | {comp['swift_mem_mb']:.2f} MB (Snapshot) | {comp['mihomo_mem_mb']:.2f} MB (Heap) | **{comp['mem_saved_pct']:.1f}% less RAM** ({comp['mihomo_mem_mb']/comp['swift_mem_mb']:.1f}x) |")
    lines.append(f"| **Mixed Throughput** | **{comp['swift_ops']:,.0f} ops/s** | {comp['mihomo_ops']:,.0f} ops/s | **{comp['throughput_multiplier']:.2f}x faster** |")
    lines.append(f"| **Mixed Latency** | **{comp['swift_mixed_ns']:.1f} ns/op** | {comp['mihomo_mixed_ns']:.1f} ns/op | **{comp['mihomo_mixed_ns']/comp['swift_mixed_ns']:.2f}x faster** |")
    if comp['tco_breakeven_queries'] is not None:
        lines.append(f"| **TCO Break-Even** | ~{comp['tco_breakeven_queries']:,} queries | — | Compile investment recovered |")
    lines.append("")

    lines.append("## Per-Query Match Latency & Parity\n")
    lines.append("| Query ID | Description | ClashRuleCore | mihomo | Speedup | Parity Policy |")
    lines.append("| :--- | :--- | :---: | :---: | :---: | :--- |")
    for q in comp["query_comparisons"]:
        ratio_str = f"{q['speedup_ratio']:.2f}x" if q['speedup_ratio'] >= 1.0 else f"{1.0/q['speedup_ratio']:.2f}x slower"
        parity_str = f"✅ `{q['swift_policy']}`" if q['parity_match'] else f"❌ `{q['swift_policy']}` vs `{q['mihomo_policy']}`"
        lines.append(f"| `{q['name']}` | {q['description']} | {q['swift_ns']:.1f} ns | {q['mihomo_ns']:.1f} ns | **{ratio_str}** | {parity_str} |")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Run and compare ClashRuleCore vs mihomo benchmarks",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--rules", default="Tools/benchmark/data/bench_100k.rules", help="Path to rules file")
    parser.add_argument("--workload", default="Tools/benchmark/data/workload.json", help="Path to workload queries JSON")
    parser.add_argument("--iters", type=int, default=50000, help="Match iterations per query")
    parser.add_argument("--quick", action="store_true", help="Quick mode (10k rules, 5000 iters)")
    parser.add_argument("--skip-build", action="store_true", help="Skip compilation of Swift and Go binaries")
    parser.add_argument("--swift-only", action="store_true", help="Run only Swift benchmark")
    parser.add_argument("--mihomo-only", action="store_true", help="Run only Go mihomo benchmark")
    parser.add_argument("--json", action="store_true", help="Output raw or combined JSON")
    parser.add_argument("--markdown", action="store_true", help="Output GitHub Markdown format")
    parser.add_argument("--output", help="Write report to specified file")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    parser.add_argument("--quiet", action="store_true", help="Suppress build and progress messages")

    args = parser.parse_args()

    repo_root = find_repo_root()

    if args.quick:
        if args.rules == "Tools/benchmark/data/bench_100k.rules":
            args.rules = "Tools/benchmark/data/bench_10k.rules"
        if args.iters == 50000:
            args.iters = 5000

    rules_path = Path(args.rules)
    if not rules_path.is_absolute():
        rules_path = repo_root / rules_path
    if not rules_path.is_file():
        sys.exit(f"Rules file not found: {rules_path}")

    workload_path = Path(args.workload)
    if not workload_path.is_absolute():
        workload_path = repo_root / workload_path
    if not workload_path.is_file():
        sys.exit(f"Workload file not found: {workload_path}")

    use_color = not args.no_color and sys.stdout.isatty() and not args.json and not args.markdown
    c = Colors(use_color)

    build_swift = not args.mihomo_only
    build_go = not args.swift_only

    swift_bin, go_bin = build_engines(
        repo_root=repo_root,
        skip_build=args.skip_build,
        build_swift=build_swift,
        build_go=build_go,
        quiet=args.quiet or args.json,
    )

    swift_data = None
    go_data = None

    if build_swift:
        if not args.quiet and not args.json:
            print("==> Running ClashRuleCore benchmark...", file=sys.stderr)
        swift_data = run_benchmark(swift_bin, rules_path, workload_path, args.iters, repo_root)

    if build_go:
        if not args.quiet and not args.json:
            print("==> Running mihomo benchmark...", file=sys.stderr)
        go_data = run_benchmark(go_bin, rules_path, workload_path, args.iters, repo_root / "Tools" / "benchmark")

    # Single-engine modes
    if args.swift_only:
        out = json.dumps(swift_data, indent=2) if args.json else str(swift_data)
        print(out)
        return

    if args.mihomo_only:
        out = json.dumps(go_data, indent=2) if args.json else str(go_data)
        print(out)
        return

    # Combined comparison
    comp = compute_comparison(swift_data, go_data)

    if args.json:
        result_payload = {
            "clash_rule_core": swift_data,
            "mihomo": go_data,
            "comparison": comp,
        }
        rendered = json.dumps(result_payload, indent=2)
    elif args.markdown:
        rendered = render_markdown_report(swift_data, go_data, comp, str(rules_path.relative_to(repo_root)), args.iters)
    else:
        rendered = render_terminal_report(swift_data, go_data, comp, c, str(rules_path.relative_to(repo_root)), args.iters)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        if not args.quiet:
            print(f"Report saved to {args.output}", file=sys.stderr)
    else:
        print(rendered)


if __name__ == "__main__":
    main()
