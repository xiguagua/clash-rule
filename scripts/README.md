# Scripts

本目录包含工程自动化与性能对标脚本。

## 基准测试对比脚本 (`benchmark.sh` / `compare_benchmark.py`)

用于全自动构建并比对 **ClashRuleCore (Swift 6.4 Zero-Alloc)** 与 **mihomo (Go / Clash.Meta)** 的宏观与微观性能及匹配一致性。

### 常用命令

```bash
# 1. 完整 100k 规则对标（默认 50,000 iters）
./scripts/benchmark.sh

# 2. 快速冒烟对标（10k 规则，5,000 iters）
./scripts/benchmark.sh --quick

# 3. 导出 GitHub Markdown 报告
./scripts/benchmark.sh --markdown

# 4. 导出 JSON 结构化数据
./scripts/benchmark.sh --json

# 5. 跳过构建（复用已生成的二进制快速重测）
./scripts/benchmark.sh --skip-build

# 6. 自定义规则与迭代轮数
./scripts/benchmark.sh --rules <path-to-rules> --workload <path-to-workload> --iters <n>
```
