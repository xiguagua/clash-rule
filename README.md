# clash-rule

一个用 Swift 实现的 Clash 规则引擎。规则在编译期被转换为扁平、不可变的索引结构，匹配热路径零堆分配、无锁，并通过稳定的 C ABI 供其他语言调用。

语义以 [mihomo](https://github.com/MetaCubeX/mihomo) 为 oracle，通过 Golden 测试做对照。

## 特性

- **完整的规则类型**：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR(6)`、`SRC-IP-CIDR(6)`、`DST-PORT`、`SRC-PORT`、`PORT`、`PROCESS-NAME`、`PROCESS-PATH`、`NETWORK`、`DSCP`、`GEOIP`、`MATCH`。
- **逻辑规则**：`AND` / `OR` / `NOT` / `SUB-RULE`，编译为扁平表达式树。
- **RULE-SET**：支持 Classical、Domain、IP-CIDR、YAML list 等格式，并可递归展开。
- **顺序语义**：规则文件顺序即优先级。各类别并发查询，取最小 `ruleIndex` 作为首条命中。
- **零分配热路径**：匹配阶段不产生堆分配（测试以 `malloc` 计数断言为 0），不使用 `String`，输入为 `Span<UInt8>` / `RawSpan`。
- **C ABI**：通过 `@c` 导出 `create` / `destroy` / `match` / `policy_name` 四个入口，头文件见 `Sources/ClashRuleCAPIHeader/include/clash_rule.h`。

## 性能

100k 条规则、同机 release 构建，与 mihomo 对比（详见 `docs/PLAN.md`）：

| 指标 | clash-rule | mihomo |
|---|---|---|
| 内存（编译态） | 5.08 MB | Go 堆增量 24.50 MB |
| 混合吞吐 | 27.5k ops/s | 10.1k ops/s |
| 全 miss 最坏延迟 | 169.5 μs | 1027.6 μs |

可通过 `./scripts/benchmark.sh` 在本机复现。

## 环境要求

- Swift 6.4+（`swift-tools-version:6.4`）
- macOS 27 / iOS 27 / tvOS 27

## 构建与测试

```bash
swift build
swift test
```

基准测试：

```bash
./scripts/benchmark.sh            # 完整 100k 对标
./scripts/benchmark.sh --quick    # 10k 冒烟对标
```

脚本依赖 Go（用于构建 mihomo oracle 与基准驱动）以及 Python 3（用于结果核算）。详见 [`scripts/README.md`](scripts/README.md)。

## 命令行工具

`clash-rule` 用于排查规则问题：编译检查，以及解释一次请求为什么命中或未命中某条规则。

```bash
clash-rule check rules.txt [--rule-set 名称=路径]...
clash-rule explain rules.txt --domain www.example.com --ip 10.1.2.3 --port 443 --network tcp
```

`explain` 会逐个类别列出求值结果，标出胜出者，并说明被覆盖的命中是被哪条规则覆盖的。RULE-SET 需要通过 `--rule-set` 指定文件。

源行号依赖 `Diagnostics` trait，默认关闭。需要显示行号时这样构建和运行：

```bash
swift run --traits Diagnostics clash-rule explain rules.txt --domain example.com
```

退出码：0 成功（含未命中）；1 规则或文件错误；2 参数错误。

## 目录结构

| 路径 | 说明 |
|---|---|
| `Sources/ClashRuleCore` | 纯 Swift 核心：Parser、Compiler、Matcher，零第三方依赖 |
| `Sources/ClashRuleCAPI` | `@c` 导出层，唯一 C ABI 面 |
| `Sources/ClashRuleCAPIHeader` | 稳定 C 头文件 |
| `Sources/ClashRuleBenchmark` | 规则生成与基准可执行程序 |
| `Sources/ClashRuleTool` | `clash-rule` 命令行的逻辑（参数解析、check / explain 输出） |
| `Sources/ClashRuleCLI` | `clash-rule` 可执行入口 |
| `Tests/` | Core、C API、Golden 测试 |
| `Tools/benchmark` | Go 端语料生成与 mihomo 基准驱动 |
| `Tools/golden-oracle` | Go 端 oracle 生成工具 |
| `scripts/` | 基准入口脚本与结果比对脚本 |
| `docs/PLAN.md` | 设计文档与里程碑 |

## 设计要点

- 编译后的快照由平铺 POD 数组和 `UInt32` 偏移组成，不含类引用，可无锁跨线程共享。
- 域名使用逆序 label 后缀 trie，IP 使用 radix trie，端口使用排序区间二分，关键字为线性比对并带早停剪枝。
- GEOIP 只做"国家码 → policy"的索引，不加载 MMDB，IP 到国家码的映射由宿主提供。

更完整的设计决策、内存模型与路线图见 [`docs/PLAN.md`](docs/PLAN.md)。

## 贡献

开发约定与提交规范见 [`AGENTS.md`](AGENTS.md)。提交前请确保 `swift test` 通过。

## 许可证

本项目代码以 [MIT License](LICENSE) 发布。

Golden 测试中的部分社区规则文件（ACL4SSR 为 CC-BY-SA-4.0，blackmatrix7 为 GPL-2.0）不适用 MIT，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
