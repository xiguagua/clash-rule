# Clash Rule Engine — Swift 实现规划

> **文档约定**：本文只描述设计决策、语义、指标与里程碑，**不内嵌代码、字段清单、目录树、测试数量**——这些以源码为准，写进文档必然过时。需要细节时按下表去源头查；文中提到的类型/文件名仅作"概念锚点"，用 `grep` 即可定位。
>
> | 想了解 | 事实来源 |
> |---|---|
> | 编译态数据布局 | `Sources/ClashRuleCore/CompiledRules.swift`、`FlatStructures.swift` |
> | 解析 / 编译 / 匹配逻辑 | `Sources/ClashRuleCore/` 下 `Parser` / `Compiler` / `Matcher` |
> | C ABI（结构体、函数签名、状态码） | `Sources/ClashRuleCAPIHeader/include/clash_rule.h`（唯一权威） |
> | 包结构、目标平台、语言模式 | `Package.swift` |
> | 测试现状 | 运行 `swift test` |
> | 基准数据 | 运行 `./scripts/benchmark.sh`（`--quick` 为 10k 烟雾） |
> | 构建/提交规范 | `AGENTS.md` |

## 目标（按优先级）

1. **性能 Tier 1**：解析 + 匹配全链路对标 mihomo/clash.meta（Go）。10 万规则量级下索引类命中单次 < 1μs；编译 10 万行（含索引构建）< 80ms（M 系芯片）；与 mihomo 按"加载 + 查询"总成本（TCO）对标，而非单项解析时长。
2. **语言互操作**：稳定 C ABI，任何能链接 C 的语言（Go/Rust/Node/Python/Kotlin/Java）零胶水调用。
3. **RAM 高效**：10 万规则编译态 < 5.5 MB，解析期峰值 < 2× 编译态（验收口径 < 10 MB），热路径零堆分配。

---

## 当前状态（Current State）

### 已完成里程碑

- **M1/M2 核心骨架与扁平内存架构**：Arena + 扁平 POD 结构（exact 哈希表、后缀 trie、IP radix、端口区间、keyword 条目）；热路径零堆分配（测试以 `malloc_count == 0` 断言）；类别并发求值 + `ruleIndex` 仲裁。
- **M3 规则语义完备**：
  - 全部规则类型：`DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `IP-CIDR(6)` / `SRC-IP-CIDR(6)` / `PORT` / `DST-PORT` / `SRC-PORT` / `PROCESS-NAME` / `PROCESS-PATH` / `NETWORK` / `DSCP` / `GEOIP` / `MATCH`；
  - 逻辑规则 `AND` / `OR` / `NOT` / `SUB-RULE`，编译为扁平表达式树；
  - `RULE-SET` 外部载入，支持多格式（Classical、Domain payload、IP-CIDR payload、YAML list）及递归展开；
  - 以 mihomo 为 oracle 建立 Golden 对拍，语料为 ACL4SSR 与 blackmatrix7 真实规则集（LAN、Apple、Telegram、ProxyLite），全量对拍与端到端集成测试通过。
- **Swift 6.4+ 现代化（无向后兼容，全面 Span 化）**：
  - 工具链与目标平台基线见 `Package.swift`，已移除所有兼容 fallback 与 `@available` 守卫；
  - Parser / Compiler / Matcher 全链路以 `Span<UInt8>` / `RawSpan` 为入参，彻底移除 `UnsafeBufferPointer` / `UnsafeRawBufferPointer` 重载；
  - **`RuleSetResolver` 借用式回调**：规则集字节仅在回调的 `body` 执行期间借用，解析器不持有。调用约定由解析器强制校验——找到时恰好调用一次 `body` 并返回 `true`；未找到时不调用并返回 `false`；违约抛 `.invalidRuleSetResolver`。宿主加载失败通过 `RuleParseError.ruleSetLoadFailed` 上报（解析器回填 `RULE-SET` 行列号）；规则集内容的解析错误即使被 resolver 吞掉也会还原抛出。属编译期路径，名字拷贝与诊断字符串会分配。
- **M4 C ABI 最小可用版**：`ClashRuleCAPI` target 以正式 `@c` 导出 create / destroy / match / policy_name 四个入口，附稳定头文件与 C 请求/错误结构；C 调用方烟雾测试覆盖编译、匹配、policy 名读取、解析错误行号。**当前不支持从 C 注入外部 `RULE-SET` resolver。**
- **M5 性能基准与剪枝优化（提前启动）**：
  - 10k / 100k 规则生成器（`Tools/benchmark/corpus`）与双端基准（Swift `ClashRuleBenchmark` vs Go `Tools/benchmark/bench`）；
  - **成本分层求值 + 有界短路剪枝**：`CategoryBounds` 记录各类别最低规则行号，把"全类别无脑仲裁"演进为 4 级求值剪枝；
  - 编译期/热路径优化：`append(copying:)` 批量写入、`span[unchecked:]` 去边界检查、struct arena trie、免排序拍平、`ByteKey` 预存哈希、按 `matchKind` 字节分发；100k 编译 164ms → 74.7ms（-54%，早期一次记录为 62ms）。

### 100k 实测（同机 release，Span 架构）

| 指标 | Swift | mihomo | 对比 |
|---|---|---|---|
| 内存 | 快照 5.08 MB | Go 堆增量 24.50 MB | 节省 79% |
| 混合吞吐 | 27.5k ops/s | 10.1k ops/s | 2.7x（Keyword 剪枝后曾测得 6.48x） |
| 全 miss 最坏 | 169.5 μs | 1027.6 μs | 6.1x |
| 查询一致性 | 10/10 策略与 oracle 100% 一致 | — | — |

单项命中延迟：Exact 62.6ns、Suffix 144.7ns、IPv4 120.1ns、IPv6 196.9ns、Port/Process/GeoIP 均 < 100ns（Process 84.1ns）；Keyword 命中经早停剪枝后从 154.5µs 降至 115.7ns。

**TCO 口径**：mihomo 解析只做 append-to-slice，代价递延到匹配时的顺序扫描。Swift 多付 21.4ms 加载，每查询省 65.6μs，约 350 个混合查询回本。

### 后续规划

- M4 收尾：CLI 发行打包、Go cgo 示例、跨平台 C ABI 链接验证。
- M5 收尾：CI 性能门禁与自动化回归；Aho-Corasick（按需）。

---

## 0. 核心设计决策（TL;DR）

| 决策点 | 选择 | 理由 |
|---|---|---|
| 对外接口 | 稳定 C ABI（`@c` 导出），opaque handle | 全语言互通的公约数；SwiftPM 生态内直接用 Swift API |
| 匹配语义 | **全类别并发求值 → 取最小 rule-index** | 保留"顺序即优先级"，把 O(n) 顺序扫描变成近 O(1) |
| 数据结构 | 扁平数组 + 偏移量句柄，arena 分配 | 无引用类型开销，缓存友好，可整块序列化 |
| 字符串 | 解析期零拷贝（字节区间 → arena + 名称 interning） | RAM 决定性因素 |
| 内存布局 | SoA，不用带 payload 的 enum 大 union | enum payload 按最大成员定尺寸会浪费 |
| 并发模型 | 编译后不可变，只读无锁共享 | 构建一次，跨线程自由读 |

---

## 1. 架构总览

三个阶段严格分离，各自可独立测试：

1. **Parser**：输入单个 UTF-8 `RawSpan` / `Span<UInt8>`，产出带位置校验的中间规则流。不产生 `String`，一切以 `(offset, length)` 区间表示；流式、无字符串分配。
2. **Compiler**：把规则流按类型编译进各索引结构，产出**不可变**快照；附带 Diagnostics（错误行号/列号，一次性）。
3. **Matcher**：热路径。输入一次请求的 context（域名/目标 IP/端口/进程等），输出 policy handle。零分配。

C ABI 层（`clash_rule_*`）包在 Matcher 之上，是唯一对外导出面。

---

## 2. 内存模型

### 2.1 扁平快照

- 编译态快照由**各规则类别的平铺 POD 数组**（`ContiguousArray<POD>`）与**连续字节区**（policy 名、关键字、逻辑规则字符串等）组成；所有内部指针一律为 `UInt32` 偏移/索引，**不含类引用与堆对象**。
- POD 结构均标注 `BitwiseCopyable` + `Sendable`；编译期以 `ByteArena.append(copying:)` 批量写入。
- 快照包含的类别：policy 表、exact 域名哈希表、后缀 trie、IPv4/IPv6 与 Src-IP 的 radix trie、端口区间、keyword、process name/path 哈希表、NETWORK（TCP/UDP 各一个槽）、DSCP 表、GeoIP 表、逻辑规则扁平表达式树、MATCH 兜底，以及 `CategoryBounds` 与规则总数。具体字段见 `CompiledRules.swift`。
- **为何平铺 + 偏移**：Swift 原生对象无法表达跨结构指针（如 trie 节点 → 字符串 arena），除非用 class（引用计数 + 散乱堆分配）；平铺后快照无引用类型，可无锁共享，内存用量可精确估算，也能平滑升级为单块连续内存。
- **进阶方向**：单块一体化 blob + `mmap`（`RegionTable`），实现免反序列化加载；`RigidArray` / `UniqueArray`（SE-0527）、`OutputSpan` / `OutputRawSpan`（SE-0448）可用于消除写入 CoW 检查——当前 `ContiguousArray` + 批量 span 拷贝已达标，且热路径 0 堆分配已有断言。

### 2.2 单条规则预算

经典规则编译后约 16–24 字节：4B 头（类型、flags、policyID）+ 4B payload（指向字节区间 / trie 叶 / 端口对）+ 4B `ruleIndex`。10 万条约 2.5 MB，远低于 Go 实现（map + 切片，通常 20–40 MB）。

### 2.3 域名后缀 trie（DOMAIN / DOMAIN-SUFFIX）

- **逆序 label trie**（`com` → `example.com`），扁平化；节点约 16B，含子节点区间、label 偏移/长度、flags、policyID。
- 查找：域名从右往左逐 label 下走，命中后缀标记即匹配，记录最长匹配；"DOMAIN-SUFFIX 贪婪 vs 先出现的具体规则"由 rule-index 仲裁。
- 10 万域名节点数通常 < 15 万，约 2.4 MB。

**DOMAIN-KEYWORD**：数量少（< 64）时平铺线性比对（cache 友好，且受 `CategoryBounds` 短路加速，按行号升序首命中即 break）；多时可升级为 Aho-Corasick 扁平自动机（已预留扩展点）。

### 2.4 IP CIDR 索引

- 扁平二叉 Patricia/radix trie，IPv4 / IPv6 各一棵，`SRC-IP-CIDR` 另有独立小 trie；节点约 12B。
- 命中最长前缀；同一前缀多条规则取最小 `ruleIndex`。
- GEOIP：编译期下发"国家码 → policy"集合，**引擎不加载 MMDB**，IP→国家由宿主提供（C ABI 请求中带国家码，见 §5）。

### 2.5 端口

`DST-PORT` / `SRC-PORT` 为排序区间数组（每区间约 8B：lo、hi、policyID），二分查找。

---

## 3. 匹配语义：O(1) 与顺序优先级兼得

Clash 语义是"规则文件顺序即优先级，第一条匹配生效"，朴素扫描 10 万条最坏 10 万次。做法：

1. 编译时每条规则记录 `ruleIndex`。
2. 请求到来时并发查询各类别：exact 哈希 O(1)；suffix trie O(label 数)；keyword O(len)（或 AC）；IP trie O(前缀位数)；ports O(log n)；process O(1)。
3. 每类别返回类内命中的最小 `ruleIndex`，全类别取最小即整体首条匹配——语义等价，实际只需约 6 次亚线性查询。
4. **有界短路剪枝**：`CategoryBounds` 提供各类别最低出现行号，已有更小命中时后续类别可跳过或限界（4 级成本分层）。
5. 逻辑规则（AND/OR/NOT）单独编译为表达式树，仅在上述未命中时参与求值（通常 < 5% 规则量）。

**热路径约束**：Matcher 全部 `@inlinable`，输入输出为值类型/handle，无 `String`、无堆分配、无锁；请求 context 为栈上 struct。字节入参统一 `Span<UInt8>` / `RawSpan`（SE-0447/0456）：容器无关，non-escapable 恰好匹配"Matcher 不存储输入"。错误用 typed throws（SE-0413）避免装箱。跨线程共享仅经 `Sendable` 快照。

---

## 4. 性能手段

- **编译选项**：`-O`、跨模块优化（CMO）、WMO、严格并发检查完整级别。
- **`@frozen` POD**：公共布局结构体全部 `@frozen`，消除运行时布局检查。
- **避免语义糖**：热路径不用 `String`（用 UTF-8 字节 + `memcmp`）、不用 `Optional`（哨兵值 branchless）、不用 `indirect enum`。
- **哈希**：自实现 FNV-1a（Swift 原生 `Hashable` 带随机种子，不能用于确定性索引构建，且更慢）。改动哈希时需同步构建端与查询端。
- **分配**：整库唯一堆分配点是 Parser/Compiler 的构建期；Matcher 分配 = 0。
- **SIMD**：域名逐 label 比对可用 `SIMD8<UInt8>` / `memchr`；keyword 即使用 AC 也保持标量，避免过度优化。
- **Benchmark 纪律**：覆盖 parse / compile / match 三轴，回归阻断 CI（待落地）。

### Swift 6.4 增量手段

- **SE-0507 `borrow` / `mutate` accessor（已落地）**：`ByteArena` 的字节存储、`CompiledRules` 的 `bounds`/`ruleCount`、`Matcher` 的快照引用均用 borrow 就地借用，消除 CoW 检查与大结构体传递时的 ARC retain/release；并提供 `String(decoding: Span)`。
- **SE-0524 `withTemporaryAllocation`**：Parser scratch 的候选扩展点；当前以零分配的 `CommaRangeScanner` 游标迭代替代。
- **SE-0527 `RigidArray` / `UniqueArray`**：编译期缓冲唯一所有权、免 CoW 的候选方案（见 §2.1）。
- **`@diagnose`**：把核心模块的 unsafe/并发类 warning 升级为 error，作为 CI 纪律。
- **6.5 预期、暂不依赖**：SE-0516 `Iterable`（Span/InlineArray 的 for-in）、SE-0515（reduce 产出 noncopyable）。

---

## 5. 互操作层（C ABI）

### 5.1 API 表面

**以 `clash_rule.h` 为唯一权威**，此处只记设计要点：

- **四个入口**：
  - `create`：输入规则文本字节（调用期间借用），返回 opaque handle；解析失败返回 `NULL` 并回填错误结构；
  - `destroy`：销毁句柄，NULL 安全；
  - `match`：输入请求结构，命中时返回 OK 并写出 policy ID 与命中规则行号，未命中返回 NO_MATCH；
  - `policy_name`：按 ID 取 policy 的 UTF-8 字节，支持容量检查与尺寸查询（缓冲不足返回 BUFFER_TOO_SMALL）。
- **状态码**：OK / NO_MATCH / INVALID_ARGUMENT / BUFFER_TOO_SMALL。
- **错误结构**：错误码 + 行号 + 列号；不返回 Swift `String`。
- **请求结构**承载：域名字节区间；目标地址（128 位拆高低 64 位，含有无标志）与端口；源地址与端口；进程名、进程路径字节区间；网络协议（未指定/TCP/UDP）；DSCP（含有无标志）；国家码（大写 ASCII 大端打包，如 `US` = `0x00005553`）。
- **Policy 用 interned ID**（`UInt16`）：配置期 intern，调用方按 ID 比对（O(1)），需要名字时再显式 `policy_name`。
- **命名约束**：头文件字段/参数不得命名为 `bytes`（与 `Data.bytes` 冲突，实际用 `rule_data`）。

### 5.2 各语言接入难度

| 语言 | 方式 | 额外工作 |
|---|---|---|
| Swift (Apple) | SwiftPM 直接依赖 | 零 |
| Go | cgo 链接 dylib + 头文件 | 一个薄 wrapper |
| Rust | `-sys` crate + bindgen | 自动生成 |
| Node / Python / Electron | N-API / cffi 走 C ABI | 各自绑定 |
| iOS 内嵌 | 静态 framework，SwiftPM binary target | 零 |

### 5.3 Swift/C 实现要点

- 用正式 `@c` 属性（取代非正式 `@_cdecl`）导出符号，头文件随包分发（SE-0541 包级 Swift/C 互操作）。
- **生命周期**：C 侧手动 create/destroy，句柄必须恰好 destroy 一次。销毁后使用、重复销毁、传入非句柄指针、销毁与同一句柄的调用并发，均为调用方责任，库不做检测（未定义行为，已在 `clash_rule.h` 中说明）。Swift 侧 handle 为 `~Copyable` 类型（SE-0544 `intoRawHandle` 消费所有权，`deinit` 自动回收），由类型系统保证单次释放。

### 5.4 SwiftPM 模块职责

具体文件与 target 见 `Package.swift` 与 `Sources/` / `Tests/` 目录，此处只记职责：

| 模块 | 职责 |
|---|---|
| `ClashRuleCore` | 纯 Swift，零第三方依赖：Parser、Compiler、Matcher、扁平结构、arena、便捷 String/Data 扩展 |
| `ClashRuleCAPIHeader` | 仅承载稳定 C 头文件 |
| `ClashRuleCAPI` | `@c` 导出层，唯一 C ABI 面 |
| `ClashRuleBenchmark` | 规则生成与基准可执行程序 |
| `ClashRuleNIO`（可选，规划） | NIO `ByteBuffer` 边界集成 |
| Core 测试 | 核心单元测试（含 Matcher 零分配断言、`RuleSetResolver` 各情形） |
| C API 测试 + 测试支持 | 句柄安全测试、纯 C 消费者烟雾测试 |
| Golden 测试 | 对拍 mihomo 输出与社区规则集 |
| `Tools/benchmark`、`Tools/golden-oracle` | Go 端：语料生成 / 对标套件 / oracle 生成 |
| `scripts/` | `benchmark.sh` 调用入口；`compare_benchmark.py` 做指标核算、一致性校验、报表 |

### 5.5 NIO ByteBuffer 集成（可选 product）

swift-nio 2.99+（Swift 6.2 编译器）已接入 Span 家族，`ByteBuffer.readableBytesSpan`（`RawSpan`，借用）可零拷贝喂给 Parser。

**仅作边界，核心类型不是 `ByteBuffer`**，三点理由：
1. `ByteBuffer` 是 owning + CoW，与"单个不可变快照无锁共享"冲突；
2. 存储由 NIO allocator 管理，拿不出可整块 `mmap` / 移交 Go/Rust 宿主的原始内存，序列化走不通；
3. reader/writer index + 闭包访问面向顺序网络 I/O，Matcher 的随机索引访问用 Span 借用更干净。

NIO 的 `writeBytes(RawSpan)` 与 `ByteBuffer(capacity:initializingWith:)`（`OutputRawSpan`）表明其在跟进同一套原语，未来可低成本深化。与 `@c` 一致的哲学：核心用最窄原语，生态适配放外围薄层。

---

## 6. 解析器细节

- **输入**：`RawSpan` / `Span<UInt8>`，无 unsafe fallback；流式逐行扫描（`memchr('\n')`）；生命周期由 Span 借用检查保证。
- **arena 写入**：`OutputSpan` / `OutputRawSpan`（SE-0448）承担 bump 分配语义，`finalize` 一次性移交所有权（当前以批量 `copying:` 实现）。
- **词法**：手写状态机，识别 `TYPE,ARG,POLICY` 三段（`no-resolve`、`no-traffic` 等 flag 一并处理）；支持 `#` 注释、空白、CRLF。
- **验证**：规则类型白名单、IP/CIDR 合法性、policy 名字符集；出错带行号 + 列号。
- **错误策略**：fail-fast；可选 collect-all 模式（编辑器集成用）。
- **RULE-SET**：`RULE-SET,NAME,POLICY` 展开为引用，加载 `.list` 复用同一 Parser。
- **编码**：仅 UTF-8，遇 BOM/非法字节立即报错。

---

## 7. 测试与验收

| 验收项 | 目标 |
|---|---|
| Golden | 与 mihomo 解析同一 config，匹配结果 100% 一致（DOMAIN/IP/PORT/PROCESS/LOGIC/RULE-SET/GEOIP）；语料为 ACL4SSR、blackmatrix7 等真实社区规则集 |
| 编译性能 | 100k 规则（含索引构建）< 80ms，单核；与 mihomo 按 TCO 对标，约 350 查询回本（口径见"当前状态"） |
| 匹配性能 | 索引类命中（exact/suffix/ip/port/process/geoip）< 1μs；全 miss 最坏 < 200μs（mihomo 约 1ms）；混合吞吐 ≥ 2x mihomo |
| RAM | 100k 编译态 < 5.5 MB；解析期峰值 < 10 MB |
| 热路径分配 | `malloc` 计数 = 0 |
| ABI 兼容 | 头文件 + dylib 符号表稳定，跨 minor 版本不破坏 |

---

## 8. 里程碑

- **M1 骨架可跑**【完成】：Swift 6.4 工具链基线；Parser + 基础类型 + Swift 匹配 API + 单测。
- **M2 内存架构落地**【完成】：Arena + 扁平 trie/radix/hash，RAM 达标，热路径零堆分配（断言保障）。
- **M3 语义完备**【完成】：全部规则类型、逻辑规则、RULE-SET 借用解析、Golden 对拍与真实规则集测试。
- **M4 互操作层**【核心完成】：
  - [x] `@c` 导出 C ABI + 稳定头文件；
  - [x] C 烟雾测试：句柄生命周期、匹配、错误码、Policy 名提取；
  - [x] CLI：`check`（编译检查）与 `explain`（逐类别解释命中原因），见 `Sources/ClashRuleTool`；
  - [ ] CLI 独立发行（打包、签名）、Go cgo 示例、跨平台链接验证。
- **M5 性能打磨**【核心完成】：
  - [x] 10k/100k corpus 与 mihomo 对拍 benchmark；
  - [x] 成本分层求值 + 有界短路剪枝；
  - [x] 编译期优化（100k 编译 74.7ms，快照 5.08MB）；
  - [x] Keyword 早停剪枝（命中 154.5µs → 115.7ns，混合吞吐一度达 6.48x mihomo）；
  - [x] 自动化对标脚本（终端着色、Markdown/JSON 导出、一致性校验、TCO 测算）；
  - [ ] Aho-Corasick（按需）、CI 性能门禁与自动回归。

---

## 9. 风险与备选

| 风险 | 缓解 |
|---|---|
| 工具链基线高（`@c` 需 6.3+，SE-0507/0524/0527 需 6.4+） | 锁定 6.4 为最低要求；宿主受限时 Core 可回退 6.2 子集（Span 全家可用），仅 C 层与 `RigidArray` 两处 feature-gate |
| ~~`@_cdecl` 非正式~~ | **已解除**：用正式 `@c`（6.3）；仅需支持 < 6.3 时回退 `@_cdecl` |
| Swift 运行时需随 dylib 分发 | iOS 系统自带；Linux 静态链接（`-static-stdlib`）或文档声明依赖 |
| Clash 语义边角（no-resolve、MATCH 兜底顺序） | Golden 以 mihomo 为 oracle，不一致以 mihomo 为准 |
| GEOIP 数据库依赖 | 引擎只做"国家码 → policy"索引，不加载 MMDB；宿主做 IP→国家并传入请求。（原设想的 C 函数指针回调未采用） |
| `InlineArray` open bug（栈拷贝内容变化，swiftlang#83774） | 仅用于小固定 N（如 16 字节 IPv6），不进核心索引；CI 加回归断言 |
| `Data.bytes: RawSpan`（SE-0456）与生成头文件标识符冲突（同 uniffi-rs#2803） | C 头不使用 `bytes` 命名（实用 `rule_data`） |

---

## 10. Swift Evolution 选型对照（2026-10）

| 用途 | 原选型 | 现选型 / 状态 | Proposal | 说明 |
|---|---|---|---|---|
| 解析输入 | `UnsafeBufferPointer<UInt8>` | `RawSpan` / `Span<UInt8>` | SE-0447/0456 | **已落地**：借用安全、无 unsafe fallback |
| 热路径字节入参 | `ArraySlice<UInt8>` | `Span<UInt8>` | SE-0447 | **已落地**：容器无关，non-escapable |
| Arena 写入 | 手写 bump 指针 | `ByteArena.append(copying:)`（`OutputSpan` 备选） | SE-0448 | **已落地**：批量拷贝，类型安全 |
| POD 结构 | 仅 `@frozen` | `+ BitwiseCopyable` | SE-0426 | **已落地**：复制即 memcpy，原始字节视图前提 |
| C ABI 导出 | `@_cdecl` | `@c` + 包级互操作 | SE-0541 · 6.3 | **已落地** |
| 错误处理 | `throws` | typed throws | SE-0413 | **已落地**：无装箱 |
| 属性借用 | 闭包传递 / get 拷贝 | `borrow` / `mutate` accessor | SE-0507 · 6.4 | **已落地**：消除 CoW 与 ARC 拷贝 |
| Parser scratch | 手管指针 | `CommaRangeScanner` 零分配扫描器 | SE-0524 · 6.4 | `withTemporaryAllocation` 为扩展点 |
| 编译期缓冲 | `ContiguousArray` | 维持（`RigidArray` 备选） | SE-0527 · 6.4 | 当前已达标，免 CoW 为进阶手段 |
| 小固定尺寸表 | `ContiguousArray` | 维持（`InlineArray` 备选） | SE-0462 | 避开 open bug #83774 |
| 大数组/arena 主体 | `ContiguousArray` / mmap | 平铺数组 + `UInt32` 索引 | — | 单块 mmap 为进阶规划 |
| 索引哈希 | wyhash/FNV | 自实现 FNV-1a | — | **已落地**：确定性构建 |
| 热加载换快照 | 锁 / 库外原子 | `Mutex` / `Atomic` | SE-0433/0438 | 仅换入换出用，match 仍无锁 |
| NIO 边界 | — | `ByteBuffer.readableBytesSpan` | swift-nio 2.99+ | 可选 `ClashRuleNIO`，核心不依赖 NIO |

补充：SE-0494（`isTriviallyIdentical`）与单快照设计无交集，跳过；Embedded Swift 作 M5 可选实验（Core 满足子集约束，可产出极小二进制，但限制 C API 动态性，不进主线）；6.4 对 Wasm/C++/Java 互操作的改进记为未来方向（Wasm 对浏览器场景是潜在加分项）。
