# Clash Rule Engine — Swift 实现规划

目标（按优先级排序）：
1. **性能 Tier 1**：解析 + 匹配全链路对标 mihomo/clash.meta 的 Go 实现，匹配热路径单次 < 1μs（10 万规则量级），解析 10 万行规则 < 50ms（M 系芯片）。
2. **语言互操作方便**：稳定 C ABI 导出，任何能链接 C 的语言（Go/Rust/Node/Python/Kotlin/Java）零胶水直接调用。
3. **RAM 高效**：10 万条规则编译态 < 5 MB，解析期峰值 < 2× 编译态，热路径零堆分配。

---

## 当前实现状态（Current State）

- **已完成里程碑**：
  - **M1/M2（核心骨架与扁平内存架构）**：基于 Arena + 扁平结构（`ExactEntry` / `SuffixTrie` / `IPNode` Radix / `PortEntry` / `KeywordEntry`），热路径零堆分配（`malloc_count == 0` 已加测试断言），类别并发求值 + `ruleIndex` 仲裁；
  - **M3（规则语义完备）**：已实现全部规则类型（`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR/6`、`SRC-IP-CIDR/6`、`PORT/DST-PORT/SRC-PORT`、`PROCESS-NAME/PATH`、`NETWORK`、`DSCP`、`GEOIP`、`MATCH`）；支持 `AND` / `OR` / `NOT` / `SUB-RULE` 逻辑表达式扁平树求值；支持 `RULE-SET` 外部载入、多格式解析（Classical、Domain payload、IP-CIDR payload、YAML list）及递归展开。
- **测试现状**：58 项单元测试全部通过（运行耗时 ~0.013s，`swift test`）。
- **后续规划**：
  - M3 收尾：mihomo 真实社区语料对拍 Golden tests；
  - M4：`ClashRuleCAPI` 稳定 C ABI 导出（`@c`）、头文件生成、CLI 工具；
  - M5：100k 性能基准（解析 < 50ms / 匹配 < 1μs / 内存 < 5MB）与 CI 门禁。

---

## 0. 核心设计决策（TL;DR）

| 决策点 | 选择 | 理由 |
|---|---|---|
| 对外语义接口 | 稳定 C ABI（Swift 6.3 `@c` 导出），opaque handle | 全语言互通的唯一公约数；SwiftPM 生态内则直接用 Swift API，不经 ABI |
| 匹配语义 | **全体类别并发求值 → 取最小 rule-index** | 保留 Clash「顺序即优先级」语义的同时，把 O(n) 顺序扫描变成 O(1)-ish |
| 数据结构 | 全部 **扁平数组（flat arrays）+ 偏移量句柄**，arena 一次性分配 | 消除 Swift 引用类型开销，缓存友好，可整块 mmap/序列化 |
| 字符串 | 解析期**零拷贝**：字节区间 → 内联 arena + 名称 interning | RAM 决定性因素 |
| 内存布局 | SoA（structure of arrays），不用 enum-with-associated-values 大 union | Swift enum payload 取最大成员大小，会浪费；手动 packed 布局可控 |
| 并发模型 | 编译完成后 **不可变**，read-only 无锁共享 | 一个 arena 构建一次，跨线程自由读 |

---

## 1. 架构总览

```
                    ┌─────────────────────────────────────────┐
                    │            clash-rule (SwiftPM)         │
                    │                                         │
  config/rule 文本  │  ┌──────────┐   ┌───────────┐   ┌──────┐ │      ┌──────────────┐
 ──────────────────►│  │  Parser  │──►│  Compiler │──►│ Arena├─┼─────►│  Matcher API │
  (zero-copy bytes) │  └──────────┘   └───────────┘   └──────┘ │      │  (Swift+C)   │
                    │   流式、无 String 分配    扁平结构构建     │      └──────────────┘
                    │                                         │   ┌──────────────┐
                    │  ┌─────────────────────────────────────┐│   │  C ABI 导出  │
                    │  │ Diagnostics（错误行号/位置，一次性）  ││──►│  clash_rule_*│
                    │  └─────────────────────────────────────┘│   └──────────────┘
                    └─────────────────────────────────────────┘
```

三个阶段严格分离，各自可独立测试与序列化：

1. **Parser**：输入单个 UTF-8 `UnsafeBufferPointer<UInt8>`，产出带位置校验的中间规则流。不产生 `String`，一切以 `(offset, length)` 区间表示。
2. **Compiler**：把规则流按类型编译进 Arena 里的各索引结构；产出一个**不可变、可序列化**的快照。
3. **Matcher**：热路径。输入一次请求的 context（域名/目标 IP/端口/进程），输出 policy handle。零分配。

---

## 2. 内存模型（RAM 高效的关键）

### 2.1 Arena + Flat Arena Region

所有数据落进一个连续内存块（`ContiguousArray<UInt8>` 或 mmap 文件），内部指针一律用 **UInt32 偏移**，不用指针。

> **Swift 6.2+ 类型选型说明**：arena 的写入阶段用 `OutputSpan`/`OutputRawSpan`（SE-0448）替代手写 bump 指针；POD 结构体显式标注 `BitwiseCopyable`（SE-0426）+ `@frozen`，保证布局并使 `Span<T>.bytes` 原始字节视图可用。仅小固定尺寸的表（region header、IPv6 16 字节等）可用 `InlineArray`（SE-0462）；**主体索引结构不用** `InlineArray`（大 N 值类型整块拷贝 + 存在 open bug swiftlang#83774），继续用扁平数组。
>
> **Swift 6.4 增量**（SE-0527，`Containers` 模块）：编译期的 arena 填充缓冲从 `ContiguousArray` 换成 **`RigidArray`（容量可预估、一次分配）或 `UniqueArray`（可增长）**——两者唯一所有权、无 CoW、单块连续堆内存，写入路径省掉引用计数检查；冻结后移交，mmap 路径仍自管。

```swift
/// 编译态快照——全部 POD，可 memcpy 可 mmap
/// 结构体需 @frozen + BitwiseCopyable（SE-0426）
struct CompiledRules {
    // 头部：各 region 的 (offset, count)，UInt32
    var regionTable: RegionTable
    // 后续是各 region 内容：
    // [0] stringArena   : UInt8 平铺（policy 名、域名、进程名）
    // [1] exactDomain   : 开放寻址哈希表 → policy handle
    // [2] suffixTrie    : 扁平 trie（见 2.3）
    // [3] keywordIndex  : 子串匹配索引（Aho-Corasick 扁平版，仅当 keyword 多时启用）
    // [4] ipTrie        : IPv4/IPv6 扁平基数 trie（见 2.4）
    // [5] portRanges    : 排序区间数组（二分）
    // [6] processIndex  : 哈希表
    // [7] ruleTable     : 逻辑规则（AND/OR/NOT/SUB-RULE）的表达式栈
}
```

**为什么用 arena + 偏移而不是 Swift 原生集合：**
- Swift `Array<Struct>` 每条规则也行，但跨结构指针（如 trie 节点 → stringArena）没法表达，除非用 class（引用计数开销 + 散乱堆分配）。
- 扁平化后整个快照是**单块内存**：构建完可整块移交/序列化/`mmap`，iOS 上还能直接用 mmap 避免驻留。

### 2.2 单条规则的编译态大小（预算）

经典规则（DOMAIN-SUFFIX, IP-CIDR 等）编译后 ~16–24 字节：

```
[ruleType: UInt8][flags: UInt8][policyID: UInt16]  4B 头
[payload: UInt32]  // 指向 stringArena 的区间 或 trie 叶子 or 端口对
[ruleIndex: UInt32]  // 用于优先级判定
```

10 万条 → 约 2.5 MB 全量，远低于 Go 实现（map[string]Policy + 切片，通常 20–40 MB）。

### 2.3 域名后缀 trie（DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD）

**逆序 trie**（从叶子向根存 `com`、`example.com`），扁平化为：

```
每节点 16B：
[childrenStart: UInt32][childCount: UInt16][flags: UInt16]
[labelOffset: UInt32][labelLen: UInt16][policyID: UInt16]
```

- 查找：输入域名从右往左逐 label 下走，命中 `flags.isSuffix` 即匹配；同时记录最长匹配（DOMAIN-SUFFIX 贪婪 vs 具体规则先出现的语义由 rule-index 仲裁）。
- 10 万域名 → 节点数通常 < 15 万 → ~2.4 MB。

DOMAIN-KEYWORD 数量少时（< 64）直接线性比对（cache 极佳）；多时编译成 Aho-Corasick 扁平自动机。

### 2.4 IP CIDR 索引

扁平基数 trie（binary Patricia），IPv4 / IPv6 各一棵：

```
每节点 12B：
[left: UInt32][right: UInt32][bits: UInt16]
[isTerminal: UInt8][policyID: UInt8+padding]
```

叶子带 rule-index，先命中最长前缀；同一前缀多条规则取最小 index。`SRC-IP-CIDR` 另一棵小 trie。GEOIP 走编译期下发的静态国家码集合（bitmap per country → policy）。

### 2.5 端口

`DST-PORT / SRC-PORT` 排序数组（每区间 8B：`lo: UInt16, hi: UInt16, policyID: UInt32`），二分查找。

---

## 3. 匹配语义：如何同时做到 O(1) 和保持顺序优先级

Clash 语义：**规则文件顺序即优先级，第一条匹配生效**。朴素做法是逐条扫，10 万条最坏 10 万次。

正确做法（mihomo 的 RuleSet 优化同理）：

1. 编译时每条规则记录 `ruleIndex`。
2. 请求到来时，**并发**查询所有类别索引：
   - exact-domain hash lookup：O(1)
   - suffix trie：O(domain labels)
   - keyword：O(len) / AC 自动机 O(len)
   - IP trie：O(prefix bits)
   - ports：O(log n)
   - process：O(1)
3. 每个类别各自返回「本类内命中的最小 ruleIndex」。
4. 全类别取最小，即整体第一条匹配 → 语义等价，且实际只需 ~6 次「亚线性」查询。

逻辑规则（AND/OR/NOT）单独编译成表达式树，只在上述失败后才参与求值（它们数量通常 < 5%）。

**热路径约束**：Matcher 所有函数 `@inlinable`，输入输出全是值类型/handle，无 `String`、无堆分配、无上锁。请求 context 用一个栈上 struct 承载。

> **入参抽象**：热路径的域名/IP 字节入参统一用 `Span<UInt8>` / `RawSpan`（SE-0447/SE-0456），容器无关且借用安全；Span 的 non-escapable 约束恰好匹配"Matcher 不存储输入"的语义。错误处理用 typed throws（SE-0413）避免错误装箱。跨线程共享仅经 `Sendable` 快照。

---

## 4. 性能手段清单（Swift 特化）

- **编译选项**：`SWIFT_OPTIMIZATION_LEVEL=-O` + `-cross-module-optimization`（跨模块内联）、`-strict-concurrency=complete`、`Whole-Module Optimization`。
- **@frozen struct**：公共 layout 的 POD 结构体全部 `@frozen`，消除运行时布局检查。
- **避免 Swift 语义糖**：热路径不用 `String`（改用 UTF-8 buffer + `memcmp`），不用 `Optional` in hot loop（branchless 处理哨兵值），不用 `indirect enum`。
- **哈希**：自实现 FNV-1a / wyhash（Swift 原生 Hashable 有随机种子，不可用于索引结构确定性构建，也更快）。
- **Allocation**：整库只有 Parser 的 arena 是唯一堆分配点；Matcher 分配次数 = 0（可写测试断言 `malloc_count == 0`）。
- **SIMD**：域名逐 label 比对用 `SIMD8<UInt8>`/`memchr` 加速；keyword 用 AC 自动机时也保持标量，避免过度优化。
- **Benchmark 纪律**：swift-benchmark 覆盖 parse / compile / match 三轴，回归 CI 阻断。

### Swift 6.4 增量手段

- **SE-0507 `borrow` / `mutate` accessors**：`CompiledRules` 的 region 以 borrowing 计算属性直出 `Span`（如 `suffixTrieSpan`），Matcher 内部传递不再层层闭包。
- **SE-0524 `withTemporaryAllocation`**：Parser scratch（label 拆分缓冲、哈希 build 临时区）交给 OutputSpan 封装，初始化/清理含 throw 路径由类型系统保证。
- **SE-0527 `RigidArray` / `UniqueArray`（`Containers` 模块）**：编译期缓冲唯一所有权、无 CoW，写入路径免引用计数检查（见 2.1）。
- **`@diagnose`**：核心模块将 unsafe/并发类 warning 升级为 error，作为 CI 纪律。
- **预期 6.5 落地、暂不依赖**：SE-0516 `Iterable`（Span/InlineArray 的 for-in 遍历）、SE-0515（reduce 产出 noncopyable）——LSG 2026-08 状态更新将其列入 6.5。

---

## 5. 互操作层（C ABI）

### 5.1 API 表面（稳定 ABI，C 语义）

```c
// Opaque handle，背后是 immutable snapshot
typedef struct clash_rule_engine_s* clash_rule_engine_t;

clash_rule_engine_t clash_rule_engine_create(
    const uint8_t* rule_bytes,    // 原始规则文本（UTF-8）——标识符避开 bytes（见 9 风险表）
    size_t len,
    clash_rule_error* out_err);   // 错误码 + 行号

clash_rule_error clash_rule_engine_match(
    clash_rule_engine_t eng,
    const clash_rule_request* req, // C struct：domain/IP/port/process
    uint32_t* out_policy_id);      // 返回 interned policy 名 ID

size_t clash_rule_engine_policy_name(
    clash_rule_engine_t eng, uint32_t policy_id,
    uint8_t* buf, size_t buf_cap);  // 拿 policy 名，避免 String ABI

void clash_rule_engine_destroy(clash_rule_engine_t eng);
```

- **错误码 + 行号** 返回，不返回 Swift String。
- **policy 用 interned ID**：配置期把 policy 名 `interning`，调用方按 ID 比对（O(1)），需要名字时再显式 `policy_name`。

### 5.2 各语言接入难度评估

| 语言 | 方式 | 额外工作 |
|---|---|---|
| Swift (Apple) | SwiftPM 直接依赖 | 零 |
| Go | cgo 链接 dylib + 生成头文件 | 一个薄 wrapper |
| Rust | `-sys` crate + bindgen | 自动生成 |
| Node / Python / Electron | N-API / cffi 走 C ABI | 各自绑定 |
| iOS 内嵌 | 静态 framework，SwiftPM binary target | 零 |

### 5.3 Swift/C 互操作实现（Swift 6.3）

- 用 Swift 6.3 的 **`@c` 属性**（取代非正式的 `@_cdecl`）导出 C 符号，头文件随包分发（SE-0541 Flexible Swift/C Interoperability for Packages）。
- 生命周期：`create` / `destroy` 手动，文档标注非线程安全的创建 + 线程安全的 match（不可变快照）。可选用 SE-0544（non-Copyable deinit 中的消费）把 Swift 侧 handle 建成 `~Copyable` 类型，destroy 语义交给编译器，C 侧仍手动。

### 5.4 SwiftPM 结构

```
clash-rule/
├── Package.swift
├── Sources/
│   ├── ClashRuleCore/        # 纯 Swift，零第三方依赖
│   │   ├── Parser/
│   │   ├── Compiler/
│   │   ├── Structures/       # FlatTrie, FlatRadix, FlatHashMap, Arena
│   │   └── Matcher/
│   ├── ClashRuleCAPI/        # @c 导出层（唯一 ABI 面）
│   ├── ClashRuleNIO/         # 可选：NIO ByteBuffer 边界集成（依赖 NIOCore）
│   └── ClashRuleCLI/         # 调试/基准 CLI
├── Tests/
│   ├── UnitTests/
│   ├── GoldenTests/          # 对拍 mihomo 输出
│   └── BenchmarkTests/
└── docs/
```

### 5.5 NIO ByteBuffer 集成（可选 product，零拷贝边界）

swift-nio 2.99+（需 Swift 6.2 编译器）已接入 Span 家族，`ByteBuffer` 与核心 `RawSpan` API 可零拷贝互通：

- **接入**：NIO 宿主传入 `ByteBuffer` → `buffer.readableBytesSpan`（`RawSpan`，`@_lifetime(borrow self)` 借用）→ 直接喂给 Parser 核心入口，无拷贝。
- **边界 only**：核心类型不是 `ByteBuffer`。三个硬理由：
  1. `ByteBuffer` 是 owning + CoW（写入前引用计数检查可能整块拷贝），与「单个不可变快照无锁共享」的所有权模型冲突；
  2. 存储由 NIO allocator 管理，拿不出可整块 `mmap` / 移交给 Go/Rust 宿主的原始内存块，序列化路径走不通；
  3. reader/writer index + 闭包式访问面向网络 I/O 顺序读写，Matcher 的 6 处随机索引访问用 Span 直接借用更干净。
- `ByteBuffer` 的 `writeBytes(RawSpan)` 与 `ByteBuffer(capacity:initializingWith:)`（借 `OutputRawSpan`）说明 NIO 正在跟进同一套原语，未来可低成本深化集成。
- 决策哲学与 `@c` 一致：核心用最窄原语（Span/arena），生态适配全放外围薄层。

---

## 6. 解析器细节

- **输入**：`RawSpan` / `UTF8Span`（SE-0447/SE-0456，Swift 6.2）优先，`UnsafeBufferPointer<UInt8>` 仅作内部 fallback；流式逐行扫描（`memchr('\n')`）。生命周期由 Span 的借用检查保证，入口无需 unsafe 约定。
- **arena 写入**：`OutputSpan`/`OutputRawSpan`（SE-0448）承担 bump 分配语义，`finalize` 一次性移交所有权。
- **词法**：手写状态机，识别 `TYPE,ARG,POLICY` 三段结构（`no-resolve`、`no-traffic` 等 flag 一起处理）。支持 `# 注释`、空白、CRLF。
- **验证**：规则类型白名单、IP/CIDR 合法性、policy 名字符集，出错带行号+列号。
- **错误策略**：fail-fast（可选 collect-all 模式，收集全部错误后一次性报告，用于编辑器集成）。
- **RuleSet 支持**：`RULE-SET,NAME,POLICY` 展开成引用，加载 `.list` 文件（复用同一 Parser）。
- **编码**：只支持 UTF-8（检测到 BOM/非法字节立即报错）。

---

## 7. 测试与验收

| 验收项 | 目标 |
|---|---|
| Golden test | 用 mihomo 解析同一 config，匹配结果 100% 一致（覆盖 DOMAIN/IP/PORT/PROCESS/LOGIC/RULE-SET/GEOIP） |
| 解析性能 | 100k 规则 < 50ms，单核 |
| 匹配性能 | 真实 config 下 miss-heavy 与 hit-heavy 两种负载均 < 1μs/次 |
| RAM | 100k 规则编译态 < 5 MB；解析期峰值 < 10 MB |
| 热路径分配 | `malloc` 计数 = 0 |
| ABI 兼容 | 头文件 + dylib 的符号表稳定，跨 minor 版本不破坏 |

**Golden test 数据来源**：抓 mihomo/clash.meta 真实社区 config（ACL4SSR、blackmatrix7 等规则集）做语料。

---

## 8. 里程碑

- **M1（骨架可跑）**：Swift 6.4 toolchain 基线；Parser + 基础类型（DOMAIN/SUFFIX/IP-CIDR/PORT/MATCH）+ Swift 匹配 API + 单测。~3–5 天。
- **M2（内存架构落地）**：Arena + flat trie + radix + hash 全部换成扁平结构，序列化快照，RAM 达标。~3–5 天。
- **M3（语义完备）**：逻辑规则 / SUB-RULE / RULE-SET / GEOIP / PROCESS / SRC 类，Golden test 对拍 mihomo。~5–7 天。
- **M4（互操作层）**：C ABI + 头文件 + Go cgo 示例 + CLI。~2–3 天。
- **M5（性能打磨）**：benchmark、CLO/内联调优、SIMD、分配审计。~3 天。

---

## 9. 风险与备选

| 风险 | 缓解 |
|---|---|
| Toolchain 基线较高（`@c` 需 6.3+，`Containers`/SE-0507/SE-0524 需 6.4+） | 锁定 Swift 6.4 toolchain 为最低要求（2026-09 发布，各平台均可安装）；若宿主环境受限，Core 回退 6.2 子集（Span 全家可用），仅 C 层和 `RigidArray` 两处 feature-gate |
| ~~`@_cdecl` 非正式特性~~ | **已解除**：Swift 6.3 起用正式的 `@c` 属性（2026-03 发布），SE-0541 提供包级 Swift/C 互操作；仅当需支持 Swift < 6.3 时才回退 `@_cdecl` |
| Swift 运行时需要随 dylib 分发（跨语言使用） | iOS 上由系统提供；Linux 上静态链接 Swift 运行时（`-static-stdlib`）或文档声明依赖 |
| Clash 规则语义边角（no-resolve、MATCH 兜底顺序） | Golden test 用 mihomo 作为 oracle，不一致以 mihomo 为准 |
| GEOIP 数据库依赖 | 引擎只做「国家码 → policy」索引，不加载 MMDB；由宿主提供 IP→country 回调（C 函数指针）注入 |
| `InlineArray` 尚有 open bug（栈拷贝内容变化，swiftlang#83774） | 仅用于小固定 N（header、16 字节 IPv6）；不上核心索引结构；CI 加回归断言 |
| Swift 6.2 `Data.bytes: RawSpan`（SE-0456）与生成头文件标识符冲突（uniffi-rs#2803 同款问题） | 生成 C 头文件时避免把字段/函数参数命名为 `bytes` |

---

## 10. Swift Evolution 类型选型对照（2026-10）

| 用途 | 原选型 | 现选型 | Proposal / 版本 | 说明 |
|---|---|---|---|---|
| 解析输入 | `UnsafeBufferPointer<UInt8>` | `RawSpan` / `UTF8Span` | SE-0447, SE-0456 · Swift 6.2 | 借用安全、non-escaping；`Data.bytes` 已直接返 `RawSpan` |
| Arena 写入 | 手写 bump 指针 | `OutputSpan` / `OutputRawSpan` | SE-0448 · Swift 6.2 | 初始化状态由类型系统保证 |
| 热路径字节入参 | `ArraySlice<UInt8>` | `Span<UInt8>` | SE-0447 · Swift 6.2 | 容器无关；non-escapable 恰好匹配"不存储输入" |
| POD 结构 | 仅 `@frozen` | `+ BitwiseCopyable` | SE-0426 | 原始字节视图（`Span.bytes`）的前提；复制为 memcpy |
| C ABI 导出 | `@_cdecl` | `@c` + SE-0541 包互操作 | Swift 6.3（2026-03） | 正式特性，风险解除 |
| 错误处理 | `throws` | typed throws | SE-0413 | `throws(RuleParseError)`，无装箱 |
| 热加载换快照 | 锁 / 库外原子 | `Mutex` / `Atomic`（`Synchronization`） | SE-0433, SE-0438 · 6.1/6.2 | 仅换入换出用；match 路径仍无锁 |
| 小固定尺寸表 | `ContiguousArray` | `InlineArray<T, N>`（小 N） | SE-0462 | 大 N 不用（值类型整块拷贝 + open bug #83774） |
| 编译期缓冲 | `ContiguousArray`（CoW） | `RigidArray` / `UniqueArray` | SE-0527 · Swift 6.4（`Containers`） | 唯一所有权无 CoW，写入免引用计数检查 |
| Parser scratch | 手管 `UnsafeMutablePointer` | `withTemporaryAllocation` | SE-0524 · Swift 6.4 | OutputSpan 封装，含 throw 路径的初始化安全 |
| Span 属性出口 | 闭包传递 | `borrow` / `mutate` accessors | SE-0507 · Swift 6.4 | region 属性直出 Span，借用检查合法化 |
| NIO 生态边界 | — | `ByteBuffer.readableBytesSpan` 借用入核心 | swift-nio 2.99+（Swift 6.2 编译器） | 可选 `ClashRuleNIO` product，边界零拷贝；核心不依赖 NIO |
| 大数组主体 / arena 主体 | `ContiguousArray` / mmap | **维持不变** | — | Evolution 无对应替代品；Span 是视图抽象，不解决存储布局 |
| 索引哈希 | 自实现 wyhash/FNV | **维持不变** | — | `Hashable` 随机种子，不能用于确定性索引结构 |

补充：SE-0494（`isTriviallyIdentical`，6.4）与我们的单 arena 快照设计无交集，跳过；Embedded Swift（6.4 有多项改进）作为 M5 可选实验——Core 满足子集约束（无反射、静态类型已知），可产出极小二进制，但会限制 C API 动态性，不进主线。6.4 对 Wasm/C++/Java 互操作的改进记为未来方向（Wasm 目标对浏览器场景是潜在加分项）。
