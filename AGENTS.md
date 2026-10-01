# AGENTS.md — clash-rule

Swift implementation of a Clash rule parsing/matching engine. **Planning stage: no code exists yet** — only `docs/PLAN.md` (in Chinese), which is the design source of truth. Read it before writing anything.

## Current state

- **M1 milestone is implemented**: `Package.swift` + `ClashRuleCore` (Parser / Compiler / flat structures / Matcher) + Swift Testing suite. No C ABI, NIO target, RULE-SET/GEOIP/logic rules yet (see `PLAN.md` §8 milestones).
- Commands: `swift build`, `swift test` (27 tests, Swift Testing framework, `@testable import ClashRuleCore`). Debug fixture helpers live at the top of `Tests/ClashRuleCoreTests/CoreTests.swift`.
- Not committed blindly: run `swift test` before every commit; performance/RAM targets (§7) are CI-blocking once benchmarks land in M5.

## Toolchain reality check (verified on this machine)

- Toolchain: Swift 6.4 (Xcode 27). Package deployment target: macOS 15 / iOS 18 — required for `UInt128`.
- **SE-0456 span convenience properties (`Array.span`, `Data.bytes`) are gated to macOS 26+ / iOS 26+** — an Apple-OS-runtime gate only (apps use the OS-shipped Swift runtime on Darwin). **Linux has no OS-version gate**: those properties work with any Swift 6.2+ toolchain, and the `@available(macOS 26, iOS 26, *)` annotations are inert there. So Linux consumers get the full Span zero-copy path today; the `UnsafeRawBufferPointer`/`UnsafeBufferPointer<UInt8>` baseline overloads exist for Apple hosts below 26. Don't "clean up" the buffer-pointer API away.
- `ContiguousArray` is not `Comparable`; `[UInt8]` is not `Comparable` either — use `lexLess` (Bytes.swift), not `.sorted()`.

## Non-negotiable design constraints

These come from `PLAN.md` and constrain every future code decision. Violating them breaks the three stated goals (tier-1 performance / easy FFI / low RAM):

- **Core (`ClashRuleCore`) has zero third-party dependencies.** NIO interop goes in a separate optional `ClashRuleNIO` product (§5.5).
- **Storage = arena + flat arrays + UInt32 offsets.** Never use classes, `enum`-with-associated-values, or `Array` in compiled indexes. Flat trie / flat radix / flat hashmap per §2.
- **No `String`, no heap allocation, no locks in the matcher hot path.** Matcher allocation count must be 0 (asserted by test). Bytes move as `Span<UInt8>` / `RawSpan`, never `String`/`ArraySlice`.
- **Match semantics**: rule file order = priority. Implementation is concurrent per-category lookup, winner = min `ruleIndex` (§3). Don't "simplify" this to sequential scanning.
- **Policy names are interned** to `UInt32` IDs at compile time; the hot path only deals with IDs.
- **Toolchain baseline: Swift 6.4.** `@c` for the C ABI (not `@_cdecl`), typed throws, `BitwiseCopyable` + `@frozen` on POD structs, `RigidArray`/`UniqueArray` for compiler-phase buffers. `InlineArray` only for small fixed N (open bug swiftlang#83774) — never in core indexes.
- **`ClashRuleCore` is immutable after compile.** Mutable state is compile-phase only; hot-reload swaps whole snapshots (§3, §10).

## Gotchas

- Generated C headers: never name a field or parameter `bytes` (collides with Swift 6.2 `Data.bytes: RawSpan`; see uniffi-rs#2803).
- Golden tests must treat **mihomo as the oracle** for rule semantics — if we disagree with mihomo, we are wrong.
- Performance/RAM targets are acceptance criteria, not aspirations (§7): 100k rules parse < 50ms, match < 1μs, compiled < 5MB. Benchmarks (parse/compile/match) gate CI.
- Docs are written in Chinese; keep that convention.
