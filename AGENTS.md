# AGENTS.md — clash-rule

Swift implementation of a Clash rule engine. Source of truth: `docs/PLAN.md`.

## Commands & Status

- **Status**: See `docs/PLAN.md` § Current State for current milestone.
- **Toolchain**: Swift 6.4+ (`swift-tools-version:6.4`, `.swiftLanguageMode(.v6)`); platforms macOS 27 / iOS 27 / tvOS 27 / watchOS 27 / visionOS 27.
- **Test**: `swift test` (required before every commit).

## Hard Constraints

- **Zero dependencies**: `ClashRuleCore` has zero third-party dependencies.
- **Storage**: Arena + flat POD arrays + `UInt32` offsets only. No classes, no enum payloads, no heap collections in compiled indexes.
- **Hot path**: Matcher heap allocations = 0 (asserted by test). No `String`, no locks; bytes as `Span<UInt8>` / `RawSpan`.
- **Match semantics**: Concurrent per-category lookup; winner = min `ruleIndex` (file order priority).
- **Interning**: Policy names interned to IDs at compile time.
- **Immutability**: `ClashRuleCore` snapshots are read-only and thread-safe once compiled.

## Gotchas

- **Span API**: Standardized on Swift 6.4+ `Span<UInt8>` / `RawSpan` first-class primitives throughout the parser and matcher. No backward compatibility fallbacks (no UnsafeBufferPointer overloads).
- **Comparison**: `[UInt8]` / `ContiguousArray` are not `Comparable`; use `lexLess` (`Bytes.swift`).
- **Oracle**: Golden tests treat **mihomo as the oracle** for rule semantics.
- **C ABI**: Never name a C header field/parameter `bytes` (name collision with `Data.bytes`).
- **Docs**: Keep documentation in Chinese.
