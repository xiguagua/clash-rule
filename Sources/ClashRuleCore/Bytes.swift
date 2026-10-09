/// Shared byte helpers. All hot-path byte handling goes through these —
/// no `String`, no `ArraySlice` in the matcher (docs/PLAN.md §4).

func lowerByte(_ b: UInt8) -> UInt8 {
    b >= 0x41 && b <= 0x5A ? b &+ 0x20 : b
}

func upperByte(_ b: UInt8) -> UInt8 {
    b >= 0x61 && b <= 0x7A ? b &- 0x20 : b
}

/// Lexicographic byte-array ordering. (`Array` is not `Comparable`.)
func lexLess(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    let n = Swift.min(a.count, b.count)
    for i in 0..<n where a[i] != b[i] { return a[i] < b[i] }
    return a.count < b.count
}

/// FNV-1a 64-bit 参数。编译期（Compiler.swift）与查询期共用，改动必须同时作用于两端。
enum FNV1a {
    static let offsetBasis: UInt64 = 0xcbf2_9ce4_8422_2325
    static let prime: UInt64 = 0x0000_0100_0000_01B3

    @inline(__always)
    static func step(_ hash: UInt64, _ lowered: UInt8) -> UInt64 {
        (hash ^ UInt64(lowered)) &* prime
    }
}

/// FNV-1a 64-bit. Deliberately not `Hashable`'s seeded hash: index structures
/// must build deterministically (docs/PLAN.md §4).
func fnv1a(_ bytes: Span<UInt8>) -> UInt64 {
    var h = FNV1a.offsetBasis
    let count = bytes.count
    for i in 0..<count {
        h = FNV1a.step(h, lowerByte(bytes[unchecked: i]))
    }
    return h
}

func fnv1a(_ bytes: [UInt8]) -> UInt64 {
    fnv1a(bytes.span)
}

/// Packs up to 4 ASCII characters into a big-endian UInt32 representation (uppercased).
/// E.g. "CN" -> 0x0000434E, "LAN" -> 0x004C414E.
public func packCountryCode(_ str: String) -> UInt32 {
    packCountryCode(str.utf8)
}

public func packCountryCode<T: Sequence>(_ bytes: T) -> UInt32 where T.Element == UInt8 {
    var code: UInt32 = 0
    for b in bytes {
        guard code <= 0x00FF_FFFF else { break }
        code = (code << 8) | UInt32(upperByte(b))
    }
    return code
}

public func packCountryCode(_ span: Span<UInt8>) -> UInt32 {
    var code: UInt32 = 0
    let count = span.count
    for i in 0..<count {
        guard code <= 0x00FF_FFFF else { break }
        code = (code << 8) | UInt32(upperByte(span[unchecked: i]))
    }
    return code
}

// MARK: - Span batch copy helpers

extension ContiguousArray where Element: BitwiseCopyable {
    @inlinable
    mutating func append(copying span: Span<Element>) {
        span.withUnsafeBufferPointer { buffer in
            self.append(contentsOf: buffer)
        }
    }
}

extension Array where Element: BitwiseCopyable {
    @inlinable
    init(copying span: Span<Element>) {
        self = span.withUnsafeBufferPointer { Array($0) }
    }

    @inlinable
    mutating func append(copying span: Span<Element>) {
        span.withUnsafeBufferPointer { buffer in
            self.append(contentsOf: buffer)
        }
    }
}

