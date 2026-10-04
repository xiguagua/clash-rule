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

/// FNV-1a 64-bit. Deliberately not `Hashable`'s seeded hash: index structures
/// must build deterministically (docs/PLAN.md §4).
func fnv1a(_ bytes: UnsafeBufferPointer<UInt8>) -> UInt64 {
    var h: UInt64 = 0xcbf2_9ce4_8422_2325
    for b in bytes { h = (h ^ UInt64(lowerByte(b))) &* 0x100000001b3 }
    return h
}

func fnv1a(_ bytes: [UInt8]) -> UInt64 {
    bytes.withUnsafeBufferPointer { fnv1a($0) }
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

public func packCountryCode(_ buf: UnsafeBufferPointer<UInt8>) -> UInt32 {
    var code: UInt32 = 0
    for b in buf {
        guard code <= 0x00FF_FFFF else { break }
        code = (code << 8) | UInt32(upperByte(b))
    }
    return code
}
