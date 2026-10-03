/// Growable byte buffer for compile-phase arenas.
/// Offsets handed out are stable for the lifetime of the snapshot.
/// Compile-phase storage only — the matcher hot path never touches this type.
struct ByteArena: Sendable {
    private(set) var bytes: ContiguousArray<UInt8> = []

    var count: Int { bytes.count }

    mutating func append(_ byte: UInt8) -> UInt32 {
        let offset = UInt32(bytes.count)
        bytes.append(byte)
        return offset
    }

    /// Copies `raw[range]` and returns the offset it now lives at.
    mutating func append(_ range: Range<Int>, in raw: UnsafeRawBufferPointer) -> UInt32 {
        let offset = UInt32(bytes.count)
        bytes.append(contentsOf: raw[range])
        return offset
    }

    mutating func append(_ newBytes: some Sequence<UInt8>) -> UInt32 {
        let offset = UInt32(bytes.count)
        bytes.append(contentsOf: newBytes)
        return offset
    }
}
