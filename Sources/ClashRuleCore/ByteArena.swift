/// Growable byte buffer for compile-phase arenas.
/// Offsets handed out are stable for the lifetime of the snapshot.
/// Compile-phase storage only — the matcher hot path never touches this type.
struct ByteArena: Sendable {
    private var _bytes: ContiguousArray<UInt8> = []

    /// Borrow and mutate accessors (SE-0507): in-place access to stored buffer
    /// without copy-on-write overhead or coroutine cost.
    var bytes: ContiguousArray<UInt8> {
        borrow { _bytes }
        mutate { &_bytes }
    }

    var count: Int { _bytes.count }

    mutating func append(_ byte: UInt8) -> UInt32 {
        let offset = UInt32(bytes.count)
        bytes.append(byte)
        return offset
    }

    /// Copies `span` and returns the offset it now lives at.
    mutating func append(_ span: Span<UInt8>) -> UInt32 {
        let offset = UInt32(bytes.count)
        bytes.append(copying: span)
        return offset
    }

    mutating func append(_ newBytes: some Sequence<UInt8>) -> UInt32 {
        let offset = UInt32(bytes.count)
        bytes.append(contentsOf: newBytes)
        return offset
    }
}
