// Variable-length integer encodeing from Section 16 of RFC 9000.
//
const std = @import("std");
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const VarIntError = error{TooBig};

// Return the number of bytes a value will be encoded to minimally.
pub fn lenOfVarInt(value: u64) VarIntError!u8 {
    if (value < 64) return 1;
    if (value < 16_383) return 2;
    if (value < 1_073_741_823) return 4;
    if (value < 4_611_686_018_427_387_903) return 8;
    return VarIntError.TooBig;
}

// Return a byte with the encoded minimal length.
pub fn encodedLen(value: u64) VarIntError!u8 {
    if (value < 64) return 0x00;
    if (value < 16_383) return 0x40;
    if (value < 1_073_741_823) return 0x80;
    if (value < 4_611_686_018_427_387_903) return 0xC0;
    return VarIntError.TooBig;
}

// Write out an encoded value.
pub fn writeVarInt(value: u64, writer: *std.Io.Writer) !void {
    const myValue = std.mem.nativeToBig(u64, value);
    const len = try lenOfVarInt(value);
    const elen = try encodedLen(value);
    for (std.mem.asBytes(&myValue), 0..) |byte, i| {
        if (i < 8 - len) continue;
        if (i == 8 - len) try writer.writeByte(elen | byte);
        if (i > 8 - len) try writer.writeByte(byte);
    }
}

// Examples from RFC 9000, Appendix A.1.
test "one-byte encode" {
    var buf = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer buf.deinit();
    try writeVarInt(37, &buf.writer);
    try expectEqualSlices(u8, buf.written(), &[_]u8{0x25});
}
test "two-byte encode" {
    var buf = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer buf.deinit();
    try writeVarInt(15_293, &buf.writer);
    try expectEqualSlices(u8, buf.written(), &[_]u8{ 0x7b, 0xbd });
}
test "four-byte encode" {
    var buf = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer buf.deinit();
    try writeVarInt(494_878_333, &buf.writer);
    try expectEqualSlices(u8, buf.written(), &[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d });
}
test "eight-byte encode" {
    var buf = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer buf.deinit();
    try writeVarInt(151_288_809_941_952_652, &buf.writer);
    try expectEqualSlices(u8, buf.written(), &[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c });
}

// Return a decoded value from the encoded bytes.
// Note: Assumes at least the correct # of bytes in encoded.
pub fn readVarInt(encoded: []const u8) !u64 {
    var value: u64 = encoded[0];
    const length: u8 = @as(u8, 1) << @as(u3, @truncate(value >> 6));
    value &= 0x3F;
    var i: usize = 1;
    while (i < length) : (i += 1) {
        value = (value << 8) | encoded[i];
    }
    return value;
}

// Return the length in bytes based on encoding in first byte.
pub fn decodedLen(encoded: u8) usize {
    return @as(u8, 1) << @as(u3, @truncate(encoded >> 6));
}

test "length decoding" {
    try expectEqual(decodedLen(0), 1);
    try expectEqual(decodedLen(1 << 6), 2);
    try expectEqual(decodedLen(2 << 6), 4);
    try expectEqual(decodedLen(3 << 6), 8);
}

// Examples from RFC 9000, Appendix A.1.
test "one-byte decode" {
    const bytes = [_]u8{0x25};
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(37, val);
}
test "two-byte decode" {
    const bytes = [_]u8{ 0x7b, 0xbd };
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(15_293, val);
}
test "two-byte decode #2" {
    const bytes = [_]u8{ 0x40, 0x25 };
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(37, val);
}
test "four-byte decode" {
    const bytes = [_]u8{ 0x9d, 0x7f, 0x3e, 0x7d };
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(494_878_333, val);
}
test "eight-byte decode" {
    const bytes = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(151_288_809_941_952_652, val);
}
