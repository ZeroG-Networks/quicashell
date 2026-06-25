// Variable-length integer encodeing from Section 16 of RFC 9000.
//
const std = @import("std");
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const VarIntError = error{TooBig};

// Return the number of bytes a value will be encoded to.
pub fn lenOfVarInt(value: u64) VarIntError!u8 {
    if (value < 64) return 1;
    if (value < 16383) return 2;
    if (value < 1073741823) return 4;
    if (value < 4611686018427387903) return 8;
    return VarIntError.TooBig;
}

// Write out an encoded value.
pub fn writeVarInt(value: u64, writer: *std.Io.Writer) !void {
    for (std.mem.asBytes(&value)) |byte| {
        if (byte == 0) continue;
        try writer.writeByte(byte);
    }
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

// Examples from RFC 9000, Appendix A.1.
test "one-byte" {
    const bytes = [_]u8{0x25};
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(37, val);
}
test "two-byte" {
    const bytes = [_]u8{ 0x7b, 0xbd };
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(15_293, val);
}
test "two-byte #2" {
    const bytes = [_]u8{ 0x40, 0x25 };
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(37, val);
}
test "four-byte" {
    const bytes = [_]u8{ 0x9d, 0x7f, 0x3e, 0x7d };
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(494_878_333, val);
}
test "eight-byte" {
    const bytes = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
    const val: u64 = try readVarInt(&bytes);
    try expectEqual(151_288_809_941_952_652, val);
}
