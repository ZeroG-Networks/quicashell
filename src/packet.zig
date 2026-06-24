// QUIC packet creation, parsing, and manipulation.

// TODO: endian stuff

const std = @import("std");

const QuicVersionNegotiation: u32 = 0x00000000;
const QuicVersion1: u32 = 0x00000001;

const DefaultDestConnIdLen: u8 = 8;
const DefaultSourceConnIdLen: u8 = 0;

// Variable-length integer encodeing from Section 16 of RFC 9000.
const VarIntError = error{TooBig};
pub fn lenOfVarInt(value: u64) VarIntError!u8 {
    if (value < 64) return 1;
    if (value < 16383) return 2;
    if (value < 1073741823) return 4;
    if (value < 4611686018427387903) return 8;
    return VarIntError.TooBig;
}
pub fn writeVarInt(value: u64, writer: *std.Io.Writer) !void {
    for (std.mem.asBytes(&value)) |byte| {
        if (byte == 0) continue;
        try writer.writeByte(byte);
    }
}

pub const ConnectionId = struct {
    const Self = @This();

    seqno: u32 = undefined,
    bytes: []const u8 = undefined,

    pub fn init(id: []const u8, seqno: u32) ConnectionId {
        return ConnectionId{
            .seqno = seqno,
            .bytes = id,
        };
    }
    // TODO methods for working with QUIC connection IDs.
};

pub const QuicPacket = struct {
    const Self = @This();

    // Generic contents of a QUIC packet, based on RFC 8999.
    use_long_form: bool = undefined,
    version_specific_bits: u8 = undefined,
    version: u32 = undefined,
    dconn_id_len: u8 = undefined,
    dconn_id: ConnectionId = undefined,
    sconn_id_len: u8 = undefined,
    sconn_id: ConnectionId = undefined,

    pub fn init() QuicPacket {
        return QuicPacket{};
    }

    // Make the packet a QUIC version 1 Initial packet.
    pub fn make_initial(self: *Self) void {
        self.use_long_form = true;
        // In version 1, the version specific bits are:
        // - 1 bit for the fixed bit (1)
        // - 2 bit for the long packet type (0 for Initial)
        // - 2 reserved bits
        // - 2 bits for packet number length
        self.version_specific_bits = 0x40; // make packet number 1 byte (TODO)
        self.version = QuicVersion1;
        self.dconn_id_len = DefaultDestConnIdLen;
        // TODO: nonsense test ID
        const dcid_bytes = [_]u32{ 0x12345678, 0x9ABCDEF0 };
        self.dconn_id = ConnectionId.init(std.mem.sliceAsBytes(dcid_bytes[0..]), 1);
        self.sconn_id_len = DefaultSourceConnIdLen;
        // TODO: left undefined
        //self.sconn_id = ConnectionId.init();
    }

    // Serialize the packet into a given buffer.
    pub fn serialize(self: Self, buf_stream: *std.Io.Writer) !void {
        const length: u32 = 1200; // TODO: use a real value.
        const pktnum: u32 = 42; // TODO: use a real value.

        var first_byte: u8 = self.version_specific_bits & 0x7F;
        if (self.use_long_form) first_byte |= 0x80;

        try buf_stream.writeByte(first_byte);
        try buf_stream.writeByte(@as(u8, @intCast(self.version >> 24)));
        try buf_stream.writeByte(@as(u8, @intCast(self.version >> 16)));
        try buf_stream.writeByte(@as(u8, @intCast(self.version >> 8)));
        try buf_stream.writeByte(@as(u8, @intCast(self.version & 0xFF)));
        try buf_stream.writeByte(self.dconn_id_len);
        try buf_stream.writeAll(self.dconn_id.bytes);
        try buf_stream.writeByte(self.sconn_id_len);
        if (self.sconn_id_len != 0)
            try buf_stream.writeAll(self.sconn_id.bytes);
        // TODO: token support
        try buf_stream.writeByte(0); // no token present.
        try writeVarInt(length, buf_stream);
        try writeVarInt(pktnum, buf_stream);
        // TODO: payload
    }

    // Read this packet from a socket.
    // TODO
};

// TODO: support ability to aggregate multiple QUIC packets into a datagram,
// and to parse datagrams that contain multiple packets, per 8999.
