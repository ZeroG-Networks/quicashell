// QUIC packet creation, parsing, and manipulation.

const std = @import("std");

pub const ConnectionId = struct {
    const Self = @This();

    pub fn init() ConnectionId {
        return ConnectionId{};
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
    //dconn_id: ConnectionId,
    sconn_id_len: u8 = undefined,
    //sconn_id: ConnectionId,

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
        self.version = 0x00000001; // TODO QUIC v1 constant
        self.dconn_id_len = 0;
        self.sconn_id_len = 0;
    }

    // Serialize the packet into a given buffer.
    pub fn serialize(self: Self, buf_stream: *std.Io.Writer) !void {
        var first_byte: u8 = self.version_specific_bits & 0x7F;
        if (self.use_long_form) first_byte |= 0x80;

        try buf_stream.writeByte(first_byte);
        try buf_stream.writeByte(@as(u8, @intCast(self.version >> 24)));
        try buf_stream.writeByte(@as(u8, @intCast(self.version >> 16)));
        try buf_stream.writeByte(@as(u8, @intCast(self.version >> 8)));
        try buf_stream.writeByte(@as(u8, @intCast(self.version & 0xFF)));
        try buf_stream.writeByte(self.dconn_id_len);
        try buf_stream.writeByte(self.sconn_id_len);
        // TODO
    }

    // Read this packet from a socket.
    // TODO
};

// TODO: support ability to aggregate multiple QUIC packets into a datagram,
// and to parse datagrams that contain multiple packets, per 8999.
