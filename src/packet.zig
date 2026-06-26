// QUIC packet creation, parsing, and manipulation.

const std = @import("std");

const tls = @import("tls.zig");
const varint = @import("varint.zig");

const QuicVersionNegotiation: u32 = 0x00000000;
const QuicVersion1: u32 = 0x00000001;

const DefaultDestConnIdLen: u8 = 8;
const DefaultSourceConnIdLen: u8 = 0;

const QuicFrameType = enum(u8) {
    CryptoFrameType = 0x06,
};

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

// Write the given data as the content of a CRYPTO frame.
fn write_crypto_frame(data: []u8, offset: u64, writer: *std.Io.Writer) !void {
    try varint.writeVarInt(@intFromEnum(QuicFrameType.CryptoFrameType), writer);
    try varint.writeVarInt(offset, writer);
    try varint.writeVarInt(data.len, writer);
    try writer.writeAll(data);
}

const QuicPktType = enum(u8) {
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
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

    quic_pkt_type: QuicPktType = undefined,

    // TODO: refactor how this works.
    crypto_payloads: std.ArrayList([]u8) = .empty,

    pub fn init() QuicPacket {
        return QuicPacket{};
    }

    // Make the packet a QUIC version 1 Initial packet.
    pub fn make_initial(self: *Self, rand: [32]u8, alloc: std.mem.Allocator) !void {
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

        self.quic_pkt_type = QuicPktType.Initial;

        // Make a TLS ClientHello.
        var buf = std.Io.Writer.Allocating.init(alloc);
        defer buf.deinit();
        var client_hello = tls.ClientHello.init(rand);
        try client_hello.serialize(&buf.writer);
        try self.crypto_payloads.append(alloc, buf.written());
    }

    // Serialize the packet into a given buffer.
    // TODO: only support long headers ATM
    pub fn serialize(self: Self, buf: *std.Io.Writer.Allocating) !void {
        const length: u32 = 1200; // TODO: use a real value.
        const pktnum: u32 = 42; // TODO: use a real value.

        var first_byte: u8 = self.version_specific_bits & 0x7F;
        if (self.use_long_form) first_byte |= 0x80;

        try buf.writer.writeByte(first_byte);
        try buf.writer.writeByte(@as(u8, @intCast(self.version >> 24)));
        try buf.writer.writeByte(@as(u8, @intCast(self.version >> 16)));
        try buf.writer.writeByte(@as(u8, @intCast(self.version >> 8)));
        try buf.writer.writeByte(@as(u8, @intCast(self.version & 0xFF)));
        try buf.writer.writeByte(self.dconn_id_len);
        try buf.writer.writeAll(self.dconn_id.bytes);
        try buf.writer.writeByte(self.sconn_id_len);
        if (self.sconn_id_len != 0)
            try buf.writer.writeAll(self.sconn_id.bytes);

        if (self.quic_pkt_type == QuicPktType.Initial) {
            try buf.writer.writeByte(0); // no token present.
            try varint.writeVarInt(length, &buf.writer);
            try varint.writeVarInt(pktnum, &buf.writer);

            for (self.crypto_payloads.items) |crypto| {
                try write_crypto_frame(crypto, 0, &buf.writer);
            }
        }
    }

    // Read this packet from a socket.
    // TODO
};

// Section 5.2 of RFC 9001 - Initial packets use secrets derived from the
// destination connection ID field from the clients first Initial packet.
//fn initial_secret(client_dcid: []u8) []u8 {
//    const initial_salt = [_]u8{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
//    return hkdfExtract(initial_salt, client_dcid);
//}

// TODO: packet protection RFC 9001
// Initial packets use AEAD_AES_128_GCM with keys derived from the destination connection ID of the first initial packet sent by the client.
//
//

// TODO: support ability to aggregate multiple QUIC packets into a datagram,
// and to parse datagrams that contain multiple packets, per 8999.
//
// Generate the header protection mask for the only supported AES-ECB option.
//fn header_protection(hp_key: []u8, sample: [16]u8) [5]u8 {
//    return [5]u8{0x00, 0x00, 0x00, 0x00, 0x00};
//}
//
// Apply header protection to a serialized and AEAD protected packet.
//pub fn header_protect(pkt: []u8) !void {
//    const mask = header_protection(hp_key, sample);
//    pn_length = (pkt[0] & 0x03) + 1;
//    if ((pkt[0] & 0x80) == 0x80) { // Long header.
//        pkt[0] ^= mask[0] & 0x0f;
//    } else {
//        pkt[0] ^= mask[0] & 0x1f;
//    }
//    for (pn_offset..pn_offset+pn_length) |i| {
//        pkt[i] ^= mask[1+i];
//    }
//}
