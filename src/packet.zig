// QUIC packet creation, parsing, and manipulation.

const std = @import("std");
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const crypto = @import("crypto.zig");
const frame = @import("frame.zig");
const tls = @import("tls.zig");
const varint = @import("varint.zig");

const QuicVersionNegotiation: u32 = 0x00000000;
const QuicVersion1: u32 = 0x00000001;

const DefaultDestConnIdLen: u8 = 8;
const DefaultSourceConnIdLen: u8 = 0;

const QuicPacketError = error{
    FixedBitError, // Indicates unexpected QUICv1 long header fixed bit.
    PacketTypeError, // Indicates unknown packet type value.
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
};

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

    // Packet number.
    pktnum: u32 = undefined,

    frames: std.ArrayList(frame.QuicFrame) = .empty,

    // TODO: only meaningful for Initial?
    token: ?[]u8 = null,

    // Allocator for temporary buffers needed for crypto, etc.
    alloc: std.mem.Allocator = undefined,

    pub fn init(alloc: std.mem.Allocator) QuicPacket {
        return QuicPacket{
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        self.frames.deinit(self.alloc);
    }

    // Make the packet a QUIC version 1 Initial packet.
    pub fn make_initial(self: *Self, rand: [32]u8) !void {
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
        self.pktnum = 1;

        // Make a TLS ClientHello.
        var buf = std.Io.Writer.Allocating.init(self.alloc);
        defer buf.deinit();
        var client_hello = tls.ClientHello.init(rand);
        try client_hello.serialize(&buf.writer);
        const c = frame.CryptoFrame.init(buf.written(), 0);
        const f = frame.QuicFrame{
            .frame_type = frame.FrameType.CRYPTO,
            .body = frame.QuicFrameBody{ .CRYPTO = c },
        };
        try self.frames.append(self.alloc, f);
    }

    // Compute the packet length value that will go into the header.
    fn get_payload_length(self: Self) !usize {
        var sz: usize = 0;
        for (self.frames.items) |f| {
            sz += try frame.get_length(&f);
        }
        return sz;
    }

    fn find_pn_offset(self: Self) !usize {
        var pn_offset: usize = undefined;

        if (self.use_long_form) {
            const payload_len = try self.get_payload_length();
            const len_of_len = try varint.lenOfVarInt(payload_len);
            pn_offset = 7 + self.dconn_id.bytes.len + self.sconn_id_len + len_of_len;
            if (self.quic_pkt_type == QuicPktType.Initial) {
                var token_len: usize = 0;
                if (self.token != null) token_len = self.token.?.len;
                const token_len_of_len = try varint.lenOfVarInt(token_len);
                pn_offset += token_len_of_len + token_len;
            }
        } else {
            // TODO: abstract to connection ID not destination.
            pn_offset = 1 + self.dconn_id.bytes.len;
        }

        return pn_offset;
    }

    fn find_sample_offset(self: Self) !usize {
        const pn_offset = try self.find_pn_offset();
        return pn_offset + 4;
    }

    // Serialize the packet heder (unprotected) through a writer.
    pub fn serialize_header(self: Self, w: *std.Io.Writer) !void {
        var first_byte: u8 = self.version_specific_bits & 0x7F;
        if (self.use_long_form) first_byte |= 0x80;

        try w.writeByte(first_byte);
        try w.writeByte(@as(u8, @intCast(self.version >> 24)));
        try w.writeByte(@as(u8, @intCast(self.version >> 16)));
        try w.writeByte(@as(u8, @intCast(self.version >> 8)));
        try w.writeByte(@as(u8, @intCast(self.version & 0xFF)));
        try w.writeByte(self.dconn_id_len);
        try w.writeAll(self.dconn_id.bytes);
        try w.writeByte(self.sconn_id_len);
        if (self.sconn_id_len != 0)
            try w.writeAll(self.sconn_id.bytes);

        const len: usize = try self.get_payload_length();
        if (self.quic_pkt_type == QuicPktType.Initial) {
            try w.writeByte(0); // TODO: no token present.
            try varint.writeVarInt(@as(u64, @intCast(len)), w);
            try varint.writeVarInt(self.pktnum, w);
        }
    }

    // Seriaize the packet payload (unprotected) through a writer.
    pub fn serialize_payload(self: Self, w: *std.Io.Writer) !void {
        for (self.frames.items) |f| {
            try frame.write_frame(&f, w);
        }
    }

    // Serialize the packet into a given writer.
    // TODO: only support long headers ATM
    pub fn serialize(self: Self, w: *std.Io.Writer) !void {
        var header = std.Io.Writer.Allocating.init(self.alloc);
        defer header.deinit();
        var pt_payload = std.Io.Writer.Allocating.init(self.alloc);
        defer pt_payload.deinit();

        // TODO: add any padding that may be necessary.

        // Create unprotected header and payload.
        try self.serialize_header(&header.writer);
        try self.serialize_payload(&pt_payload.writer);

        // Apply payload protection.
        // TODO: Replace temp_crypto w/ crypto for Initial, etc.
        var temp_crypto = crypto.QuicCrypto.init(self.dconn_id.bytes);
        var ct_payload: []u8 = try self.alloc.alloc(u8, pt_payload.written().len);
        var tag: [16]u8 = undefined;
        temp_crypto.protectPacket(ct_payload, &tag, pt_payload.written(), header.written(), self.pktnum);
        // TODO: Append the protected payload and tag.
        try w.writeAll(ct_payload);
        try w.writeAll(&tag);

        // Generate the header protection sample.
        const sample_offset = try self.find_sample_offset();
        const sample_len: usize = 16;
        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, ct_payload[sample_offset .. sample_offset + sample_len]);
        // Finally, apply header protection.
        const pn_offset = try self.find_pn_offset();
        try temp_crypto.protectHeader(header.written(), sample, pn_offset);
    }

    // Read this packet from a buffer, e.g. received from a UDP socket.
    // TODO

    // Decode a packet header; return number of bytes read.
    // TODO: Only long headers supported.
    pub fn decode_header(self: *Self, buf: []const u8) !usize {
        var bytes_read: usize = 0;
        // TODO: Validate minimal length input.
        self.use_long_form = buf[0] & 0x80 == 0x80;
        self.version_specific_bits = buf[0] & 0x7F;
        self.version = std.mem.readInt(u32, buf[1..5], .big);
        self.dconn_id_len = buf[5];
        self.dconn_id = ConnectionId.init(buf[6 .. 6 + self.dconn_id_len], 0);
        bytes_read += 6 + self.dconn_id_len;
        self.sconn_id_len = buf[bytes_read];
        bytes_read += 1;
        self.sconn_id = ConnectionId.init(buf[bytes_read .. bytes_read + self.sconn_id_len], 0);
        bytes_read += self.sconn_id_len;

        // For QUICv1, check the fixed bit.
        if (self.version == QuicVersion1 and
            (self.version_specific_bits & 0x40 != 0x40))
        {
            return error.FixedBitError;
        }
        // See if anything further about the packet type can be determined.
        // - Check if Version 1, and Long, then look for type.
        if (self.version == QuicVersion1 and self.use_long_form) {
            const long_pkt_type = (self.version_specific_bits & 0x30) >> 4;
            if (long_pkt_type == @intFromEnum(QuicPktType.Initial)) {
                self.quic_pkt_type = QuicPktType.Initial;
                // Read packet number length.
                //const pktnum_len = self.version_specific_bits & 0x03;
                // TODO: Read token length and token.
                // XXX need to know # of bytes read ... const token_len = varint.readVarInt();
                // TODO: Read overall length.
                // TODO: Read packet number.
            } else {
                return error.PacketTypeError;
            }
        }

        return bytes_read;
    }
};

const test_data = @import("test_data.zig");
test "header decode" {
    var p = QuicPacket.init(std.testing.allocator);
    _ = try p.decode_header(&test_data.client_header);
    try expectEqual(p.use_long_form, true);
    try expectEqual(p.version, QuicVersion1);
    try expectEqual(p.dconn_id_len, 8);
    try expectEqualSlices(u8, p.dconn_id.bytes, &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    try expectEqual(p.sconn_id_len, 0);
    try expectEqual(p.quic_pkt_type, QuicPktType.Initial);
}

test "pn and sample offset" {
    var p = QuicPacket.init(std.testing.allocator);
    defer p.deinit();
    _ = try p.decode_header(&test_data.client_header);

    try expectEqual(p.find_pn_offset(), 17);
    try expectEqual(p.find_sample_offset(), 21);
}

test "make initial" {
    const rand = [_]u8{0} ** 32;
    var p = QuicPacket.init(std.testing.allocator);
    defer p.deinit();
    try p.make_initial(rand);

    try expectEqual(p.find_pn_offset(), 17);
    try expectEqual(p.find_sample_offset(), 21);
}

// TODO: support ability to aggregate multiple QUIC packets into a datagram,
// and to parse datagrams that contain multiple packets, per 8999.
