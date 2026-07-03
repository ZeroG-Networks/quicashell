// Crypto/TLS integration for QUIC, mostly from RFC 9001.

const std = @import("std");

const test_data = @import("test_data.zig");

const expectEqualSlices = std.testing.expectEqualSlices;

const sha256 = std.crypto.hash.sha2.Sha256;

// Configuration per Section 5.2 of RFC 9001.
const initialHkdf = std.crypto.kdf.hkdf.HkdfSha256;
const initial_salt = [_]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };
// Initial packets use AEAD_AES_128_GCM.
const initialProtection = std.crypto.aead.aes_gcm.Aes128Gcm;
const initialHeaderProtection = std.crypto.core.aes.Aes128;

const hkdfExpandLabel = std.crypto.tls.hkdfExpandLabel;

pub const QuicCrypto = struct {
    const Self = @This();

    initial_secret: [32]u8 = undefined,
    client_initial_secret: [32]u8 = undefined,
    client_key: [16]u8 = undefined,
    client_iv: [12]u8 = undefined,
    client_hp: [16]u8 = undefined,

    // Just support client Initial packets for now.
    pub fn init(conn_id: []const u8) QuicCrypto {
        const initial_secret = initialHkdf.extract(&initial_salt, conn_id);
        const secret = hkdfExpandLabel(initialHkdf, initial_secret, "client in", "", 32);

        return QuicCrypto{
            .initial_secret = initial_secret,
            .client_initial_secret = secret,
            .client_key = hkdfExpandLabel(initialHkdf, secret, "quic key", "", 16),
            .client_iv = hkdfExpandLabel(initialHkdf, secret, "quic iv", "", 12),
            .client_hp = hkdfExpandLabel(initialHkdf, secret, "quic hp", "", 16),
        };
    }

    // The provided protected text and authentication tag will be filled in.
    // TODO: assumes client IV and client key
    pub fn protectPacket(self: Self, protected: []u8, tag: *[16]u8, payload: []u8, header: []u8, pktnum: u64) void {
        // The unprotected packet header is used as the associated data.
        const assoc = header;

        // The nonce combines the packet protection IV with the packet number.
        var nonce: [12]u8 = undefined;
        std.mem.writeInt(u32, nonce[0..4], 0, .big);
        std.mem.writeInt(u64, nonce[4..], pktnum, .big);
        for (self.client_iv, 0..) |iv, i| {
            nonce[i] ^= iv;
        }

        initialProtection.encrypt(protected, tag, payload, assoc, nonce, self.client_key);
    }

    // Generate the header protection mask.
    pub fn protectHeaderMask(self: Self, sample: [16]u8, mask: *[5]u8) void {
        var full_mask: [16]u8 = undefined;
        const ctx = initialHeaderProtection.initEnc(self.client_hp);
        ctx.encrypt(&full_mask, &sample);
        @memcpy(mask, full_mask[0..5]);
    }

    // Apply header protection to a serialized and AEAD protected packet.
    pub fn protectHeader(self: QuicCrypto, pkt: []u8, sample: [16]u8, pn_offset: usize) !void {
        var mask: [5]u8 = undefined;
        self.protectHeaderMask(sample, &mask);

        const pn_length: usize = (pkt[0] & 0x03) + 1;
        if ((pkt[0] & 0x80) == 0x80) { // Long header.
            pkt[0] ^= (mask[0] & 0x0f);
        } else {
            pkt[0] ^= mask[0] & 0x1f;
        }
        for (0..pn_length) |i| {
            pkt[pn_offset + i] ^= mask[1 + i];
        }
    }
};

test "generate client initial" {
    try test_data.loadTestData();

    const c = QuicCrypto.init(&test_data.conn_id);
    try expectEqualSlices(u8, &c.initial_secret, &test_data.initial_secret);
    try expectEqualSlices(u8, &c.client_initial_secret, &test_data.client_initial_secret);
    try expectEqualSlices(u8, &c.client_key, &test_data.client_key);
    try expectEqualSlices(u8, &c.client_iv, &test_data.client_iv);
    try expectEqualSlices(u8, &c.client_hp, &test_data.client_hp);

    var mask: [5]u8 = undefined;
    c.protectHeaderMask(test_data.client_sample, &mask);
    try expectEqualSlices(u8, &mask, &test_data.client_mask);
}

// TODO: test "generate server initial"
