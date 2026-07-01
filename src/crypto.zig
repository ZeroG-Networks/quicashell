// Crypto/TLS integration for QUIC, mostly from RFC 9001.

const std = @import("std");

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
    client_secret: [32]u8 = undefined,
    client_key: [16]u8 = undefined,
    client_iv: [12]u8 = undefined,
    client_hp: [16]u8 = undefined,

    // Just support client Initial packets for now.
    pub fn init(conn_id: []const u8) QuicCrypto {
        const initial_secret = initialHkdf.extract(&initial_salt, conn_id);
        const secret = hkdfExpandLabel(initialHkdf, initial_secret, "client in", "", 32);

        return QuicCrypto{
            .initial_secret = initial_secret,
            .client_secret = secret,
            .client_key = hkdfExpandLabel(initialHkdf, secret, "quic key", "", 16),
            .client_iv = hkdfExpandLabel(initialHkdf, secret, "quic iv", "", 12),
            .client_hp = hkdfExpandLabel(initialHkdf, secret, "quic hp", "", 16),
        };
    }

    // The provided protected text and authentication tag will be filled in.
    // TODO: assumes client IV and client key
    pub fn protectPacket(self: QuicCrypto, protected: []u8, tag: *[16]u8, payload: []u8, header: []u8, pktnum: u64) void {
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

    // Apply header protection to a serialized and AEAD protected packet.
    pub fn protectHeader(self: QuicCrypto, pkt: []u8, sample: [16]u8, pn_offset: usize) !void {
        var mask: [16]u8 = undefined;
        const ctx = initialHeaderProtection.initEnc(self.client_hp);
        ctx.encrypt(&mask, &sample);

        const pn_length: usize = (pkt[0] & 0x03) + 1;
        if ((pkt[0] & 0x80) == 0x80) { // Long header.
            pkt[0] ^= mask[0] & 0x0f;
        } else {
            pkt[0] ^= mask[0] & 0x1f;
        }
        for (pn_offset..pn_offset + pn_length) |i| {
            pkt[i] ^= mask[1 + i];
        }
    }
};

// Test data below comes from Appendix A of RFC 9001.
const test_conn_id = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const test_initial_secret = [_]u8{ 0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92, 0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44 };
const test_client_secret = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
const test_client_key = [_]u8{ 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };
const test_client_iv = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
const test_client_hp = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };

test "generate client in" {
    const c = QuicCrypto.init(&test_conn_id);
    try expectEqualSlices(u8, &c.initial_secret, &test_initial_secret);
    try expectEqualSlices(u8, &c.client_secret, &test_client_secret);
    try expectEqualSlices(u8, &c.client_key, &test_client_key);
    try expectEqualSlices(u8, &c.client_iv, &test_client_iv);
    try expectEqualSlices(u8, &c.client_hp, &test_client_hp);
}
