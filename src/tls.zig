const std = @import("std");

// Handshake protocol message types in RFC 8446, B.3.
const HandshakeClientHello: u8 = 1;

const OldProtocolVersion: u16 = 0x0303; // TLS 1.2 compatibility.
const NewProtocolVersion: u16 = 0x0304; // TLS 1.3.
const TlsAes128GcmSha256: u16 = 0x1301;

const SupportedVersionsExtension: u16 = 43;

pub const ClientHello = struct {
    const Self = @This();

    random: [32]u8 = undefined,

    pub fn init(random: [32]u8) ClientHello {
        return ClientHello{
            .random = random,
        };
    }

    // Write out according to the protocol.
    pub fn serialize(self: Self, writer: *std.Io.Writer) !void {
        try writer.writeByte(@as(u8, OldProtocolVersion >> 8));
        try writer.writeByte(@as(u8, OldProtocolVersion & 0xFF));
        try writer.writeAll(&self.random);
        // Fill in the session ID.
        // TODO: Only zero-byte / empty IDs are supported.
        try writer.writeByte(0x00);

        // Fill in the cipher suites.
        // NOTE: This code only supports the minimum mandatory algorithms.
        try writer.writeByte(0x02); // Two bytes of length for ciphersuite list.
        try writer.writeByte(TlsAes128GcmSha256 >> 8);
        try writer.writeByte(TlsAes128GcmSha256 & 0xFF);

        // Fill in compression methods.
        try writer.writeByte(0x01); // Only a single byte is needed for the list.
        try writer.writeByte(0x00); // Only null compression is supported in TLS 1.3.

        // Fill in extensions, with two bytes reserved for extensions length.
        try writer.writeByte(0x00);
        try writer.writeByte(0x00);
        // Add the supported-versions extension; only TLS 1.3 is supported.
        try writer.writeByte(@as(u8, SupportedVersionsExtension >> 8));
        try writer.writeByte(@as(u8, SupportedVersionsExtension & 0xFF));
        // Size of extensions is 3-bytes.
        try writer.writeByte(0x00);
        try writer.writeByte(0x03);
        try writer.writeByte(0x02); // List of versions is 2-bytes long.
        try writer.writeByte(NewProtocolVersion >> 8);
        try writer.writeByte(NewProtocolVersion & 0xFF);
    }
};
