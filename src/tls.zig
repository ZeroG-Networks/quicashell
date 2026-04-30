const std = @import("std");

// Handshake protocol message types in RFC 8446, B.3.
const HandshakeClientHello: u8 = 1;

const OldProtocolVersion: u16 = 0x0303; // TLS 1.2 compatibility.
const NewProtocolVersion: u16 = 0x0304; // TLS 1.3.
const TlsAes128GcmSha256: u16 = 0x1301;

const SupportedVersionsExtension: u8 = 43;

// TODO: Instead of this, should we just write straight to output?
// Append a ClientHello message into the msg buffer provided.
pub fn CreateClientHello(msg: *std.ArrayList(u8), io: std.Io, gpa: std.mem.Allocator) !void {
    const now_ms = std.Io.Clock.now(.real, io).toMilliseconds();
    var rand = std.Random.DefaultPrng.init(@as(u64, @bitCast(now_ms)));

    // Resize to at least fit the type, length, and protocol version.
    const origlen: usize = msg.items.len;
    var msglen: u24 = @truncate(6 + origlen);
    try msg.resize(gpa, msglen);

    // Indicate client hello type.
    msg.items[origlen] = HandshakeClientHello;

    // Fill in the protocol version.
    msglen += 32;
    try msg.resize(gpa, msglen);
    for (0..8) |i| {
        const randint: u32 = rand.random().int(u32);
        msg.items[origlen + 5 + (i * 4)] = @truncate(randint >> 24);
        msg.items[origlen + 6 + (i * 4)] = @truncate(randint >> 16);
        msg.items[origlen + 7 + (i * 4)] = @truncate(randint >> 8);
        msg.items[origlen + 8 + (i * 4)] = @truncate(randint);
    }

    // Fill in the session ID.
    // TODO: This code only supports a zero-byte / empty ID.
    try msg.append(gpa, 0x00);

    // Fill in the cipher suites.
    // Note: This code only supports the minimum mandatory algorithms.
    try msg.append(gpa, 0x02); // Two bytes of length for ciphersuite list.
    try msg.append(gpa, TlsAes128GcmSha256 >> 8);
    try msg.append(gpa, TlsAes128GcmSha256 & 0xFF);

    // Fill in compression methods.
    try msg.append(gpa, 0x01); // Only a single byte is needed for the list.
    try msg.append(gpa, 0x00); // Only null compression is supported in TLS 1.3.

    // Fill in extensions.
    const extensions_start: usize = msg.items.len;
    try msg.resize(gpa, extensions_start + 2); // Reserve 2 bytes for length.
    var extensions_len: u16 = 0;

    // Add the supported-versions extension; only TLS 1.3 is supported.
    try msg.append(gpa, @as(u16, SupportedVersionsExtension) >> 8);
    try msg.append(gpa, SupportedVersionsExtension & 0xFF);
    // Size of extensions is 3-bytes.
    try msg.append(gpa, 0x00);
    try msg.append(gpa, 0x03);
    try msg.append(gpa, 0x02); // List of versions is 2-bytes long.
    try msg.append(gpa, NewProtocolVersion >> 8);
    try msg.append(gpa, NewProtocolVersion & 0xFF);
    extensions_len += 7;

    msg.items[extensions_start] = @truncate(extensions_len >> 8);
    msg.items[extensions_start + 1] = @truncate(extensions_len & 0xFF);

    // Finally, fill in space that was left prior for the message length.
    msglen = @truncate(msg.items.len - 4);
    msg.items[origlen + 1] = @truncate(msglen >> 16);
    msg.items[origlen + 2] = @truncate((msglen >> 8) & 0xFF);
    msg.items[origlen + 3] = @truncate(msglen & 0xFF);
    // TODO: This is overwriting the version done at the beginning???
}
