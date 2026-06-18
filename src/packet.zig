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
    dconn_id: ConnectionId,
    sconn_id_len: u8 = undefined,
    sconn_id: ConnectionId,

    pub fn init() QuicPacket {
        return QuicPacket{};
    }

    // Send this packet out a socket.
    // TODO

    // Read this packet from a socket.
    // TODO
};

// TODO: support ability to aggregate multiple QUIC packets into a datagram,
// and to parse datagrams that contain multiple packets, per 8999.
