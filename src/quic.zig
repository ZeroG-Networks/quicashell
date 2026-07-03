const std = @import("std");
const net = std.Io.net;

// This represents a QUIC endpoint.
pub const Quic = struct {
    const Self = @This();

    socket: std.Io.net.Socket = undefined,
    io: std.Io = undefined,

    pub fn init(io: std.Io, ip: []const u8, port: u16) !Quic {
        const address = try net.IpAddress.parse(ip, port);
        const socket = try net.IpAddress.bind(&address, io, .{
            .ip6_only = false,
            .mode = .dgram,
            .protocol = .udp,
        });
        return Quic{ .socket = socket, .io = io };
    }

    pub fn deinit(self: Self) void {
        self.socket.close(self.io);
    }

    pub fn sendPacket(self: Self, pkt: []u8, dest: net.IpAddress) !void {
        try self.socket.send(self.io, &dest, pkt);
    }
};
