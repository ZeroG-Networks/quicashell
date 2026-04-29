const std = @import("std");
const net = std.Io.net;

pub const Quic = struct {
    const Self = @This();

    socket: std.Io.net.Socket = undefined,

    pub fn init(io: std.Io, ip: []const u8, port: u16) !Quic {
        const address = try net.IpAddress.parse(ip, port);
        const socket = try net.IpAddress.bind(&address, io, .{
            .ip6_only = false,
            .mode = .dgram,
            .protocol = .udp,
        });
        return Quic{ .socket = socket };
    }

    pub fn deinit(self: Self, io: std.Io) void {
        self.socket.close(io);
    }
};
