//! By convention, root.zig is the root source file when making a library.
const std = @import("std");

const quic = @import("quic.zig");
const tls = @import("tls.zig");

pub const Quic = quic.Quic;
pub const Tls = tls;

pub fn hexdumpSlice(bytes: []u8, out: *std.Io.Writer) !void {
    try out.print("Length: {} bytes.\n", .{bytes.len});
    for (bytes) |byte| {
        try out.print("{x:0>2} ", .{byte});
    }
    try out.print("\n", .{});
}

// TODO: test for hexdumpSlice.
