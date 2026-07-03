const std = @import("std");
const Io = std.Io;
const quicashell = @import("root.zig");

var quit = false;
var endpoint: quicashell.Quic = undefined;

// Print REPL usage information.
fn help(output: *std.Io.Writer) !void {
    try output.print("sendinit - show an Initial packet\n", .{});
    try output.print("endpoint - set the local IP & UDP port information\n", .{});
    try output.print("quit - exit quicashell\n", .{});
}

// Evaluate a line of command inputs.
fn eval(line: []const u8, output: *std.Io.Writer, io: Io, alloc: std.mem.Allocator) !void {
    var it = std.mem.splitScalar(u8, line, ' ');
    const cmd = it.next();

    if (std.mem.eql(u8, cmd.?, "help") == true) {
        try help(output);
    } else if (std.mem.eql(u8, cmd.?, "quit") == true) {
        quit = true;
    } else if (std.mem.eql(u8, cmd.?, "endpoint") == true) {
        endpoint = try quicashell.Quic.init(io, "0.0.0.0", 24242);
        // TODO: Allow local port and IP to be specified.
    } else if (std.mem.eql(u8, cmd.?, "sendinit") == true) {
        // TODO: The endpoint should be created as a precondition?
        endpoint = try quicashell.Quic.init(io, "0.0.0.0", 24242);
        // TODO: Allow local port and IP to be specified.

        var dest_host = it.next();
        if (dest_host == null) dest_host = "127.0.0.1";
        var dest_port_str = it.next();
        if (dest_port_str == null) dest_port_str = "55555";
        const dest_port = try std.fmt.parseInt(u16, dest_port_str.?, 10);
        const dest_addr = try std.Io.net.IpAddress.resolve(io, dest_host.?, dest_port);

        var randbytes = [_]u8{0} ** 32;
        const now_ms = std.Io.Clock.now(.real, io).toMilliseconds();
        var rng = std.Random.DefaultPrng.init(@as(u64, @bitCast(now_ms)));
        for (0..4) |i| {
            const randint: u32 = rng.random().int(u32);
            @memcpy(randbytes[i * 4 .. (i + 1) * 4], std.mem.asBytes(&randint));
        }

        var pkt = quicashell.QuicPacket.init(alloc);
        try pkt.make_initial(randbytes);
        var pkt_writer = std.Io.Writer.Allocating.init(alloc);
        defer pkt_writer.deinit();
        try pkt.serialize(&pkt_writer.writer);
        // TODO try quicashell.hexdumpSlice(pkt_writer.written(), output);
        try endpoint.sendPacket(pkt_writer.written(), dest_addr);
    } else {
        try output.print("Invalid command: {s}.\n", .{cmd.?});
    }
}

// Loop continuously, processing commands and providing outputs.
fn repl(input: *std.Io.Reader, output: *std.Io.Writer, io: Io, alloc: std.mem.Allocator) !void {
    while (!quit) {
        try output.print("> ", .{});
        try output.flush();
        const line = input.takeDelimiterExclusive('\n') catch break;
        input.toss(1); // Discard newline.
        try eval(line, output, io, alloc);
        try output.flush();
    }
}

// The program entry point simply starts a REPL.
pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    for (args, 0..args.len) |arg, i| {
        if (i > 0) {
            std.log.info("{d} - {s}", .{ i, arg });
        }
    }

    const io = init.io;
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    var stdin_buffer: [1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buffer);
    const stdin = &stdin_reader.interface;

    try repl(stdin, stdout, io, arena);
}

// TODO: replace
test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
