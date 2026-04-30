const std = @import("std");
const Io = std.Io;
const quicashell = @import("root.zig");

var quit = false;
var endpoint: quicashell.Quic = undefined;

fn help(output: *std.Io.Writer) !void {
    try output.print("quit - exit quicashell\n", .{});
}

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
    } else if (std.mem.eql(u8, cmd.?, "dumpinit") == true) {
        var record: std.ArrayList(u8) = .empty;
        defer record.deinit(alloc);

        // Set aside 5 bytes for the record header to be filled in.
        try record.resize(alloc, 5);
        try quicashell.Tls.CreateClientHello(&record, io, alloc);

        const OldProtocolVersion: u16 = 0x0303; // TODO: redundant; remove.
        record.items[0] = 22; // TODO: redundant; remove.
        record.items[1] = OldProtocolVersion >> 8;
        record.items[2] = OldProtocolVersion & 0xFF;
        record.items[3] = @truncate((record.items.len - 5) >> 8);
        record.items[4] = @truncate((record.items.len - 5) & 0xFF);

        try quicashell.hexdumpSlice(record.items, output);
    } else {
        try output.print("Invalid command: {s}.\n", .{cmd.?});
    }
}

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

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
