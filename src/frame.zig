// QUIC frame handling from Section 12.4 of RFC 9000.
const std = @import("std");
const expectEqual = std.testing.expectEqual;

const varint = @import("varint.zig");

pub const FrameType = enum(u8) {
    PADDING = 0x00,
    //    PING = 0x01,
    //    ACK1 = 0x02,
    //    ACK2 = 0x03,
    //    RESET_STREAM = 0x04,
    //    STOP_SENDING = 0x05,
    CRYPTO = 0x06,
    //    NEW_TOKEN = 0x07,
    //    STREAM0 = 0x08,
    // ... TODO
    //    STREAMN = 0x0F,
    //    MAX_DATA = 0x10,
    //    MAX_STREAM_DATA = 0x11,
    //    MAX_STREAMS1 = 0x12,
    //    MAX_STREAMS2 = 0x13,
    //    DATA_BLOCKED = 0x14,
    //    STREAM_DATA_BLOCKED = 0x15,
    //    STREAMS_BLOCKED1 = 0x16,
    //    STREAMS_BLOCKED2 = 0x17,
    //    NEW_CONNECTION_ID = 0x18,
    //    RETIRE_CONNECTION_ID = 0x19,
    //    PATH_CHALLENGE = 0x1A,
    //    PATH_RESPONSE = 0x1B,
    //    CONNECTION_CLOSE1 = 0x1C,
    //    CONNECTION_CLOSE2 = 0x1D,
    //    HANDSHAKE_DONE = 0x1E,
};

pub const PaddingFrame = struct {
    const Self = @This();

    len: usize = undefined,

    pub fn init(sz: usize) PaddingFrame {
        return PaddingFrame{ .len = sz };
    }

    pub fn write_frame(self: Self, w: *std.Io.Writer) !void {
        for (0..self.len) |_| {
            try w.writeByte(0x00);
        }
    }

    pub fn get_length(self: Self) usize {
        return self.len;
    } // TODO
};

pub const CryptoFrame = struct {
    const Self = @This();

    data: []const u8 = undefined,
    offset: u64 = undefined,

    pub fn init(data: []const u8, offset: u64) CryptoFrame {
        return CryptoFrame{
            .data = data,
            .offset = offset,
        };
    }

    pub fn write_frame(self: Self, writer: *std.Io.Writer) !void {
        try varint.writeVarInt(@intFromEnum(FrameType.CRYPTO), writer);
        try varint.writeVarInt(self.offset, writer);
        try varint.writeVarInt(self.data.len, writer);
        try writer.writeAll(self.data);
    }

    // Return the size that the serialized frame will be.
    pub fn get_length(self: Self) !usize {
        var sz: usize = 0;
        sz += try varint.lenOfVarInt(@intFromEnum(FrameType.CRYPTO));
        sz += try varint.lenOfVarInt(self.offset);
        sz += try varint.lenOfVarInt(self.data.len);
        sz += self.data.len;
        return sz;
    }
};

pub const QuicFrameBody = union(FrameType) {
    PADDING: PaddingFrame,
    CRYPTO: CryptoFrame,
};

pub const QuicFrame = struct {
    const Self = @This();

    frame_type: FrameType = undefined,
    body: QuicFrameBody = undefined,

    pub fn init() QuicFrame {
        return QuicFrame{};
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    // Read this frame in from a buffer, and return number of bytes read.
    pub fn decode(self: *Self, buf: []const u8) !usize {
        var bytes_read: usize = 0;
        self.frame_type = @enumFromInt(try varint.readVarInt(buf));
        bytes_read += varint.decodedLen(buf[0]);

        switch (self.frame_type) {
            .PADDING => self.body = QuicFrameBody{
                .PADDING = PaddingFrame.init(0),
            },
            .CRYPTO => {
                const offset = try varint.readVarInt(buf[bytes_read..]);
                bytes_read += varint.decodedLen(buf[bytes_read]);
                const length = try varint.readVarInt(buf[bytes_read..]);
                bytes_read += varint.decodedLen(buf[bytes_read]);
                // TODO: copy the data like this?
                // const data = try alloc.dupe(u8, buf[bytes_read .. bytes_read + length]);
                const data = buf[bytes_read .. bytes_read + length];
                bytes_read += length;

                self.body = QuicFrameBody{
                    .CRYPTO = CryptoFrame.init(data, offset),
                };
            },
        }
        return bytes_read;
    }
};

pub fn write_frame(f: *const QuicFrame, writer: *std.Io.Writer) !void {
    switch (f.frame_type) {
        .PADDING => try f.body.PADDING.write_frame(writer),
        .CRYPTO => try f.body.CRYPTO.write_frame(writer),
    }
}

// Return the size that the serialized frame will be.
pub fn get_length(f: *const QuicFrame) !usize {
    switch (f.frame_type) {
        .PADDING => return f.body.PADDING.get_length(),
        .CRYPTO => return f.body.CRYPTO.get_length(),
    }
}

test "padding length" {
    const f = QuicFrame{
        .frame_type = FrameType.PADDING,
        .body = QuicFrameBody{
            .PADDING = PaddingFrame.init(1),
        },
    };
    try expectEqual(1, get_length(&f));
}

test "crypto length" {
    const testdata: []const u8 = "test";

    const f = QuicFrame{
        .frame_type = FrameType.CRYPTO,
        .body = QuicFrameBody{
            .CRYPTO = CryptoFrame.init(testdata, 2),
        },
    };
    try expectEqual(7, get_length(&f));
}
