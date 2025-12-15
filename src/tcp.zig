//! TCP header parsing
//! Based on RFC 793

const std = @import("std");

pub const OptionKind = struct {
    pub const END: u8 = 0;
    pub const NOOP: u8 = 1;
    pub const MAXIMUM_SEGMENT_SIZE: u8 = 2;
    pub const WINDOW_SCALE: u8 = 3;
    pub const SELECTIVE_ACK_PERMITTED: u8 = 4;
    pub const SELECTIVE_ACK: u8 = 5;
    pub const TIMESTAMP: u8 = 8;
};

pub const OptionLen = struct {
    pub const MAXIMUM_SEGMENT_SIZE: u8 = 4;
    pub const WINDOW_SCALE: u8 = 3;
    pub const SELECTIVE_ACK_PERMITTED: u8 = 2;
    pub const TIMESTAMP: u8 = 10;
};

pub const SackBlock = struct {
    left: u32,
    right: u32,
};

pub const TCPOptionElement = union(enum) {
    noop: void,
    maximum_segment_size: u16,
    window_scale: u8,
    sack_permitted: void,
    selective_ack: struct {
        first_left: u32,
        first_right: u32,
        blocks: [3]?SackBlock,
    },
    timestamp: struct {
        tsval: u32,
        tsecr: u32,
    },
};

/// TCP Header (20 bytes minimum, up to 60 bytes with options)
pub const TCPHeader = struct {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    /// Data offset (header length in 32-bit words, minimum 5)
    data_offset: u4,
    reserved: u4,
    flags: Flags,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    options: []const u8,

    pub const Flags = packed struct {
        fin: bool = false,
        syn: bool = false,
        rst: bool = false,
        psh: bool = false,
        ack: bool = false,
        urg: bool = false,
        ece: bool = false,
        cwr: bool = false,
        ns: bool = false,
    };

    pub fn parse(data: []const u8) !TCPHeader {
        if (data.len < 20) return error.InvalidLength;

        const source_port = std.mem.readInt(u16, data[0..2], .big);
        const destination_port = std.mem.readInt(u16, data[2..4], .big);
        const sequence_number = std.mem.readInt(u32, data[4..8], .big);
        const acknowledgment_number = std.mem.readInt(u32, data[8..12], .big);

        const data_offset = @as(u4, @truncate(data[12] >> 4));
        const reserved = @as(u4, @truncate((data[12] & 0x0F) >> 1));

        if (data_offset < 5) return error.InvalidHeaderLength;

        const header_len: usize = @as(usize, data_offset) * 4;
        if (data.len < header_len) return error.InvalidLength;

        const flags = Flags{
            .ns = (data[12] & 0x01) != 0,
            .cwr = (data[13] & 0x80) != 0,
            .ece = (data[13] & 0x40) != 0,
            .urg = (data[13] & 0x20) != 0,
            .ack = (data[13] & 0x10) != 0,
            .psh = (data[13] & 0x08) != 0,
            .rst = (data[13] & 0x04) != 0,
            .syn = (data[13] & 0x02) != 0,
            .fin = (data[13] & 0x01) != 0,
        };

        const window_size = std.mem.readInt(u16, data[14..16], .big);
        const checksum = std.mem.readInt(u16, data[16..18], .big);
        const urgent_pointer = std.mem.readInt(u16, data[18..20], .big);

        const options = if (header_len > 20) data[20..header_len] else &[_]u8{};

        return TCPHeader{
            .source_port = source_port,
            .destination_port = destination_port,
            .sequence_number = sequence_number,
            .acknowledgment_number = acknowledgment_number,
            .data_offset = data_offset,
            .reserved = reserved,
            .flags = flags,
            .window_size = window_size,
            .checksum = checksum,
            .urgent_pointer = urgent_pointer,
            .options = options,
        };
    }

    pub fn headerLength(self: TCPHeader) usize {
        return @as(usize, self.data_offset) * 4;
    }

    pub fn dump(self: TCPHeader, writer: anytype) !void {
        try writer.writeAll("TCP Header:\n");
        try writer.print("  Source Port: {}\n", .{self.source_port});
        try writer.print("  Destination Port: {}\n", .{self.destination_port});
        try writer.print("  Sequence Number: {}\n", .{self.sequence_number});
        try writer.print("  Acknowledgment Number: {}\n", .{self.acknowledgment_number});
        try writer.print("  Data Offset: {} ({} bytes)\n", .{ self.data_offset, self.headerLength() });
        try writer.print("  Flags: ", .{});
        if (self.flags.syn) try writer.writeAll("SYN ");
        if (self.flags.ack) try writer.writeAll("ACK ");
        if (self.flags.fin) try writer.writeAll("FIN ");
        if (self.flags.rst) try writer.writeAll("RST ");
        if (self.flags.psh) try writer.writeAll("PSH ");
        if (self.flags.urg) try writer.writeAll("URG ");
        if (self.flags.ece) try writer.writeAll("ECE ");
        if (self.flags.cwr) try writer.writeAll("CWR ");
        if (self.flags.ns) try writer.writeAll("NS ");
        try writer.writeAll("\n");
        try writer.print("  Window Size: {}\n", .{self.window_size});
        try writer.print("  Checksum: 0x{x:0>4}\n", .{self.checksum});
        if (self.flags.urg) {
            try writer.print("  Urgent Pointer: {}\n", .{self.urgent_pointer});
        }
        if (self.options.len > 0) {
            try writer.print("  Options: {} bytes\n", .{self.options.len});
        }
    }

    pub fn getOptions(self: TCPHeader) TCPOptions {
        return TCPOptions.fromSlice(self.options);
    }
};

pub const TCPOptionsWriteError = error{NotEnoughSpace};

pub const TCPOptionReadError = error{
    UnexpectedEndOfSlice,
    UnexpectedSize,
    UnknownId,
};

pub const TCPOptions = struct {
    len: u8,
    buf: [40]u8,

    pub const MAX_LEN: usize = 40;

    /// Creates TCPOptions from a byte slice with automatic padding.
    ///
    /// This function performs the following steps:
    /// 1. Checks if slice length > 40 bytes (MAX_LEN)
    /// 2. If too long, returns error
    /// 3. Rounds up length to nearest multiple of 4 (for 32-bit word alignment)
    /// 4. Copies slice data into fixed buffer
    /// 5. Pads remaining bytes with zeros
    pub fn fromSlice(slice: []const u8) TCPOptionsWriteError!TCPOptions {

        // Validate that the slice is not too long
        if (MAX_LEN < slice.len) {
            return error.NotEnoughSpace;
        }

        // Cast to u8 (safe because we checked MAX_LEN = 40)
        const len: u8 = @intCast(slice.len);

        // Calculate padded lenght (round up to multiple of 4)
        const has_remainder = (len & 0b11) != 0;
        const rounded_down = (len >> 2) << 2;
        const padded_len = rounded_down + if (has_remainder) @as(u8, 4) else @as(u8, 0);

        // Create buffer and copy data
        var buf: [40]u8 = undefined;
        @memset(&buf, 0);
        @memcpy(buf[0..slice.len], slice);

        return TCPOptions{
            .len = padded_len,
            .buf = buf,
        };
    }

    // pub fn parse()
};

pub const TCPOptionsIterator = struct {
    buf: []const u8,
    pos: usize,

    pub fn init(options: []const u8) TCPOptionsIterator {
        return TCPOptionsIterator{
            .buf = options,
            .pos = 0,
        };
    }

    pub fn next(self: *TCPOptionsIterator) !?TCPOptionElement {
        if (self.pos >= self.buf.len) {
            return null;
        }

        const kind = self.buf[self.pos];

        switch (kind) {
            OptionKind.END => {
                return null;
            },
            OptionKind.NOOP => {
                self.pos += 1;
                return TCPOptionElement{ .noop = {} };
            },
            OptionKind.MAXIMUM_SEGMENT_SIZE => {
                // Check we have at least 4 bytes
                if (self.buf.len < self.pos + 4) {
                    return TCPOptionReadError.UnexpectedEndOfSlice;
                }

                // Check legnth field
                const length = self.buf[self.pos + 1];
                if (length != OptionLen.MAXIMUM_SEGMENT_SIZE) {
                    return TCPOptionReadError.UnexpectedSize;
                }
                const mss = std.mem.readInt(u16, self.buf[self.pos + 2 ..][0..2], .big);
                self.pos += @as(usize, length);
                return TCPOptionElement{ .maximum_segment_size = mss };
            },
            OptionKind.WINDOW_SCALE => {
                if (self.buf.len < self.pos + 3) {
                    return TCPOptionReadError.UnexpectedEndOfSlice;
                }
                const length = self.buf[self.pos + 1];
                if (length != OptionLen.WINDOW_SCALE) {
                    return TCPOptionReadError.UnexpectedSize;
                }
                const scale = self.buf[self.pos + 2];
                self.pos += @as(usize, length);
                return TCPOptionElement{ .window_scale = scale };
            },
            OptionKind.SELECTIVE_ACK_PERMITTED => {
                if (self.buf.len < self.pos + 2) {
                    return TCPOptionReadError.UnexpectedEndOfSlice;
                }
                const length = self.buf[self.pos + 1];
                if (length != OptionLen.SELECTIVE_ACK_PERMITTED) {
                    return TCPOptionReadError.UnexpectedSize;
                }
                self.pos += @as(usize, length);
                return TCPOptionElement{ .sack_permitted = {} };
            },
            OptionKind.TIMESTAMP => {
                if (self.buf.len < self.pos + 10) {
                    return TCPOptionReadError.UnexpectedEndOfSlice;
                }
                const length = self.buf[self.pos + 1];
                if (length != OptionLen.TIMESTAMP) {
                    return TCPOptionReadError.UnexpectedSize;
                }
                const tsval = std.mem.readInt(u32, self.buf[self.pos + 2 ..][0..4], .big);
                const tsecr = std.mem.readInt(u32, self.buf[self.pos + 6 ..][0..4], .big);
                self.pos += @as(usize, length);
                return TCPOptionElement{ .timestamp = .{ .tsval = tsval, .tsecr = tsecr } };
            },
            OptionKind.SELECTIVE_ACK => {
                // Need at least 2 bytes for kind and length
                if (self.buf.len < self.pos + 2) {
                    return TCPOptionReadError.UnexpectedEndOfSlice;
                }

                const length = self.buf[self.pos + 1];

                if (length < 2 or ((length - 2) % 8) != 0) {
                    return TCPOptionReadError.UnexpectedSize;
                }

                if (self.buf.len < self.pos + length) {
                    return TCPOptionReadError.UnexpectedEndOfSlice;
                }

                const first_left = std.mem.readInt(u32, self.buf[self.pos + 2 ..][0..4], .big);
                const first_right = std.mem.readInt(u32, self.buf[self.pos + 6 ..][0..4], .big);

                var blocks: [3]?SackBlock = .{null} ** 3;

                var i: usize = 0;
                while (i < 3) : (i += 1) {
                    const offset = 2 + 8 + (i * 8);
                    if (offset < length) {
                        const left = std.mem.readInt(u32, self.buf[self.pos + offset..][0..4], .big);
                        const right = std.mem.readInt(u32, self.buf[self.pos + offset + 4..][0..4], .big);
                        blocks[i] = SackBlock{ .left = left, .right = right };
                    } else {
                        break;
                    }
                }

                self.pos += length;

                return TCPOptionElement{ .selective_ack = .{
                    .first_left = first_left,
                    .first_right = first_right,
                    .blocks = blocks,
                } };
            },
            else => {
                return TCPOptionReadError.UnknownId;
            },
        }
    }
};

test "fromSlice - exact multiple of 4" {
    const data = [_]u8{ 1, 2, 3, 4 };
    const opts = try TCPOptions.fromSlice(&data);

    try std.testing.expectEqual(@as(u8, 4), opts.len);
    try std.testing.expectEqualSlices(u8, &data, opts.buf[0..4]);
}

test "fromSlice - needs padding" {
    const data = [_]u8{ 1, 2, 3 }; // 3 bytes
    const opts = try TCPOptions.fromSlice(&data);

    try std.testing.expectEqual(@as(u8, 4), opts.len); // Padded to 4
    try std.testing.expectEqual(@as(u8, 1), opts.buf[0]);
    try std.testing.expectEqual(@as(u8, 2), opts.buf[1]);
    try std.testing.expectEqual(@as(u8, 3), opts.buf[2]);
    try std.testing.expectEqual(@as(u8, 0), opts.buf[3]); // Padding
}

test "fromSlice - too long" {
    const data = [_]u8{0} ** 41; // 41 bytes - too long!
    const result = TCPOptions.fromSlice(&data);

    try std.testing.expectError(error.NotEnoughSpace, result);
}

// Test SACK with valid lengths (10, 18, 26, 34 bytes)
test "TCPOptionsIterator - SACK with 1 block (10 bytes)" {
    const data = [_]u8{
        5, // KIND_SELECTIVE_ACK
        10, // Length: 10 bytes (1 SACK block)
        // First block: left edge = 0x12345678, right edge = 0x9ABCDEF0
        0x12,
        0x34,
        0x56,
        0x78,
        0x9A,
        0xBC,
        0xDE,
        0xF0,
    };

    var iter = TCPOptionsIterator.init(&data);
    const opt = try iter.next();

    try std.testing.expect(opt != null);
    try std.testing.expect(opt.? == .selective_ack);
    try std.testing.expectEqual(@as(u32, 0x12345678), opt.?.selective_ack.first_left);
    try std.testing.expectEqual(@as(u32, 0x9ABCDEF0), opt.?.selective_ack.first_right);
    try std.testing.expect(opt.?.selective_ack.blocks[0] == null);
}

test "TCPOptionsIterator - SACK with 2 blocks (18 bytes)" {
    const data = [_]u8{
        5, // KIND_SELECTIVE_ACK
        18, // Length: 18 bytes (2 SACK blocks)
        // First block
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x02,
        // Second block
        0x00,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x00,
        0x04,
    };

    var iter = TCPOptionsIterator.init(&data);
    const opt = try iter.next();

    try std.testing.expect(opt != null);
    try std.testing.expect(opt.? == .selective_ack);
    try std.testing.expectEqual(@as(u32, 1), opt.?.selective_ack.first_left);
    try std.testing.expectEqual(@as(u32, 2), opt.?.selective_ack.first_right);

    try std.testing.expect(opt.?.selective_ack.blocks[0] != null);
    try std.testing.expectEqual(@as(u32, 3), opt.?.selective_ack.blocks[0].?.left);
    try std.testing.expectEqual(@as(u32, 4), opt.?.selective_ack.blocks[0].?.right);
    try std.testing.expect(opt.?.selective_ack.blocks[1] == null);
}

test "TCPOptionsIterator - SACK with 4 blocks (34 bytes)" {
    const data = [_]u8{
        5, // KIND_SELECTIVE_ACK
        34, // Length: 34 bytes (4 SACK blocks)
        // First block
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x02,
        // Second block
        0x00,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x00,
        0x04,
        // Third block
        0x00,
        0x00,
        0x00,
        0x05,
        0x00,
        0x00,
        0x00,
        0x06,
        // Fourth block
        0x00,
        0x00,
        0x00,
        0x07,
        0x00,
        0x00,
        0x00,
        0x08,
    };

    var iter = TCPOptionsIterator.init(&data);
    const opt = try iter.next();

    try std.testing.expect(opt != null);
    try std.testing.expectEqual(@as(u32, 1), opt.?.selective_ack.first_left);
    try std.testing.expectEqual(@as(u32, 2), opt.?.selective_ack.first_right);
    try std.testing.expectEqual(@as(u32, 3), opt.?.selective_ack.blocks[0].?.left);
    try std.testing.expectEqual(@as(u32, 4), opt.?.selective_ack.blocks[0].?.right);
    try std.testing.expectEqual(@as(u32, 5), opt.?.selective_ack.blocks[1].?.left);
    try std.testing.expectEqual(@as(u32, 6), opt.?.selective_ack.blocks[1].?.right);
    try std.testing.expectEqual(@as(u32, 7), opt.?.selective_ack.blocks[2].?.left);
    try std.testing.expectEqual(@as(u32, 8), opt.?.selective_ack.blocks[2].?.right);
}

// Test SACK with INVALID lengths (should fail)
test "TCPOptionsIterator - SACK with invalid length 14" {
    const data = [_]u8{
        5, // KIND_SELECTIVE_ACK
        14, // Invalid length! (not 10, 18, 26, or 34)
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
    };

    var iter = TCPOptionsIterator.init(&data);
    const result = iter.next();

    // This should FAIL with current code because length validation is wrong!
    try std.testing.expectError(error.UnexpectedSize, result);
}

test "TCPOptionsIterator - SACK with invalid length 8" {
    const data = [_]u8{
        5, // KIND_SELECTIVE_ACK
        8, // Invalid length! Too short
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
    };

    var iter = TCPOptionsIterator.init(&data);
    const result = iter.next();

    // Should fail
    try std.testing.expectError(error.UnexpectedSize, result);
}

// Test basic iterator options
test "TCPOptionsIterator - NOOP" {
    const data = [_]u8{1}; // NOOP
    var iter = TCPOptionsIterator.init(&data);
    const opt = try iter.next();

    try std.testing.expect(opt != null);
    try std.testing.expect(opt.? == .noop);
}

test "TCPOptionsIterator - END stops iteration" {
    const data = [_]u8{0}; // END
    var iter = TCPOptionsIterator.init(&data);
    const opt = try iter.next();

    try std.testing.expect(opt == null);
}

test "TCPOptionsIterator - MSS" {
    const data = [_]u8{
        2, // KIND_MAXIMUM_SEGMENT_SIZE
        4, // Length
        0x05, 0xDC, // 1500
    };

    var iter = TCPOptionsIterator.init(&data);
    const opt = try iter.next();

    try std.testing.expect(opt != null);
    try std.testing.expect(opt.? == .maximum_segment_size);
    try std.testing.expectEqual(@as(u16, 1500), opt.?.maximum_segment_size);
}

test "TCPOptionsIterator - Timestamp" {
    const data = [_]u8{
        8, // KIND_TIMESTAMP
        10, // Length
        0x00, 0x00, 0x00, 0x01, // tsval = 1
        0x00, 0x00, 0x00, 0x02, // tsecr = 2
    };

    var iter = TCPOptionsIterator.init(&data);
    const opt = try iter.next();

    try std.testing.expect(opt != null);
    try std.testing.expect(opt.? == .timestamp);
    try std.testing.expectEqual(@as(u32, 1), opt.?.timestamp.tsval);
    try std.testing.expectEqual(@as(u32, 2), opt.?.timestamp.tsecr);
}

test "TCPOptionsIterator - Multiple options" {
    const data = [_]u8{
        1, // NOOP
        2, 4, 0x05, 0xDC, // MSS = 1500
        1, // NOOP
        4, 2, // SACK permitted
        0, // END
    };

    var iter = TCPOptionsIterator.init(&data);

    const opt1 = try iter.next();
    try std.testing.expect(opt1.? == .noop);

    const opt2 = try iter.next();
    try std.testing.expect(opt2.? == .maximum_segment_size);
    try std.testing.expectEqual(@as(u16, 1500), opt2.?.maximum_segment_size);

    const opt3 = try iter.next();
    try std.testing.expect(opt3.? == .noop);

    const opt4 = try iter.next();
    try std.testing.expect(opt4.? == .sack_permitted);

    const opt5 = try iter.next();
    try std.testing.expect(opt5 == null); // END
}
