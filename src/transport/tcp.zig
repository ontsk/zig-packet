//! TCP header parsing and utilities
//! Based on RFC 793

const std = @import("std");

// ============================================================================
// Flow Identification (stateless utilities for connection tracking)
// ============================================================================

/// 5-tuple flow identifier for TCP connections.
/// Supports both IPv4 (as v6-mapped) and native IPv6 addresses.
/// This is a stateless utility - no allocations, suitable for use as hash key.
pub const Flow = struct {
    src_addr: [16]u8, // IPv4 stored as v6-mapped (::ffff:x.x.x.x) or native IPv6
    dst_addr: [16]u8,
    src_port: u16,
    dst_port: u16,
    is_ipv6: bool,

    /// Create a flow from IPv4 addresses
    pub fn fromIPv4(
        src_addr: [4]u8,
        dst_addr: [4]u8,
        src_port: u16,
        dst_port: u16,
    ) Flow {
        return .{
            .src_addr = mapIPv4toIPv6(src_addr),
            .dst_addr = mapIPv4toIPv6(dst_addr),
            .src_port = src_port,
            .dst_port = dst_port,
            .is_ipv6 = false,
        };
    }

    /// Create a flow from IPv6 addresses
    pub fn fromIPv6(
        src_addr: [16]u8,
        dst_addr: [16]u8,
        src_port: u16,
        dst_port: u16,
    ) Flow {
        return .{
            .src_addr = src_addr,
            .dst_addr = dst_addr,
            .src_port = src_port,
            .dst_port = dst_port,
            .is_ipv6 = true,
        };
    }

    /// Returns the reverse flow (swap src/dst)
    pub fn reverse(self: Flow) Flow {
        return .{
            .src_addr = self.dst_addr,
            .dst_addr = self.src_addr,
            .src_port = self.dst_port,
            .dst_port = self.src_port,
            .is_ipv6 = self.is_ipv6,
        };
    }

    /// Hash function for use in hash maps
    pub fn hash(self: Flow) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&self.src_addr);
        hasher.update(&self.dst_addr);
        hasher.update(std.mem.asBytes(&self.src_port));
        hasher.update(std.mem.asBytes(&self.dst_port));
        return hasher.final();
    }

    /// Equality check for use in hash maps
    pub fn eql(self: Flow, other: Flow) bool {
        return std.mem.eql(u8, &self.src_addr, &other.src_addr) and
            std.mem.eql(u8, &self.dst_addr, &other.dst_addr) and
            self.src_port == other.src_port and
            self.dst_port == other.dst_port;
    }

    /// HashMap context for std.HashMap
    pub const HashContext = struct {
        pub fn hash(_: HashContext, flow: Flow) u64 {
            return flow.hash();
        }

        pub fn eql(_: HashContext, a: Flow, b: Flow) bool {
            return a.eql(b);
        }
    };

    /// Convert IPv4 address to IPv6-mapped format (::ffff:x.x.x.x)
    fn mapIPv4toIPv6(ipv4: [4]u8) [16]u8 {
        return .{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0xff, 0xff, // IPv6-mapped prefix
            ipv4[0], ipv4[1], ipv4[2], ipv4[3],
        };
    }

    /// Extract IPv4 address if this is an IPv4 flow
    pub fn getIPv4Src(self: Flow) ?[4]u8 {
        if (self.is_ipv6) return null;
        return .{ self.src_addr[12], self.src_addr[13], self.src_addr[14], self.src_addr[15] };
    }

    /// Extract IPv4 address if this is an IPv4 flow
    pub fn getIPv4Dst(self: Flow) ?[4]u8 {
        if (self.is_ipv6) return null;
        return .{ self.dst_addr[12], self.dst_addr[13], self.dst_addr[14], self.dst_addr[15] };
    }

    /// Format the flow for debugging
    pub fn format(
        self: Flow,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (self.is_ipv6) {
            try writer.print("[{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}]:{} -> [{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}]:{}", .{
                std.mem.readInt(u16, self.src_addr[0..2], .big),
                std.mem.readInt(u16, self.src_addr[2..4], .big),
                std.mem.readInt(u16, self.src_addr[4..6], .big),
                std.mem.readInt(u16, self.src_addr[6..8], .big),
                std.mem.readInt(u16, self.src_addr[8..10], .big),
                std.mem.readInt(u16, self.src_addr[10..12], .big),
                std.mem.readInt(u16, self.src_addr[12..14], .big),
                std.mem.readInt(u16, self.src_addr[14..16], .big),
                self.src_port,
                std.mem.readInt(u16, self.dst_addr[0..2], .big),
                std.mem.readInt(u16, self.dst_addr[2..4], .big),
                std.mem.readInt(u16, self.dst_addr[4..6], .big),
                std.mem.readInt(u16, self.dst_addr[6..8], .big),
                std.mem.readInt(u16, self.dst_addr[8..10], .big),
                std.mem.readInt(u16, self.dst_addr[10..12], .big),
                std.mem.readInt(u16, self.dst_addr[12..14], .big),
                std.mem.readInt(u16, self.dst_addr[14..16], .big),
                self.dst_port,
            });
        } else {
            const src = self.getIPv4Src().?;
            const dst = self.getIPv4Dst().?;
            try writer.print("{}.{}.{}.{}:{} -> {}.{}.{}.{}:{}", .{
                src[0], src[1], src[2], src[3], self.src_port,
                dst[0], dst[1], dst[2], dst[3], self.dst_port,
            });
        }
    }
};

// ============================================================================
// Sequence Number Arithmetic (handles 32-bit wraparound per RFC 793)
// ============================================================================

/// TCP sequence number with proper wraparound arithmetic.
/// TCP sequence numbers are 32-bit and wrap around, requiring special
/// comparison logic (RFC 793 Section 3.3).
pub const SeqNum = struct {
    value: u32,

    /// Create a SeqNum from a raw u32 value
    pub fn init(value: u32) SeqNum {
        return .{ .value = value };
    }

    /// Calculate signed difference between two sequence numbers.
    /// Handles 32-bit wraparound correctly.
    /// Returns positive if self > other, negative if self < other.
    pub fn diff(self: SeqNum, other: SeqNum) i33 {
        // Two's complement subtraction handles wraparound
        const raw_diff: i32 = @bitCast(self.value -% other.value);
        return @as(i33, raw_diff);
    }

    /// Check if self < other (with wraparound handling)
    pub fn lessThan(self: SeqNum, other: SeqNum) bool {
        return self.diff(other) < 0;
    }

    /// Check if self <= other (with wraparound handling)
    pub fn lessThanOrEqual(self: SeqNum, other: SeqNum) bool {
        return self.diff(other) <= 0;
    }

    /// Check if self > other (with wraparound handling)
    pub fn greaterThan(self: SeqNum, other: SeqNum) bool {
        return self.diff(other) > 0;
    }

    /// Check if self >= other (with wraparound handling)
    pub fn greaterThanOrEqual(self: SeqNum, other: SeqNum) bool {
        return self.diff(other) >= 0;
    }

    /// Add an offset to the sequence number (wraps around)
    pub fn add(self: SeqNum, offset: u32) SeqNum {
        return .{ .value = self.value +% offset };
    }

    /// Subtract an offset from the sequence number (wraps around)
    pub fn sub(self: SeqNum, offset: u32) SeqNum {
        return .{ .value = self.value -% offset };
    }

    /// Format for debugging
    pub fn format(
        self: SeqNum,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{}", .{self.value});
    }
};

// ============================================================================
// TCP Option Constants and Types
// ============================================================================

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

// ============================================================================
// Flow and SeqNum Tests
// ============================================================================

test "Flow - IPv4 creation and reverse" {
    const flow = Flow.fromIPv4(
        .{ 192, 168, 1, 1 },
        .{ 10, 0, 0, 1 },
        12345,
        80,
    );

    try std.testing.expectEqual(@as(u16, 12345), flow.src_port);
    try std.testing.expectEqual(@as(u16, 80), flow.dst_port);
    try std.testing.expect(!flow.is_ipv6);

    const src = flow.getIPv4Src().?;
    try std.testing.expectEqual(@as(u8, 192), src[0]);
    try std.testing.expectEqual(@as(u8, 168), src[1]);
    try std.testing.expectEqual(@as(u8, 1), src[2]);
    try std.testing.expectEqual(@as(u8, 1), src[3]);

    const reversed = flow.reverse();
    try std.testing.expectEqual(@as(u16, 80), reversed.src_port);
    try std.testing.expectEqual(@as(u16, 12345), reversed.dst_port);

    const rev_src = reversed.getIPv4Src().?;
    try std.testing.expectEqual(@as(u8, 10), rev_src[0]);
    try std.testing.expectEqual(@as(u8, 0), rev_src[1]);
    try std.testing.expectEqual(@as(u8, 0), rev_src[2]);
    try std.testing.expectEqual(@as(u8, 1), rev_src[3]);
}

test "Flow - IPv6 creation" {
    const src_addr = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst_addr = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

    const flow = Flow.fromIPv6(src_addr, dst_addr, 443, 8080);

    try std.testing.expect(flow.is_ipv6);
    try std.testing.expectEqual(@as(u16, 443), flow.src_port);
    try std.testing.expectEqual(@as(u16, 8080), flow.dst_port);
    try std.testing.expect(flow.getIPv4Src() == null); // Not IPv4
}

test "Flow - hash and equality" {
    const flow1 = Flow.fromIPv4(.{ 192, 168, 1, 1 }, .{ 10, 0, 0, 1 }, 12345, 80);
    const flow2 = Flow.fromIPv4(.{ 192, 168, 1, 1 }, .{ 10, 0, 0, 1 }, 12345, 80);
    const flow3 = Flow.fromIPv4(.{ 192, 168, 1, 2 }, .{ 10, 0, 0, 1 }, 12345, 80);

    try std.testing.expect(flow1.eql(flow2));
    try std.testing.expect(!flow1.eql(flow3));
    try std.testing.expectEqual(flow1.hash(), flow2.hash());
    try std.testing.expect(flow1.hash() != flow3.hash());
}

test "Flow - HashMap integration" {
    var map = std.HashMap(Flow, u32, Flow.HashContext, 80).init(std.testing.allocator);
    defer map.deinit();

    const flow1 = Flow.fromIPv4(.{ 192, 168, 1, 1 }, .{ 10, 0, 0, 1 }, 12345, 80);
    const flow2 = Flow.fromIPv4(.{ 192, 168, 1, 2 }, .{ 10, 0, 0, 1 }, 12346, 80);

    try map.put(flow1, 100);
    try map.put(flow2, 200);

    try std.testing.expectEqual(@as(u32, 100), map.get(flow1).?);
    try std.testing.expectEqual(@as(u32, 200), map.get(flow2).?);
}

test "SeqNum - basic operations" {
    const seq1 = SeqNum.init(1000);
    const seq2 = SeqNum.init(2000);

    try std.testing.expect(seq1.lessThan(seq2));
    try std.testing.expect(seq2.greaterThan(seq1));
    try std.testing.expect(!seq1.greaterThan(seq2));
    try std.testing.expect(seq1.lessThanOrEqual(seq2));
    try std.testing.expect(seq2.greaterThanOrEqual(seq1));
}

test "SeqNum - wraparound comparison" {
    // Test wraparound: 0xFFFFFF00 should be "less than" 0x00000100
    // because 0x00000100 is "ahead" in the sequence space
    const near_max = SeqNum.init(0xFFFFFF00);
    const after_wrap = SeqNum.init(0x00000100);

    // after_wrap is 512 bytes ahead of near_max (with wraparound)
    try std.testing.expect(near_max.lessThan(after_wrap));
    try std.testing.expect(after_wrap.greaterThan(near_max));

    // Difference should be positive (after_wrap - near_max = 512)
    const diff = after_wrap.diff(near_max);
    try std.testing.expectEqual(@as(i33, 512), diff);
}

test "SeqNum - add and subtract" {
    const seq = SeqNum.init(100);

    const added = seq.add(50);
    try std.testing.expectEqual(@as(u32, 150), added.value);

    const subtracted = seq.sub(50);
    try std.testing.expectEqual(@as(u32, 50), subtracted.value);

    // Test wraparound add
    const near_max = SeqNum.init(0xFFFFFFF0);
    const wrapped = near_max.add(0x20);
    try std.testing.expectEqual(@as(u32, 0x10), wrapped.value);
}

test "SeqNum - diff calculation" {
    const a = SeqNum.init(1000);
    const b = SeqNum.init(500);

    try std.testing.expectEqual(@as(i33, 500), a.diff(b)); // a - b = 500
    try std.testing.expectEqual(@as(i33, -500), b.diff(a)); // b - a = -500
}
