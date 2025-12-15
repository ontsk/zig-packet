//! IPv4 header parsing and serialization
//! Based on RFC 791

const std = @import("std");

/// IPv4 Header (20 bytes minimum, up to 60 bytes with options)
/// All multi-byte fields are in network byte order (big-endian)
pub const IPv4Header = struct {
    /// IP version (always 4 for IPv4)
    version: u4,
    /// Internet Header Length (number of 32-bit words, minimum 5)
    ihl: u4,
    /// Type of Service / Differentiated Services Code Point
    dscp: u6,
    /// Explicit Congestion Notification
    ecn: u2,
    /// Total packet length (header + payload, max 65535)
    total_length: u16,
    /// Identification field for fragmentation
    identification: u16,
    /// Flags: [reserved, DF (Don't Fragment), MF (More Fragments)]
    flags: Flags,
    /// Fragment offset (in 8-byte blocks)
    fragment_offset: u13,
    /// Time To Live
    ttl: u8,
    /// Protocol number (6=TCP, 17=UDP, 1=ICMP)
    protocol: u8,
    /// Header checksum
    checksum: u16,
    /// Source IP address
    source: [4]u8,
    /// Destination IP address
    destination: [4]u8,
    /// IP options (if IHL > 5)
    options: []const u8,

    pub const Flags = packed struct {
        reserved: bool = false,
        dont_fragment: bool = false,
        more_fragments: bool = false,
    };

    /// Parse IPv4 header from raw bytes (zero-copy)
    pub fn parse(data: []const u8) !IPv4Header {
        if (data.len < 20) return error.InvalidLength;

        const version_ihl = data[0];
        const version = @as(u4, @truncate(version_ihl >> 4));
        const ihl = @as(u4, @truncate(version_ihl & 0x0F));

        if (version != 4) return error.InvalidVersion;
        if (ihl < 5) return error.InvalidHeaderLength;

        const header_len: usize = @as(usize, ihl) * 4;
        if (data.len < header_len) return error.InvalidLength;

        // Parse DSCP and ECN from TOS byte
        const tos = data[1];
        const dscp = @as(u6, @truncate(tos >> 2));
        const ecn = @as(u2, @truncate(tos & 0x03));

        const total_length = std.mem.readInt(u16, data[2..4], .big);
        const identification = std.mem.readInt(u16, data[4..6], .big);

        // Parse flags and fragment offset
        const flags_frag = std.mem.readInt(u16, data[6..8], .big);
        const flags = Flags{
            .reserved = (flags_frag & 0x8000) != 0,
            .dont_fragment = (flags_frag & 0x4000) != 0,
            .more_fragments = (flags_frag & 0x2000) != 0,
        };
        const fragment_offset = @as(u13, @truncate(flags_frag & 0x1FFF));

        const ttl = data[8];
        const protocol = data[9];
        const checksum = std.mem.readInt(u16, data[10..12], .big);

        var source: [4]u8 = undefined;
        var destination: [4]u8 = undefined;
        @memcpy(&source, data[12..16]);
        @memcpy(&destination, data[16..20]);

        const options = if (header_len > 20) data[20..header_len] else &[_]u8{};

        return IPv4Header{
            .version = version,
            .ihl = ihl,
            .dscp = dscp,
            .ecn = ecn,
            .total_length = total_length,
            .identification = identification,
            .flags = flags,
            .fragment_offset = fragment_offset,
            .ttl = ttl,
            .protocol = protocol,
            .checksum = checksum,
            .source = source,
            .destination = destination,
            .options = options,
        };
    }

    /// Get the header length in bytes
    pub fn headerLength(self: IPv4Header) usize {
        return @as(usize, self.ihl) * 4;
    }

    /// Get the payload length (total_length - header_length)
    pub fn payloadLength(self: IPv4Header) usize {
        const header_len = self.headerLength();
        return if (self.total_length >= header_len)
            self.total_length - header_len
        else
            0;
    }

    /// Check if packet is fragmented
    pub fn isFragmented(self: IPv4Header) bool {
        return self.flags.more_fragments or self.fragment_offset != 0;
    }

    /// Format source IP as string
    pub fn formatSource(self: IPv4Header, writer: anytype) !void {
        try writer.print("{}.{}.{}.{}", .{
            self.source[0],
            self.source[1],
            self.source[2],
            self.source[3],
        });
    }

    /// Format destination IP as string
    pub fn formatDestination(self: IPv4Header, writer: anytype) !void {
        try writer.print("{}.{}.{}.{}", .{
            self.destination[0],
            self.destination[1],
            self.destination[2],
            self.destination[3],
        });
    }

    /// Dump header information for debugging
    pub fn dump(self: IPv4Header) void {
        std.debug.print("IPv4 Header:\n", .{});
        std.debug.print("  Version: {}\n", .{self.version});
        std.debug.print("  IHL: {} ({} bytes)\n", .{ self.ihl, self.headerLength() });
        std.debug.print("  DSCP: 0x{x:0>2}, ECN: 0x{x}\n", .{ self.dscp, self.ecn });
        std.debug.print("  Total Length: {} bytes\n", .{self.total_length});
        std.debug.print("  Identification: 0x{x:0>4}\n", .{self.identification});
        std.debug.print("  Flags: DF={}, MF={}\n", .{
            self.flags.dont_fragment,
            self.flags.more_fragments,
        });
        std.debug.print("  Fragment Offset: {}\n", .{self.fragment_offset});
        std.debug.print("  TTL: {}\n", .{self.ttl});
        std.debug.print("  Protocol: {} ({s})\n", .{ self.protocol, protocolName(self.protocol) });
        std.debug.print("  Checksum: 0x{x:0>4}\n", .{self.checksum});
        std.debug.print("  Source: {}.{}.{}.{}\n", .{
            self.source[0],
            self.source[1],
            self.source[2],
            self.source[3],
        });
        std.debug.print("  Destination: {}.{}.{}.{}\n", .{
            self.destination[0],
            self.destination[1],
            self.destination[2],
            self.destination[3],
        });
        if (self.options.len > 0) {
            std.debug.print("  Options: {} bytes\n", .{self.options.len});
        }
    }
};

fn protocolName(protocol: u8) []const u8 {
    return switch (protocol) {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        else => "Unknown",
    };
}

// Tests
test "IPv4Header.parse - minimal header" {
    // Minimal IPv4 header (20 bytes, no options)
    const data = [_]u8{
        0x45, // Version=4, IHL=5
        0x00, // DSCP=0, ECN=0
        0x00, 0x3c, // Total Length = 60
        0x1c, 0x46, // Identification
        0x40, 0x00, // Flags: DF=1, Fragment Offset=0
        0x40, // TTL=64
        0x06, // Protocol=TCP
        0xb1, 0xe6, // Checksum
        0xc0, 0xa8, 0x01, 0x64, // Source: 192.168.1.100
        0xc0, 0xa8, 0x01, 0x01, // Dest: 192.168.1.1
    };

    const header = try IPv4Header.parse(&data);

    try std.testing.expectEqual(@as(u4, 4), header.version);
    try std.testing.expectEqual(@as(u4, 5), header.ihl);
    try std.testing.expectEqual(@as(u16, 60), header.total_length);
    try std.testing.expectEqual(@as(u8, 64), header.ttl);
    try std.testing.expectEqual(@as(u8, 6), header.protocol);
    try std.testing.expect(header.flags.dont_fragment);
    try std.testing.expect(!header.flags.more_fragments);
    try std.testing.expectEqual(@as(usize, 20), header.headerLength());
    try std.testing.expectEqual(@as(usize, 40), header.payloadLength());
}

test "IPv4Header.parse - invalid version" {
    const data = [_]u8{
        0x55, // Version=5 (invalid)
        0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
    };

    try std.testing.expectError(error.InvalidVersion, IPv4Header.parse(&data));
}

test "IPv4Header.parse - too short" {
    const data = [_]u8{ 0x45, 0x00, 0x00 }; // Only 3 bytes
    try std.testing.expectError(error.InvalidLength, IPv4Header.parse(&data));
}
