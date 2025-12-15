//! ICMP header parsing
//! Based on RFC 792

const std = @import("std");

/// ICMP Header (8 bytes minimum)
pub const ICMPHeader = struct {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    rest_of_header: [4]u8,

    pub fn parse(data: []const u8) !ICMPHeader {
        if (data.len < 8) return error.InvalidLength;

        var rest_of_header: [4]u8 = undefined;
        @memcpy(&rest_of_header, data[4..8]);

        return ICMPHeader{
            .icmp_type = data[0],
            .code = data[1],
            .checksum = std.mem.readInt(u16, data[2..4], .big),
            .rest_of_header = rest_of_header,
        };
    }

    pub fn dump(self: ICMPHeader, writer: anytype) !void {
        try writer.writeAll("ICMP Header:\n");
        try writer.print("  Type: {} ({})\n", .{ self.icmp_type, icmpTypeName(self.icmp_type) });
        try writer.print("  Code: {}\n", .{self.code});
        try writer.print("  Checksum: 0x{x:0>4}\n", .{self.checksum});
    }
};

fn icmpTypeName(icmp_type: u8) []const u8 {
    return switch (icmp_type) {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        else => "Unknown",
    };
}
