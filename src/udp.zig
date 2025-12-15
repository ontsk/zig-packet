//! UDP header parsing
//! Based on RFC 768

const std = @import("std");

/// UDP Header (8 bytes fixed)
pub const UDPHeader = struct {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,

    pub fn parse(data: []const u8) !UDPHeader {
        if (data.len < 8) return error.InvalidLength;

        return UDPHeader{
            .source_port = std.mem.readInt(u16, data[0..2], .big),
            .destination_port = std.mem.readInt(u16, data[2..4], .big),
            .length = std.mem.readInt(u16, data[4..6], .big),
            .checksum = std.mem.readInt(u16, data[6..8], .big),
        };
    }

    pub fn payloadLength(self: UDPHeader) usize {
        return if (self.length >= 8) self.length - 8 else 0;
    }

    pub fn dump(self: UDPHeader, writer: anytype) !void {
        try writer.writeAll("UDP Header:\n");
        try writer.print("  Source Port: {}\n", .{self.source_port});
        try writer.print("  Destination Port: {}\n", .{self.destination_port});
        try writer.print("  Length: {} bytes\n", .{self.length});
        try writer.print("  Checksum: 0x{x:0>4}\n", .{self.checksum});
        try writer.print("  Payload Length: {} bytes\n", .{self.payloadLength()});
    }
};
