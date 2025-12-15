//! Ethernet II header parsing

const std = @import("std");

/// Ethernet II Header (14 bytes)
pub const EthernetHeader = struct {
    destination: [6]u8,
    source: [6]u8,
    ether_type: u16,

    pub fn parse(data: []const u8) !EthernetHeader {
        if (data.len < 14) return error.InvalidLength;

        var destination: [6]u8 = undefined;
        var source: [6]u8 = undefined;
        @memcpy(&destination, data[0..6]);
        @memcpy(&source, data[6..12]);

        const ether_type = std.mem.readInt(u16, data[12..14], .big);

        return EthernetHeader{
            .destination = destination,
            .source = source,
            .ether_type = ether_type,
        };
    }

    pub fn dump(self: EthernetHeader, writer: anytype) !void {
        try writer.writeAll("Ethernet II Header:\n");
        try writer.writeAll("  Destination: ");
        try formatMac(self.destination, writer);
        try writer.writeAll("\n  Source: ");
        try formatMac(self.source, writer);
        try writer.print("\n  EtherType: 0x{x:0>4} ({})\n", .{
            self.ether_type,
            etherTypeName(self.ether_type),
        });
    }
};

fn formatMac(mac: [6]u8, writer: anytype) !void {
    try writer.print("{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    });
}

fn etherTypeName(ether_type: u16) []const u8 {
    return switch (ether_type) {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        0x8100 => "VLAN",
        else => "Unknown",
    };
}
