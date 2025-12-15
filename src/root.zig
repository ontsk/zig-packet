//! etherparse-zig: Zero-allocation network packet parsing library
//!
//! A Zig port of the Rust etherparse library for parsing and writing
//! network packet protocols (Ethernet II, IPv4, IPv6, TCP, UDP, etc.)

const std = @import("std");

// Core modules
pub const ipv4 = @import("ipv4.zig");
pub const ipv6 = @import("ipv6.zig");
pub const tcp = @import("tcp.zig");
pub const udp = @import("udp.zig");
pub const icmp = @import("icmp.zig");
pub const ethernet = @import("ethernet.zig");

// Re-export commonly used types
pub const IPv4Header = ipv4.IPv4Header;
pub const TCPHeader = tcp.TCPHeader;
pub const UDPHeader = udp.UDPHeader;
pub const ICMPHeader = icmp.ICMPHeader;
pub const EthernetHeader = ethernet.EthernetHeader;

// Common error type
pub const ParseError = error{
    InvalidLength,
    InvalidVersion,
    InvalidHeaderLength,
    InvalidChecksum,
    UnsupportedProtocol,
};

// Protocol numbers (IANA assigned)
pub const IpProtocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    icmpv6 = 58,
    _,

    pub fn name(self: IpProtocol) []const u8 {
        return switch (self) {
            .icmp => "ICMP",
            .tcp => "TCP",
            .udp => "UDP",
            .icmpv6 => "ICMPv6",
            _ => "Unknown",
        };
    }
};

// EtherType values
pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86DD,
    vlan = 0x8100,
    _,

    pub fn name(self: EtherType) []const u8 {
        return switch (self) {
            .ipv4 => "IPv4",
            .arp => "ARP",
            .ipv6 => "IPv6",
            .vlan => "VLAN",
            _ => "Unknown",
        };
    }
};

test "import all modules" {
    std.testing.refAllDecls(@This());
}
