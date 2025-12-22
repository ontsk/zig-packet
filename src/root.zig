//! etherparse-zig: Zero-allocation network packet parsing library
//!
//! A Zig port of the Rust etherparse library for parsing and writing
//! network packet protocols (Ethernet II, IPv4, IPv6, TCP, UDP, etc.)

const std = @import("std");

// Layer 2 - Link Layer
pub const ethernet = @import("link/ethernet.zig");

// Layer 3 - Network Layer (net/)
pub const ipv4 = @import("net/ipv4.zig");
pub const ipv6 = @import("net/ipv6.zig");
pub const icmp = @import("net/icmp.zig");

// Layer 4 - Transport Layer
pub const tcp = @import("transport/tcp.zig");
pub const udp = @import("transport/udp.zig");

// Application Layer Protocols
pub const dns = @import("dns.zig");

// Stream Processing (stateful, requires allocator)
pub const reassembly = struct {
    pub const Assembler = @import("reassembly/assembler.zig").Assembler;
    pub const Event = @import("reassembly/assembler.zig").Event;
    pub const EndReason = @import("reassembly/assembler.zig").EndReason;
    pub const Config = @import("reassembly/assembler.zig").Config;
    pub const PagePool = @import("reassembly/page.zig").PagePool;
    pub const Page = @import("reassembly/page.zig").Page;
    pub const Connection = @import("reassembly/connection.zig").Connection;
    pub const HalfConnection = @import("reassembly/connection.zig").HalfConnection;
};

// Re-export commonly used types for convenience
pub const EthernetHeader = ethernet.EthernetHeader;
pub const IPv4Header = ipv4.IPv4Header;
pub const IPv6Header = ipv6.IPv6Header;
pub const ICMPHeader = icmp.ICMPHeader;
pub const TCPHeader = tcp.TCPHeader;
pub const UDPHeader = udp.UDPHeader;

// TCP flow tracking types
pub const Flow = tcp.Flow;
pub const SeqNum = tcp.SeqNum;

// DNS types
pub const DNSHeader = dns.DNSHeader;
pub const DNSMessage = dns.DNSMessage;
pub const DNSQuestion = dns.DNSQuestion;
pub const DNSResourceRecord = dns.DNSResourceRecord;
pub const DNSName = dns.DNSName;

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

    // Import reassembly tests
    _ = @import("reassembly/page.zig");
    _ = @import("reassembly/connection.zig");
    _ = @import("reassembly/assembler.zig");

    // Import DNS tests
    _ = @import("dns.zig");
}
