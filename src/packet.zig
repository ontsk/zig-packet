//! Main packet parsing library entry point
//!
//! This module provides convenient access to all protocol parsers organized by OSI layer.
//! You can use either this module or root.zig - they provide the same exports.
//!
//! ## Usage Examples
//!
//! ```zig
//! const packet = @import("packet");
//!
//! // Parse IPv4 packet
//! const ip = try packet.ipv4.IPv4Header.parse(data);
//!
//! // Parse TCP segment
//! const tcp_data = data[ip.headerLength()..];
//! const tcp = try packet.tcp.TCPHeader.parse(tcp_data);
//!
//! // Iterate TCP options
//! var iter = tcp.getOptions().iter();
//! while (try iter.next()) |opt| {
//!     // Process options
//! }
//! ```

// Re-export everything from root
pub usingnamespace @import("root.zig");
