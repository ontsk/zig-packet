//! DNS message parsing (RFC 1035)
//!
//! Zero-copy DNS packet parsing supporting:
//! - Header parsing (ID, flags, counts)
//! - Question section parsing
//! - Resource record parsing (answers, authority, additional)
//! - Name compression (pointer handling)

const std = @import("std");

// ============================================================================
// DNS Constants
// ============================================================================

/// DNS record types (RFC 1035 + common extensions)
pub const RecordType = enum(u16) {
    A = 1, // IPv4 address
    NS = 2, // Name server
    CNAME = 5, // Canonical name
    SOA = 6, // Start of authority
    PTR = 12, // Pointer record
    MX = 15, // Mail exchange
    TXT = 16, // Text record
    AAAA = 28, // IPv6 address
    SRV = 33, // Service record
    OPT = 41, // EDNS option
    ANY = 255, // Any record
    _,

    pub fn name(self: RecordType) []const u8 {
        return switch (self) {
            .A => "A",
            .NS => "NS",
            .CNAME => "CNAME",
            .SOA => "SOA",
            .PTR => "PTR",
            .MX => "MX",
            .TXT => "TXT",
            .AAAA => "AAAA",
            .SRV => "SRV",
            .OPT => "OPT",
            .ANY => "ANY",
            _ => "UNKNOWN",
        };
    }
};

/// DNS record classes
pub const RecordClass = enum(u16) {
    IN = 1, // Internet
    CS = 2, // CSNET (obsolete)
    CH = 3, // CHAOS
    HS = 4, // Hesiod
    ANY = 255, // Any class
    _,

    pub fn name(self: RecordClass) []const u8 {
        return switch (self) {
            .IN => "IN",
            .CS => "CS",
            .CH => "CH",
            .HS => "HS",
            .ANY => "ANY",
            _ => "UNKNOWN",
        };
    }
};

/// DNS response codes
pub const ResponseCode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3, // NXDOMAIN
    not_implemented = 4,
    refused = 5,
    _,

    pub fn name(self: ResponseCode) []const u8 {
        return switch (self) {
            .no_error => "NOERROR",
            .format_error => "FORMERR",
            .server_failure => "SERVFAIL",
            .name_error => "NXDOMAIN",
            .not_implemented => "NOTIMP",
            .refused => "REFUSED",
            _ => "UNKNOWN",
        };
    }
};

/// DNS opcode
pub const Opcode = enum(u4) {
    query = 0,
    iquery = 1, // Inverse query (obsolete)
    status = 2,
    notify = 4,
    update = 5,
    _,
};

// ============================================================================
// DNS Header
// ============================================================================

/// DNS message header (12 bytes)
/// RFC 1035 Section 4.1.1
pub const DNSHeader = struct {
    /// Message identifier
    id: u16,
    /// Query/Response flag (false = query, true = response)
    qr: bool,
    /// Operation code
    opcode: Opcode,
    /// Authoritative Answer flag
    aa: bool,
    /// Truncation flag
    tc: bool,
    /// Recursion Desired flag
    rd: bool,
    /// Recursion Available flag
    ra: bool,
    /// Response code
    rcode: ResponseCode,
    /// Number of questions
    qdcount: u16,
    /// Number of answers
    ancount: u16,
    /// Number of authority records
    nscount: u16,
    /// Number of additional records
    arcount: u16,

    pub const SIZE: usize = 12;

    pub const ParseError = error{
        InvalidLength,
    };

    /// Parse DNS header from raw bytes
    pub fn parse(data: []const u8) ParseError!DNSHeader {
        if (data.len < SIZE) {
            return error.InvalidLength;
        }

        const flags = std.mem.readInt(u16, data[2..4], .big);

        return .{
            .id = std.mem.readInt(u16, data[0..2], .big),
            .qr = (flags & 0x8000) != 0,
            .opcode = @enumFromInt(@as(u4, @truncate((flags >> 11) & 0xF))),
            .aa = (flags & 0x0400) != 0,
            .tc = (flags & 0x0200) != 0,
            .rd = (flags & 0x0100) != 0,
            .ra = (flags & 0x0080) != 0,
            .rcode = @enumFromInt(@as(u4, @truncate(flags & 0xF))),
            .qdcount = std.mem.readInt(u16, data[4..6], .big),
            .ancount = std.mem.readInt(u16, data[6..8], .big),
            .nscount = std.mem.readInt(u16, data[8..10], .big),
            .arcount = std.mem.readInt(u16, data[10..12], .big),
        };
    }

    /// Check if this is a query
    pub fn isQuery(self: DNSHeader) bool {
        return !self.qr;
    }

    /// Check if this is a response
    pub fn isResponse(self: DNSHeader) bool {
        return self.qr;
    }

    /// Get total number of records (all sections)
    pub fn totalRecords(self: DNSHeader) u32 {
        return @as(u32, self.qdcount) + @as(u32, self.ancount) +
            @as(u32, self.nscount) + @as(u32, self.arcount);
    }

    /// Format header for debugging
    pub fn format(
        self: DNSHeader,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("DNS {{ id=0x{x:0>4}, {s}, opcode={s}, rcode={s}, qd={}, an={}, ns={}, ar={} }}", .{
            self.id,
            if (self.qr) "RESPONSE" else "QUERY",
            @tagName(self.opcode),
            self.rcode.name(),
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        });
    }
};

// ============================================================================
// DNS Name (with compression support)
// ============================================================================

/// Maximum DNS name length (RFC 1035)
pub const MAX_NAME_LENGTH: usize = 255;
/// Maximum label length
pub const MAX_LABEL_LENGTH: usize = 63;
/// Compression pointer mask
const COMPRESSION_MASK: u8 = 0xC0;

/// DNS name with compression support
/// Stores a reference to the original packet for pointer resolution
pub const DNSName = struct {
    /// Reference to full DNS message (for pointer resolution)
    message: []const u8,
    /// Offset where this name starts in the message
    offset: usize,
    /// Parsed length in the original data (including any pointers)
    wire_length: usize,

    pub const ParseError = error{
        InvalidLength,
        InvalidPointer,
        PointerLoop,
        NameTooLong,
        LabelTooLong,
    };

    /// Parse a DNS name starting at the given offset
    /// Returns the name and advances past it in the wire format
    pub fn parse(message: []const u8, start_offset: usize) ParseError!DNSName {
        if (start_offset >= message.len) {
            return error.InvalidLength;
        }

        // Calculate wire length (how many bytes this name occupies in the original position)
        var wire_len: usize = 0;
        var offset = start_offset;
        var followed_pointer = false;

        while (offset < message.len) {
            const len_byte = message[offset];

            if (len_byte == 0) {
                // End of name
                if (!followed_pointer) {
                    wire_len += 1;
                }
                break;
            } else if ((len_byte & COMPRESSION_MASK) == COMPRESSION_MASK) {
                // Compression pointer
                if (offset + 1 >= message.len) {
                    return error.InvalidLength;
                }
                if (!followed_pointer) {
                    wire_len += 2;
                    followed_pointer = true;
                }
                // Follow the pointer
                const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | @as(u16, message[offset + 1]);
                if (ptr_offset >= offset) {
                    return error.InvalidPointer; // Must point backwards
                }
                offset = ptr_offset;
            } else {
                // Regular label
                if (len_byte > MAX_LABEL_LENGTH) {
                    return error.LabelTooLong;
                }
                const label_len = @as(usize, len_byte);
                if (offset + 1 + label_len > message.len) {
                    return error.InvalidLength;
                }
                if (!followed_pointer) {
                    wire_len += 1 + label_len;
                }
                offset += 1 + label_len;
            }
        }

        return .{
            .message = message,
            .offset = start_offset,
            .wire_length = wire_len,
        };
    }

    /// Get an iterator over the labels in this name
    pub fn labelIterator(self: DNSName) LabelIterator {
        return .{
            .message = self.message,
            .offset = self.offset,
            .jumps = 0,
        };
    }

    /// Write the name to a buffer in dotted format (e.g., "www.example.com")
    /// Returns the number of bytes written
    pub fn writeTo(self: DNSName, buffer: []u8) ParseError!usize {
        var iter = self.labelIterator();
        var pos: usize = 0;
        var first = true;

        while (try iter.next()) |label| {
            if (!first) {
                if (pos >= buffer.len) return error.NameTooLong;
                buffer[pos] = '.';
                pos += 1;
            }
            first = false;

            if (pos + label.len > buffer.len) return error.NameTooLong;
            @memcpy(buffer[pos..][0..label.len], label);
            pos += label.len;
        }

        return pos;
    }

    /// Compare two DNS names (case-insensitive per RFC 1035)
    pub fn eql(self: DNSName, other: DNSName) bool {
        var iter1 = self.labelIterator();
        var iter2 = other.labelIterator();

        while (true) {
            const label1 = iter1.next() catch return false;
            const label2 = iter2.next() catch return false;

            if (label1 == null and label2 == null) return true;
            if (label1 == null or label2 == null) return false;

            if (!std.ascii.eqlIgnoreCase(label1.?, label2.?)) return false;
        }
    }

    /// Format name for debugging
    pub fn format(
        self: DNSName,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var iter = self.labelIterator();
        var first = true;
        while (iter.next() catch null) |label| {
            if (!first) try writer.writeByte('.');
            first = false;
            try writer.writeAll(label);
        }
        if (first) try writer.writeByte('.'); // Root domain
    }
};

/// Iterator over DNS name labels
pub const LabelIterator = struct {
    message: []const u8,
    offset: usize,
    jumps: u8,

    const MAX_JUMPS: u8 = 128; // Prevent infinite loops

    pub fn next(self: *LabelIterator) DNSName.ParseError!?[]const u8 {
        while (self.offset < self.message.len) {
            const len_byte = self.message[self.offset];

            if (len_byte == 0) {
                return null; // End of name
            } else if ((len_byte & COMPRESSION_MASK) == COMPRESSION_MASK) {
                // Compression pointer
                if (self.offset + 1 >= self.message.len) {
                    return error.InvalidLength;
                }
                if (self.jumps >= MAX_JUMPS) {
                    return error.PointerLoop;
                }
                self.jumps += 1;
                const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | @as(u16, self.message[self.offset + 1]);
                self.offset = ptr_offset;
            } else {
                // Regular label
                const label_len = @as(usize, len_byte);
                if (self.offset + 1 + label_len > self.message.len) {
                    return error.InvalidLength;
                }
                const label = self.message[self.offset + 1 ..][0..label_len];
                self.offset += 1 + label_len;
                return label;
            }
        }
        return error.InvalidLength;
    }
};

// ============================================================================
// DNS Question
// ============================================================================

/// DNS question entry
pub const DNSQuestion = struct {
    /// Query name
    name: DNSName,
    /// Query type
    qtype: RecordType,
    /// Query class
    qclass: RecordClass,
    /// Total bytes consumed in wire format
    wire_length: usize,

    pub const ParseError = DNSName.ParseError || error{InvalidLength};

    /// Parse a question from the message at the given offset
    pub fn parse(message: []const u8, offset: usize) ParseError!DNSQuestion {
        const name = try DNSName.parse(message, offset);
        const after_name = offset + name.wire_length;

        if (after_name + 4 > message.len) {
            return error.InvalidLength;
        }

        return .{
            .name = name,
            .qtype = @enumFromInt(std.mem.readInt(u16, message[after_name..][0..2], .big)),
            .qclass = @enumFromInt(std.mem.readInt(u16, message[after_name + 2 ..][0..2], .big)),
            .wire_length = name.wire_length + 4,
        };
    }

    /// Format for debugging
    pub fn format(
        self: DNSQuestion,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{} {s} {s}", .{ self.name, self.qclass.name(), self.qtype.name() });
    }
};

// ============================================================================
// DNS Resource Record
// ============================================================================

/// DNS resource record (answer, authority, or additional)
pub const DNSResourceRecord = struct {
    /// Record name
    name: DNSName,
    /// Record type
    rtype: RecordType,
    /// Record class
    rclass: RecordClass,
    /// Time to live (seconds)
    ttl: u32,
    /// Record data (raw bytes)
    rdata: []const u8,
    /// Total bytes consumed in wire format
    wire_length: usize,
    /// Reference to full message (for parsing rdata with names)
    message: []const u8,
    /// Offset where rdata starts
    rdata_offset: usize,

    pub const ParseError = DNSName.ParseError || error{InvalidLength};

    /// Parse a resource record from the message at the given offset
    pub fn parse(message: []const u8, offset: usize) ParseError!DNSResourceRecord {
        const name = try DNSName.parse(message, offset);
        const after_name = offset + name.wire_length;

        if (after_name + 10 > message.len) {
            return error.InvalidLength;
        }

        const rdlength = std.mem.readInt(u16, message[after_name + 8 ..][0..2], .big);
        const rdata_start = after_name + 10;

        if (rdata_start + rdlength > message.len) {
            return error.InvalidLength;
        }

        return .{
            .name = name,
            .rtype = @enumFromInt(std.mem.readInt(u16, message[after_name..][0..2], .big)),
            .rclass = @enumFromInt(std.mem.readInt(u16, message[after_name + 2 ..][0..2], .big)),
            .ttl = std.mem.readInt(u32, message[after_name + 4 ..][0..4], .big),
            .rdata = message[rdata_start..][0..rdlength],
            .wire_length = name.wire_length + 10 + rdlength,
            .message = message,
            .rdata_offset = rdata_start,
        };
    }

    /// Get A record (IPv4 address)
    pub fn getA(self: DNSResourceRecord) ?[4]u8 {
        if (self.rtype != .A or self.rdata.len != 4) return null;
        return self.rdata[0..4].*;
    }

    /// Get AAAA record (IPv6 address)
    pub fn getAAAA(self: DNSResourceRecord) ?[16]u8 {
        if (self.rtype != .AAAA or self.rdata.len != 16) return null;
        return self.rdata[0..16].*;
    }

    /// Get CNAME/NS/PTR target name
    pub fn getNameTarget(self: DNSResourceRecord) ?DNSName {
        if (self.rtype != .CNAME and self.rtype != .NS and self.rtype != .PTR) return null;
        return DNSName.parse(self.message, self.rdata_offset) catch null;
    }

    /// Get MX record
    pub fn getMX(self: DNSResourceRecord) ?MXRecord {
        if (self.rtype != .MX or self.rdata.len < 3) return null;
        const exchange = DNSName.parse(self.message, self.rdata_offset + 2) catch return null;
        return .{
            .preference = std.mem.readInt(u16, self.rdata[0..2], .big),
            .exchange = exchange,
        };
    }

    /// Get TXT record data
    pub fn getTXT(self: DNSResourceRecord) ?[]const u8 {
        if (self.rtype != .TXT or self.rdata.len < 1) return null;
        const txt_len = self.rdata[0];
        if (1 + txt_len > self.rdata.len) return null;
        return self.rdata[1..][0..txt_len];
    }

    /// Format for debugging
    pub fn format(
        self: DNSResourceRecord,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{} {} {s} {s} ", .{ self.name, self.ttl, self.rclass.name(), self.rtype.name() });

        switch (self.rtype) {
            .A => {
                if (self.getA()) |addr| {
                    try writer.print("{}.{}.{}.{}", .{ addr[0], addr[1], addr[2], addr[3] });
                }
            },
            .AAAA => {
                if (self.getAAAA()) |addr| {
                    // Simplified IPv6 output
                    for (addr, 0..) |b, i| {
                        if (i > 0 and i % 2 == 0) try writer.writeByte(':');
                        try writer.print("{x:0>2}", .{b});
                    }
                }
            },
            .CNAME, .NS, .PTR => {
                if (self.getNameTarget()) |target| {
                    try writer.print("{}", .{target});
                }
            },
            .MX => {
                if (self.getMX()) |mx| {
                    try writer.print("{} {}", .{ mx.preference, mx.exchange });
                }
            },
            .TXT => {
                if (self.getTXT()) |txt| {
                    try writer.print("\"{s}\"", .{txt});
                }
            },
            else => {
                try writer.print("[{} bytes]", .{self.rdata.len});
            },
        }
    }
};

pub const MXRecord = struct {
    preference: u16,
    exchange: DNSName,
};

// ============================================================================
// DNS Message Parser
// ============================================================================

/// Complete DNS message parser with iterators for sections
pub const DNSMessage = struct {
    /// Raw message data
    data: []const u8,
    /// Parsed header
    header: DNSHeader,

    pub const ParseError = DNSHeader.ParseError || DNSQuestion.ParseError || DNSResourceRecord.ParseError;

    /// Parse a DNS message
    pub fn parse(data: []const u8) DNSHeader.ParseError!DNSMessage {
        return .{
            .data = data,
            .header = try DNSHeader.parse(data),
        };
    }

    /// Get an iterator over questions
    pub fn questionIterator(self: DNSMessage) QuestionIterator {
        return .{
            .message = self.data,
            .offset = DNSHeader.SIZE,
            .remaining = self.header.qdcount,
        };
    }

    /// Get an iterator over all resource records (answers, authority, additional)
    /// Must consume questions first
    pub fn recordIterator(self: DNSMessage, start_offset: usize) RecordIterator {
        return .{
            .message = self.data,
            .offset = start_offset,
            .remaining = @as(u32, self.header.ancount) +
                @as(u32, self.header.nscount) +
                @as(u32, self.header.arcount),
        };
    }

    /// Convenience: parse first question (common case)
    pub fn firstQuestion(self: DNSMessage) ?DNSQuestion {
        if (self.header.qdcount == 0) return null;
        return DNSQuestion.parse(self.data, DNSHeader.SIZE) catch null;
    }
};

/// Iterator over DNS questions
pub const QuestionIterator = struct {
    message: []const u8,
    offset: usize,
    remaining: u16,

    pub fn next(self: *QuestionIterator) DNSQuestion.ParseError!?DNSQuestion {
        if (self.remaining == 0) return null;
        const question = try DNSQuestion.parse(self.message, self.offset);
        self.offset += question.wire_length;
        self.remaining -= 1;
        return question;
    }

    /// Current offset (for starting record iteration)
    pub fn currentOffset(self: QuestionIterator) usize {
        return self.offset;
    }
};

/// Iterator over DNS resource records
pub const RecordIterator = struct {
    message: []const u8,
    offset: usize,
    remaining: u32,

    pub fn next(self: *RecordIterator) DNSResourceRecord.ParseError!?DNSResourceRecord {
        if (self.remaining == 0) return null;
        const record = try DNSResourceRecord.parse(self.message, self.offset);
        self.offset += record.wire_length;
        self.remaining -= 1;
        return record;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DNSHeader - parse query" {
    // DNS query for example.com A record
    const query = [_]u8{
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: RD=1, rest=0
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    };

    const header = try DNSHeader.parse(&query);
    try std.testing.expectEqual(@as(u16, 0x1234), header.id);
    try std.testing.expect(header.isQuery());
    try std.testing.expect(!header.isResponse());
    try std.testing.expect(header.rd);
    try std.testing.expect(!header.aa);
    try std.testing.expectEqual(@as(u16, 1), header.qdcount);
    try std.testing.expectEqual(@as(u16, 0), header.ancount);
}

test "DNSHeader - parse response" {
    // DNS response
    const response = [_]u8{
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x02, // ANCOUNT = 2
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
    };

    const header = try DNSHeader.parse(&response);
    try std.testing.expect(header.isResponse());
    try std.testing.expect(header.rd);
    try std.testing.expect(header.ra);
    try std.testing.expectEqual(ResponseCode.no_error, header.rcode);
    try std.testing.expectEqual(@as(u16, 2), header.ancount);
}

test "DNSName - parse simple name" {
    // "www.example.com" encoded
    const data = [_]u8{
        3, 'w', 'w', 'w',
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm',
        0, // null terminator
    };

    const name = try DNSName.parse(&data, 0);
    try std.testing.expectEqual(@as(usize, 17), name.wire_length);

    var buffer: [256]u8 = undefined;
    const len = try name.writeTo(&buffer);
    try std.testing.expectEqualStrings("www.example.com", buffer[0..len]);
}

test "DNSName - parse with compression" {
    // Message with compression pointer
    // First name at offset 0: "example.com"
    // Second name at offset 13: pointer to offset 0
    const data = [_]u8{
        7,   'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0, // null terminator (offset 12)
        // Pointer to offset 0 (0xC000 | 0x0000)
        0xC0, 0x00,
    };

    // Parse the pointer
    const name = try DNSName.parse(&data, 13);
    try std.testing.expectEqual(@as(usize, 2), name.wire_length); // Just the pointer

    var buffer: [256]u8 = undefined;
    const len = try name.writeTo(&buffer);
    try std.testing.expectEqualStrings("example.com", buffer[0..len]);
}

test "DNSQuestion - parse" {
    // Full DNS query message
    const message = [_]u8{
        // Header (12 bytes)
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Question: www.example.com A IN
        3,    'w',  'w',  'w',
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',
        0, // null terminator
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
    };

    const msg = try DNSMessage.parse(&message);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);

    const question = msg.firstQuestion().?;
    try std.testing.expectEqual(RecordType.A, question.qtype);
    try std.testing.expectEqual(RecordClass.IN, question.qclass);
}

test "DNSResourceRecord - parse A record" {
    // Minimal message with one A record answer
    const message = [_]u8{
        // Header (12 bytes)
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // Answer: example.com A 93.184.216.34
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',
        0, // null terminator
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x0E, 0x10, // TTL = 3600
        0x00, 0x04, // RDLENGTH = 4
        93,   184,  216,  34, // RDATA = 93.184.216.34
    };

    const record = try DNSResourceRecord.parse(&message, 12);
    try std.testing.expectEqual(RecordType.A, record.rtype);
    try std.testing.expectEqual(@as(u32, 3600), record.ttl);

    const addr = record.getA().?;
    try std.testing.expectEqual(@as(u8, 93), addr[0]);
    try std.testing.expectEqual(@as(u8, 184), addr[1]);
    try std.testing.expectEqual(@as(u8, 216), addr[2]);
    try std.testing.expectEqual(@as(u8, 34), addr[3]);
}

test "DNSMessage - full query/response" {
    // Complete DNS response with question and answer
    const message = [_]u8{
        // Header
        0xAB, 0xCD, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x01, // ANCOUNT = 1
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Question: example.com A IN
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',
        0,
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
        // Answer: (pointer to question name) A 93.184.216.34
        0xC0, 0x0C, // Pointer to offset 12
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x0E, 0x10, // TTL = 3600
        0x00, 0x04, // RDLENGTH = 4
        93,   184,  216,  34, // RDATA
    };

    const msg = try DNSMessage.parse(&message);
    try std.testing.expect(msg.header.isResponse());
    try std.testing.expectEqual(@as(u16, 0xABCD), msg.header.id);

    // Iterate questions
    var q_iter = msg.questionIterator();
    const q = (try q_iter.next()).?;
    try std.testing.expectEqual(RecordType.A, q.qtype);

    // Iterate answers
    var r_iter = msg.recordIterator(q_iter.currentOffset());
    const a = (try r_iter.next()).?;
    try std.testing.expectEqual(RecordType.A, a.rtype);

    const addr = a.getA().?;
    try std.testing.expectEqual(@as(u8, 93), addr[0]);
}

test "DNSName - equality" {
    const data1 = [_]u8{ 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 3, 'C', 'O', 'M', 0 };
    const data2 = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

    const name1 = try DNSName.parse(&data1, 0);
    const name2 = try DNSName.parse(&data2, 0);

    try std.testing.expect(name1.eql(name2)); // Case insensitive
}
