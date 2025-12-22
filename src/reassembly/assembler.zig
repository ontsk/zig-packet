//! TCP Stream Reassembly
//!
//! Reassembles ordered byte streams from individual TCP segments.
//! Follows gopacket/reassembly design patterns with Zig idioms.
//!
//! ## Usage Example
//!
//! ```zig
//! const reassembly = @import("zig-packet").reassembly;
//!
//! const MyHandler = struct {
//!     pub fn onReassembled(self: *@This(), flow: tcp.Flow, event: reassembly.Event) void {
//!         switch (event) {
//!             .data => |d| {
//!                 // Process reassembled data
//!                 processData(d.bytes, d.is_start);
//!             },
//!             .gap => |g| {
//!                 // Handle missing bytes
//!                 log.warn("Gap of {} bytes", .{g.bytes_missing});
//!             },
//!             .end => |reason| {
//!                 // Connection ended
//!                 cleanup(reason);
//!             },
//!         }
//!     }
//! };
//!
//! var assembler = reassembly.Assembler(MyHandler).init(allocator, &handler, .{});
//! defer assembler.deinit();
//!
//! // Feed packets from nfqueue/pcap
//! assembler.assemble(flow, tcp_header, payload, timestamp);
//! ```

const std = @import("std");
const tcp = @import("../transport/tcp.zig");
const page_mod = @import("page.zig");
const conn_mod = @import("connection.zig");

const Flow = tcp.Flow;
const SeqNum = tcp.SeqNum;
const TCPHeader = tcp.TCPHeader;
const Page = page_mod.Page;
const PagePool = page_mod.PagePool;
const Connection = conn_mod.Connection;
const HalfConnection = conn_mod.HalfConnection;

/// Events delivered to the stream handler
pub const Event = union(enum) {
    /// Contiguous reassembled data ready for processing
    data: struct {
        /// The reassembled bytes (may be zero-copy slice or from buffer)
        bytes: []const u8,
        /// True if this is the first data after connection start/SYN
        is_start: bool,
        /// Direction: true = client->server, false = server->client
        is_client_to_server: bool,
    },

    /// Gap detected in the stream (bytes were lost/never received)
    gap: struct {
        /// Number of bytes missing
        bytes_missing: u32,
        /// Direction
        is_client_to_server: bool,
    },

    /// Stream ended
    end: struct {
        reason: EndReason,
        is_client_to_server: bool,
    },
};

pub const EndReason = enum {
    fin,
    rst,
    timeout,
    flush,
};

/// Configuration for the assembler
pub const Config = struct {
    /// Maximum total pages across all connections
    max_buffered_pages_total: usize = 65536, // ~256MB with 4KB pages
    /// Maximum pages per connection (per direction)
    max_buffered_pages_per_conn: usize = 16, // ~64KB per half-connection
    /// Idle timeout in nanoseconds (default 10 minutes)
    stream_timeout_ns: i128 = 600_000_000_000,
    /// Page size for buffering
    page_size: usize = page_mod.DEFAULT_PAGE_SIZE,
    /// Skip data before seeing SYN (accept mid-stream connections)
    accept_mid_stream: bool = true,
};

/// TCP Stream Assembler with comptime handler type
pub fn Assembler(comptime Handler: type) type {
    // Validate handler has required method
    comptime {
        if (!@hasDecl(Handler, "onReassembled")) {
            @compileError("Handler must have 'onReassembled' method");
        }
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        connections: std.HashMap(Flow, *Connection, Flow.HashContext, 80),
        page_pool: PagePool,
        handler: *Handler,
        config: Config,

        /// Statistics
        stats: Stats,

        pub const Stats = struct {
            packets_processed: u64 = 0,
            bytes_reassembled: u64 = 0,
            connections_created: u64 = 0,
            connections_closed: u64 = 0,
            gaps_detected: u64 = 0,
            pages_used: u64 = 0,
        };

        /// Initialize a new assembler
        pub fn init(allocator: std.mem.Allocator, handler: *Handler, config: Config) Self {
            return .{
                .allocator = allocator,
                .connections = std.HashMap(Flow, *Connection, Flow.HashContext, 80).init(allocator),
                .page_pool = PagePool.init(allocator, .{
                    .page_size = config.page_size,
                    .max_pages = config.max_buffered_pages_total,
                }),
                .handler = handler,
                .config = config,
                .stats = .{},
            };
        }

        /// Deinitialize and free all resources
        pub fn deinit(self: *Self) void {
            // Release all connection resources
            var it = self.connections.iterator();
            while (it.next()) |entry| {
                const conn = entry.value_ptr.*;
                conn.reset(&self.page_pool);
                self.allocator.destroy(conn);
            }
            self.connections.deinit();
            self.page_pool.deinit();
        }

        /// Process a TCP segment
        pub fn assemble(
            self: *Self,
            flow: Flow,
            header: *const TCPHeader,
            payload: []const u8,
            timestamp_ns: i128,
        ) void {
            self.stats.packets_processed += 1;

            // Get or create connection
            const conn = self.getOrCreateConnection(flow, timestamp_ns) orelse return;

            // Determine direction
            const is_c2s = flow.eql(conn.flow);
            const half = conn.getHalf(is_c2s);

            half.last_activity_ns = timestamp_ns;

            // Handle TCP flags
            if (header.flags.rst) {
                self.handleRst(conn, is_c2s);
                return;
            }

            if (header.flags.syn) {
                self.handleSyn(half, header);
            }

            if (header.flags.fin) {
                half.fin_seen = true;
            }

            // Process payload if present
            if (payload.len > 0) {
                self.processPayload(conn, half, header, payload, is_c2s);
            }

            // If FIN was set and no buffered data, signal end
            if (header.flags.fin and half.page_count == 0) {
                self.handler.onReassembled(flow, .{
                    .end = .{
                        .reason = .fin,
                        .is_client_to_server = is_c2s,
                    },
                });
            }
        }

        /// Flush connections older than the given timeout
        pub fn flushOlderThan(self: *Self, current_ns: i128, timeout_ns: i128) void {
            var to_remove: std.ArrayListUnmanaged(Flow) = .{};
            defer to_remove.deinit(self.allocator);

            var it = self.connections.iterator();
            while (it.next()) |entry| {
                const conn = entry.value_ptr.*;
                if (conn.isIdle(current_ns, timeout_ns)) {
                    // Flush any remaining data
                    self.flushConnection(conn, entry.key_ptr.*);
                    to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }

            for (to_remove.items) |flow| {
                if (self.connections.fetchRemove(flow)) |kv| {
                    self.allocator.destroy(kv.value);
                    self.stats.connections_closed += 1;
                }
            }
        }

        /// Flush all connections and clear state
        pub fn flushAll(self: *Self) void {
            var it = self.connections.iterator();
            while (it.next()) |entry| {
                self.flushConnection(entry.value_ptr.*, entry.key_ptr.*);
            }

            // Clear all connections
            var it2 = self.connections.iterator();
            while (it2.next()) |entry| {
                entry.value_ptr.*.reset(&self.page_pool);
                self.allocator.destroy(entry.value_ptr.*);
            }
            self.connections.clearAndFree();
        }

        /// Get current statistics
        pub fn getStats(self: *const Self) Stats {
            return self.stats;
        }

        /// Get page pool statistics
        pub fn getPoolStats(self: *const Self) PagePool.Stats {
            return self.page_pool.stats();
        }

        // ====================================================================
        // Internal methods
        // ====================================================================

        fn getOrCreateConnection(self: *Self, flow: Flow, timestamp_ns: i128) ?*Connection {
            // Check for existing connection (in either direction)
            if (self.connections.get(flow)) |conn| {
                return conn;
            }

            const reverse = flow.reverse();
            if (self.connections.get(reverse)) |conn| {
                return conn;
            }

            // Create new connection
            const conn = self.allocator.create(Connection) catch return null;
            conn.* = Connection.init(flow, self.config.max_buffered_pages_per_conn, timestamp_ns);

            self.connections.put(flow, conn) catch {
                self.allocator.destroy(conn);
                return null;
            };

            self.stats.connections_created += 1;
            return conn;
        }

        fn handleSyn(self: *Self, half: *HalfConnection, header: *const TCPHeader) void {
            _ = self;
            if (!half.syn_seen) {
                half.syn_seen = true;
                // SYN consumes one sequence number
                half.next_seq = SeqNum.init(header.sequence_number).add(1);
            }
        }

        fn handleRst(self: *Self, conn: *Connection, is_c2s: bool) void {
            const flow = if (is_c2s) conn.flow else conn.flow.reverse();

            // Signal end to handler
            self.handler.onReassembled(flow, .{
                .end = .{
                    .reason = .rst,
                    .is_client_to_server = is_c2s,
                },
            });

            // Clean up connection
            conn.reset(&self.page_pool);
            _ = self.connections.remove(conn.flow);
            self.allocator.destroy(conn);
            self.stats.connections_closed += 1;
        }

        fn processPayload(
            self: *Self,
            conn: *Connection,
            half: *HalfConnection,
            header: *const TCPHeader,
            payload: []const u8,
            is_c2s: bool,
        ) void {
            const seq = SeqNum.init(header.sequence_number);
            const flow = if (is_c2s) conn.flow else conn.flow.reverse();

            // If we haven't seen SYN and not accepting mid-stream, skip
            if (!half.syn_seen and !self.config.accept_mid_stream) {
                return;
            }

            // Initialize next_seq if this is first data (mid-stream)
            if (!half.syn_seen and half.next_seq.value == 0) {
                half.next_seq = seq;
            }

            // Check if this segment is in order
            if (seq.value == half.next_seq.value) {
                // In order - deliver directly (zero-copy)
                const is_start = !half.syn_seen or half.next_seq.value == seq.value;

                self.handler.onReassembled(flow, .{
                    .data = .{
                        .bytes = payload,
                        .is_start = is_start,
                        .is_client_to_server = is_c2s,
                    },
                });

                half.next_seq = seq.add(@intCast(payload.len));
                self.stats.bytes_reassembled += payload.len;

                // Check if we can deliver buffered pages
                self.deliverBuffered(half, flow, is_c2s);
            } else if (seq.greaterThan(half.next_seq)) {
                // Out of order - buffer it
                self.bufferSegment(half, seq, payload);
            }
            // else: retransmission of already-received data, ignore
        }

        fn bufferSegment(
            self: *Self,
            half: *HalfConnection,
            seq: SeqNum,
            payload: []const u8,
        ) void {
            if (!half.canBuffer()) {
                return; // Limit reached
            }

            const page = self.page_pool.acquire() orelse return;
            page.seq_start = seq.value;
            _ = page.write(payload);
            half.insertPage(page);
            self.stats.pages_used += 1;
        }

        fn deliverBuffered(
            self: *Self,
            half: *HalfConnection,
            flow: Flow,
            is_c2s: bool,
        ) void {
            while (true) {
                // Check for gap
                if (half.gapToFirstBuffered()) |gap| {
                    self.handler.onReassembled(flow, .{
                        .gap = .{
                            .bytes_missing = gap,
                            .is_client_to_server = is_c2s,
                        },
                    });
                    self.stats.gaps_detected += 1;

                    // Skip over the gap
                    half.next_seq = half.next_seq.add(gap);
                }

                // Try to deliver ready page
                const page = half.getReadyPage() orelse break;

                self.handler.onReassembled(flow, .{
                    .data = .{
                        .bytes = page.usedSlice(),
                        .is_start = false,
                        .is_client_to_server = is_c2s,
                    },
                });

                half.next_seq = half.next_seq.add(@intCast(page.used));
                self.stats.bytes_reassembled += page.used;

                half.removePage(page);
                self.page_pool.release(page);
            }
        }

        fn flushConnection(self: *Self, conn: *Connection, flow: Flow) void {
            // Flush client to server
            self.flushHalf(&conn.client_to_server, flow, true);

            // Flush server to client
            self.flushHalf(&conn.server_to_client, flow.reverse(), false);
        }

        fn flushHalf(self: *Self, half: *HalfConnection, flow: Flow, is_c2s: bool) void {
            // Deliver any buffered data
            while (half.buffered_pages) |page| {
                // Report gap if needed
                if (half.gapToFirstBuffered()) |gap| {
                    self.handler.onReassembled(flow, .{
                        .gap = .{
                            .bytes_missing = gap,
                            .is_client_to_server = is_c2s,
                        },
                    });
                    half.next_seq = half.next_seq.add(gap);
                }

                self.handler.onReassembled(flow, .{
                    .data = .{
                        .bytes = page.usedSlice(),
                        .is_start = false,
                        .is_client_to_server = is_c2s,
                    },
                });

                half.next_seq = half.next_seq.add(@intCast(page.used));
                half.removePage(page);
                self.page_pool.release(page);
            }

            // Signal timeout/flush end
            self.handler.onReassembled(flow, .{
                .end = .{
                    .reason = .timeout,
                    .is_client_to_server = is_c2s,
                },
            });
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const TestHandler = struct {
    events: std.ArrayListUnmanaged(Event),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) TestHandler {
        return .{
            .events = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *TestHandler) void {
        // Free any allocated data bytes
        for (self.events.items) |event| {
            if (event == .data) {
                self.allocator.free(event.data.bytes);
            }
        }
        self.events.deinit(self.allocator);
    }

    pub fn onReassembled(self: *TestHandler, _: Flow, event: Event) void {
        // Clone event data if needed (for data events, copy the bytes)
        var cloned_event = event;
        if (event == .data) {
            const copy = self.allocator.dupe(u8, event.data.bytes) catch return;
            cloned_event = .{
                .data = .{
                    .bytes = copy,
                    .is_start = event.data.is_start,
                    .is_client_to_server = event.data.is_client_to_server,
                },
            };
        }
        self.events.append(self.allocator, cloned_event) catch {};
    }

    fn clear(self: *TestHandler) void {
        // Free any allocated data
        for (self.events.items) |event| {
            if (event == .data) {
                self.allocator.free(event.data.bytes);
            }
        }
        self.events.clearRetainingCapacity();
    }
};

test "Assembler - in-order delivery" {
    var handler = TestHandler.init(std.testing.allocator);
    defer handler.deinit();

    var assembler = Assembler(TestHandler).init(std.testing.allocator, &handler, .{
        .max_buffered_pages_total = 10,
        .max_buffered_pages_per_conn = 4,
    });
    defer assembler.deinit();

    const flow = Flow.fromIPv4(.{ 192, 168, 1, 1 }, .{ 10, 0, 0, 1 }, 12345, 80);

    // Create a mock TCP header
    var header_data = [_]u8{
        0x30, 0x39, // src port 12345
        0x00, 0x50, // dst port 80
        0x00, 0x00, 0x00, 0x64, // seq 100
        0x00, 0x00, 0x00, 0x00, // ack 0
        0x50, 0x02, // data offset 5, SYN flag
        0x00, 0x00, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    };
    var tcp_header = TCPHeader.parse(&header_data) catch unreachable;

    // Send SYN
    assembler.assemble(flow, &tcp_header, "", 1000);

    // Send data (seq 101)
    header_data[4] = 0x00;
    header_data[5] = 0x00;
    header_data[6] = 0x00;
    header_data[7] = 0x65; // seq 101
    header_data[13] = 0x18; // PSH+ACK
    tcp_header = TCPHeader.parse(&header_data) catch unreachable;

    assembler.assemble(flow, &tcp_header, "hello", 2000);

    // Verify event received
    try std.testing.expectEqual(@as(usize, 1), handler.events.items.len);
    try std.testing.expect(handler.events.items[0] == .data);
    try std.testing.expectEqualStrings("hello", handler.events.items[0].data.bytes);

    handler.clear();
}

test "Assembler - stats tracking" {
    var handler = TestHandler.init(std.testing.allocator);
    defer handler.deinit();

    var assembler = Assembler(TestHandler).init(std.testing.allocator, &handler, .{});
    defer assembler.deinit();

    const stats = assembler.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.packets_processed);
    try std.testing.expectEqual(@as(u64, 0), stats.connections_created);
}
