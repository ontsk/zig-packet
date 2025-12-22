//! TCP connection state tracking for reassembly
//!
//! Tracks sequence numbers and buffers out-of-order segments
//! for a single direction of a TCP connection (half-connection).

const std = @import("std");
const page_mod = @import("page.zig");
const tcp = @import("../transport/tcp.zig");

const Page = page_mod.Page;
const PagePool = page_mod.PagePool;
const SeqNum = tcp.SeqNum;

/// Represents one direction of a TCP connection
pub const HalfConnection = struct {
    /// Next expected sequence number (left edge of receive window)
    next_seq: SeqNum,
    /// Whether we've seen the initial SYN
    syn_seen: bool,
    /// Whether we've seen FIN
    fin_seen: bool,
    /// Linked list of buffered out-of-order pages
    buffered_pages: ?*Page,
    /// Number of pages buffered for this half-connection
    page_count: usize,
    /// Maximum pages allowed per half-connection
    max_pages: usize,
    /// Last activity timestamp (nanoseconds)
    last_activity_ns: i128,

    pub fn init(max_pages_per_conn: usize) HalfConnection {
        return .{
            .next_seq = SeqNum.init(0),
            .syn_seen = false,
            .fin_seen = false,
            .buffered_pages = null,
            .page_count = 0,
            .max_pages = max_pages_per_conn,
            .last_activity_ns = 0,
        };
    }

    /// Reset the half-connection state and release all pages
    pub fn reset(self: *HalfConnection, pool: *PagePool) void {
        self.releaseAllPages(pool);
        self.next_seq = SeqNum.init(0);
        self.syn_seen = false;
        self.fin_seen = false;
        self.last_activity_ns = 0;
    }

    /// Release all buffered pages back to the pool
    pub fn releaseAllPages(self: *HalfConnection, pool: *PagePool) void {
        var current = self.buffered_pages;
        while (current) |page| {
            const next = page.next;
            pool.release(page);
            current = next;
        }
        self.buffered_pages = null;
        self.page_count = 0;
    }

    /// Check if we can buffer more pages
    pub fn canBuffer(self: *const HalfConnection) bool {
        return self.page_count < self.max_pages;
    }

    /// Insert a page into the ordered buffer list (sorted by seq_start)
    pub fn insertPage(self: *HalfConnection, new_page: *Page) void {
        new_page.next = null;
        new_page.prev = null;

        if (self.buffered_pages == null) {
            self.buffered_pages = new_page;
            self.page_count = 1;
            return;
        }

        // Find insertion point (sorted by sequence number)
        var current = self.buffered_pages;
        var prev: ?*Page = null;

        while (current) |page| {
            const new_seq = SeqNum.init(new_page.seq_start);
            const cur_seq = SeqNum.init(page.seq_start);

            if (new_seq.lessThan(cur_seq)) {
                // Insert before current
                new_page.next = page;
                new_page.prev = prev;
                page.prev = new_page;

                if (prev) |p| {
                    p.next = new_page;
                } else {
                    self.buffered_pages = new_page;
                }

                self.page_count += 1;
                return;
            }

            prev = page;
            current = page.next;
        }

        // Insert at end
        if (prev) |p| {
            p.next = new_page;
            new_page.prev = p;
        }
        self.page_count += 1;
    }

    /// Remove a page from the buffer list
    pub fn removePage(self: *HalfConnection, page: *Page) void {
        if (page.prev) |prev| {
            prev.next = page.next;
        } else {
            self.buffered_pages = page.next;
        }

        if (page.next) |next| {
            next.prev = page.prev;
        }

        page.next = null;
        page.prev = null;
        self.page_count -= 1;
    }

    /// Get the first buffered page that's ready to be delivered
    /// (its seq_start matches next_seq)
    pub fn getReadyPage(self: *HalfConnection) ?*Page {
        if (self.buffered_pages) |page| {
            if (page.seq_start == self.next_seq.value) {
                return page;
            }
        }
        return null;
    }

    /// Calculate gap between next_seq and first buffered page
    pub fn gapToFirstBuffered(self: *const HalfConnection) ?u32 {
        if (self.buffered_pages) |page| {
            const buffered_seq = SeqNum.init(page.seq_start);
            if (buffered_seq.greaterThan(self.next_seq)) {
                const diff = buffered_seq.diff(self.next_seq);
                if (diff > 0 and diff <= std.math.maxInt(u32)) {
                    return @intCast(diff);
                }
            }
        }
        return null;
    }
};

/// Full bidirectional TCP connection
pub const Connection = struct {
    /// Client to server direction
    client_to_server: HalfConnection,
    /// Server to client direction
    server_to_client: HalfConnection,
    /// Flow identifier
    flow: tcp.Flow,
    /// Connection creation timestamp
    created_ns: i128,

    pub fn init(flow: tcp.Flow, max_pages_per_conn: usize, timestamp_ns: i128) Connection {
        return .{
            .client_to_server = HalfConnection.init(max_pages_per_conn),
            .server_to_client = HalfConnection.init(max_pages_per_conn),
            .flow = flow,
            .created_ns = timestamp_ns,
        };
    }

    /// Get the half-connection for the given direction
    pub fn getHalf(self: *Connection, is_client_to_server: bool) *HalfConnection {
        return if (is_client_to_server) &self.client_to_server else &self.server_to_client;
    }

    /// Reset both half-connections
    pub fn reset(self: *Connection, pool: *PagePool) void {
        self.client_to_server.reset(pool);
        self.server_to_client.reset(pool);
    }

    /// Get last activity timestamp across both directions
    pub fn lastActivity(self: *const Connection) i128 {
        return @max(
            self.client_to_server.last_activity_ns,
            self.server_to_client.last_activity_ns,
        );
    }

    /// Check if connection is idle (no activity for given duration)
    pub fn isIdle(self: *const Connection, current_ns: i128, timeout_ns: i128) bool {
        return (current_ns - self.lastActivity()) > timeout_ns;
    }

    /// Get total buffered pages across both directions
    pub fn totalBufferedPages(self: *const Connection) usize {
        return self.client_to_server.page_count + self.server_to_client.page_count;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "HalfConnection - basic init" {
    const half = HalfConnection.init(16);
    try std.testing.expectEqual(@as(usize, 0), half.page_count);
    try std.testing.expect(!half.syn_seen);
    try std.testing.expect(!half.fin_seen);
    try std.testing.expect(half.canBuffer());
}

test "HalfConnection - page insertion order" {
    var pool = PagePool.init(std.testing.allocator, .{
        .page_size = 64,
        .max_pages = 10,
    });
    defer pool.deinit();

    var half = HalfConnection.init(16);
    defer half.releaseAllPages(&pool);

    // Insert pages out of order
    var page3 = pool.acquire().?;
    page3.seq_start = 3000;
    half.insertPage(page3);

    var page1 = pool.acquire().?;
    page1.seq_start = 1000;
    half.insertPage(page1);

    var page2 = pool.acquire().?;
    page2.seq_start = 2000;
    half.insertPage(page2);

    // Verify order
    try std.testing.expectEqual(@as(usize, 3), half.page_count);

    var current = half.buffered_pages;
    try std.testing.expectEqual(@as(u32, 1000), current.?.seq_start);
    current = current.?.next;
    try std.testing.expectEqual(@as(u32, 2000), current.?.seq_start);
    current = current.?.next;
    try std.testing.expectEqual(@as(u32, 3000), current.?.seq_start);
    try std.testing.expect(current.?.next == null);
}

test "HalfConnection - ready page detection" {
    var pool = PagePool.init(std.testing.allocator, .{
        .page_size = 64,
        .max_pages = 10,
    });
    defer pool.deinit();

    var half = HalfConnection.init(16);
    defer half.releaseAllPages(&pool);

    half.next_seq = SeqNum.init(1000);

    // Insert page at seq 2000 (not ready, there's a gap)
    var page1 = pool.acquire().?;
    page1.seq_start = 2000;
    half.insertPage(page1);

    try std.testing.expect(half.getReadyPage() == null);
    try std.testing.expectEqual(@as(?u32, 1000), half.gapToFirstBuffered());

    // Insert page at seq 1000 (ready!)
    var page2 = pool.acquire().?;
    page2.seq_start = 1000;
    half.insertPage(page2);

    try std.testing.expect(half.getReadyPage() != null);
    try std.testing.expectEqual(@as(u32, 1000), half.getReadyPage().?.seq_start);
}

test "Connection - basic operations" {
    const flow = tcp.Flow.fromIPv4(
        .{ 192, 168, 1, 1 },
        .{ 10, 0, 0, 1 },
        12345,
        80,
    );

    var conn = Connection.init(flow, 16, 1000);

    try std.testing.expectEqual(@as(usize, 0), conn.totalBufferedPages());

    const c2s = conn.getHalf(true);
    const s2c = conn.getHalf(false);

    try std.testing.expect(c2s == &conn.client_to_server);
    try std.testing.expect(s2c == &conn.server_to_client);
}

test "Connection - idle detection" {
    const flow = tcp.Flow.fromIPv4(.{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 }, 1000, 2000);
    var conn = Connection.init(flow, 16, 0);

    conn.client_to_server.last_activity_ns = 1000;
    conn.server_to_client.last_activity_ns = 2000;

    try std.testing.expectEqual(@as(i128, 2000), conn.lastActivity());
    try std.testing.expect(!conn.isIdle(2500, 1000)); // Not idle yet
    try std.testing.expect(conn.isIdle(3500, 1000)); // Now idle
}
