//! Page-based memory management for TCP reassembly
//!
//! Uses fixed-size pages for predictable memory usage and efficient
//! allocation/deallocation of out-of-order TCP segment buffers.

const std = @import("std");

/// Default page size (4KB, matches OS page size)
pub const DEFAULT_PAGE_SIZE: usize = 4096;

/// A fixed-size page for storing segment data
pub const Page = struct {
    /// Raw data buffer
    data: []u8,
    /// Number of bytes used in this page
    used: usize,
    /// Sequence number of first byte in this page
    seq_start: u32,
    /// Link to next page in list
    next: ?*Page,
    /// Link to previous page in list
    prev: ?*Page,

    /// Initialize a page with allocated memory
    pub fn init(data: []u8) Page {
        return .{
            .data = data,
            .used = 0,
            .seq_start = 0,
            .next = null,
            .prev = null,
        };
    }

    /// Reset page for reuse
    pub fn reset(self: *Page) void {
        self.used = 0;
        self.seq_start = 0;
        self.next = null;
        self.prev = null;
    }

    /// Get available space in this page
    pub fn available(self: *const Page) usize {
        return self.data.len - self.used;
    }

    /// Write data to the page, returns number of bytes written
    pub fn write(self: *Page, data: []const u8) usize {
        const to_write = @min(data.len, self.available());
        @memcpy(self.data[self.used..][0..to_write], data[0..to_write]);
        self.used += to_write;
        return to_write;
    }

    /// Get the used portion of the page
    pub fn usedSlice(self: *const Page) []const u8 {
        return self.data[0..self.used];
    }
};

/// Pool of reusable pages for efficient memory management
pub const PagePool = struct {
    allocator: std.mem.Allocator,
    /// Size of each page
    page_size: usize,
    /// Free list of available pages
    free_list: ?*Page,
    /// Total number of pages allocated
    total_pages: usize,
    /// Maximum number of pages allowed
    max_pages: usize,
    /// Number of pages currently in use
    in_use: usize,

    pub const Config = struct {
        page_size: usize = DEFAULT_PAGE_SIZE,
        max_pages: usize = 65536, // ~256MB with 4KB pages
    };

    /// Initialize a new page pool
    pub fn init(allocator: std.mem.Allocator, config: Config) PagePool {
        return .{
            .allocator = allocator,
            .page_size = config.page_size,
            .free_list = null,
            .total_pages = 0,
            .max_pages = config.max_pages,
            .in_use = 0,
        };
    }

    /// Deinitialize the pool and free all pages
    pub fn deinit(self: *PagePool) void {
        // Free all pages in the free list
        var page = self.free_list;
        while (page) |p| {
            const next = p.next;
            self.allocator.free(p.data);
            self.allocator.destroy(p);
            page = next;
        }
        self.free_list = null;
        self.total_pages = 0;
        self.in_use = 0;
    }

    /// Acquire a page from the pool
    /// Returns null if max_pages limit is reached and no free pages available
    pub fn acquire(self: *PagePool) ?*Page {
        // Try to get from free list first
        if (self.free_list) |page| {
            self.free_list = page.next;
            page.reset();
            self.in_use += 1;
            return page;
        }

        // Check if we can allocate a new page
        if (self.total_pages >= self.max_pages) {
            return null;
        }

        // Allocate new page
        const data = self.allocator.alloc(u8, self.page_size) catch return null;
        const page = self.allocator.create(Page) catch {
            self.allocator.free(data);
            return null;
        };

        page.* = Page.init(data);
        self.total_pages += 1;
        self.in_use += 1;
        return page;
    }

    /// Release a page back to the pool
    pub fn release(self: *PagePool, page: *Page) void {
        page.reset();
        page.next = self.free_list;
        self.free_list = page;
        self.in_use -= 1;
    }

    /// Get current memory usage statistics
    pub fn stats(self: *const PagePool) Stats {
        return .{
            .total_pages = self.total_pages,
            .in_use = self.in_use,
            .free = self.total_pages - self.in_use,
            .total_bytes = self.total_pages * self.page_size,
            .used_bytes = self.in_use * self.page_size,
        };
    }

    pub const Stats = struct {
        total_pages: usize,
        in_use: usize,
        free: usize,
        total_bytes: usize,
        used_bytes: usize,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "Page - basic operations" {
    var data: [64]u8 = undefined;
    var page = Page.init(&data);

    try std.testing.expectEqual(@as(usize, 0), page.used);
    try std.testing.expectEqual(@as(usize, 64), page.available());

    const written = page.write("hello");
    try std.testing.expectEqual(@as(usize, 5), written);
    try std.testing.expectEqual(@as(usize, 5), page.used);
    try std.testing.expectEqual(@as(usize, 59), page.available());
    try std.testing.expectEqualStrings("hello", page.usedSlice());
}

test "Page - write overflow" {
    var data: [4]u8 = undefined;
    var page = Page.init(&data);

    const written = page.write("hello world");
    try std.testing.expectEqual(@as(usize, 4), written); // Only 4 bytes fit
    try std.testing.expectEqual(@as(usize, 0), page.available());
}

test "PagePool - acquire and release" {
    var pool = PagePool.init(std.testing.allocator, .{
        .page_size = 64,
        .max_pages = 4,
    });
    defer pool.deinit();

    // Acquire a page
    const page1 = pool.acquire().?;
    try std.testing.expectEqual(@as(usize, 1), pool.in_use);
    try std.testing.expectEqual(@as(usize, 1), pool.total_pages);

    // Use the page
    _ = page1.write("test data");
    try std.testing.expectEqual(@as(usize, 9), page1.used);

    // Release it
    pool.release(page1);
    try std.testing.expectEqual(@as(usize, 0), pool.in_use);

    // Acquire again (should reuse)
    const page2 = pool.acquire().?;
    try std.testing.expect(page1 == page2); // Same page reused
    try std.testing.expectEqual(@as(usize, 1), pool.total_pages); // No new allocation

    // Release for cleanup
    pool.release(page2);
}

test "PagePool - max pages limit" {
    var pool = PagePool.init(std.testing.allocator, .{
        .page_size = 64,
        .max_pages = 2,
    });
    defer pool.deinit();

    const page1 = pool.acquire().?;
    const page2 = pool.acquire().?;
    const page3 = pool.acquire();

    try std.testing.expect(page3 == null); // Limit reached
    try std.testing.expectEqual(@as(usize, 2), pool.total_pages);

    // Release one, should be able to acquire again
    pool.release(page1);
    const page4 = pool.acquire().?;
    try std.testing.expect(page4 == page1); // Reused

    pool.release(page2);
    pool.release(page4);
}

test "PagePool - stats" {
    var pool = PagePool.init(std.testing.allocator, .{
        .page_size = 1024,
        .max_pages = 10,
    });
    defer pool.deinit();

    const page1 = pool.acquire().?;
    const page2 = pool.acquire().?;
    const page3 = pool.acquire().?;

    const s = pool.stats();
    try std.testing.expectEqual(@as(usize, 3), s.total_pages);
    try std.testing.expectEqual(@as(usize, 3), s.in_use);
    try std.testing.expectEqual(@as(usize, 0), s.free);
    try std.testing.expectEqual(@as(usize, 3072), s.total_bytes);

    pool.release(page3);
    const s2 = pool.stats();
    try std.testing.expectEqual(@as(usize, 2), s2.in_use);
    try std.testing.expectEqual(@as(usize, 1), s2.free);

    // Release remaining pages for cleanup
    pool.release(page1);
    pool.release(page2);
}
