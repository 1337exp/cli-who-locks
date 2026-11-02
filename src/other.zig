const std = @import("std");
const report = @import("report.zig");

pub fn query(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    path: []const u8,
) report.QueryError!report.Outcome {
    _ = gpa;
    _ = arena;
    _ = path;
    return error.PlatformNotImplemented;
}
