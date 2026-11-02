//! Processes that have a path open, from the system handle table.
//!
//! NtQuerySystemInformation class 64 (SystemExtendedHandleInformation) is
//! not a documented Win32 call. DuplicateHandle plus GetFinalPathNameByHandle
//! then turns a handle into a path. Nothing here loads a driver or closes a
//! handle. Protected processes can refuse both OpenProcess and
//! DuplicateHandle, and those locks stay invisible.

const builtin = @import("builtin");
const std = @import("std");
const match = @import("match.zig");
const report = @import("report.zig");

const windows = std.os.windows;

comptime {
    if (builtin.os.tag != .windows) @compileError("src/windows.zig is Windows only");
    if (@sizeOf(usize) != 8) @compileError("who-locks reads the 64-bit system handle table");
}

const QueryError = report.QueryError;
const Outcome = report.Outcome;

const Acc = struct {
    pid: u32,
    name: []const u8,
    paths: std.ArrayList([]const u8),
};

const win = struct {
    pub extern "kernel32" fn OpenProcess(
        access: windows.DWORD,
        inherit: windows.BOOL,
        pid: windows.DWORD,
    ) callconv(.winapi) ?windows.HANDLE;

    pub extern "kernel32" fn GetCurrentProcess() callconv(.winapi) windows.HANDLE;

    pub extern "kernel32" fn DuplicateHandle(
        src_process: windows.HANDLE,
        src_handle: windows.HANDLE,
        dst_process: windows.HANDLE,
        dst_handle: *windows.HANDLE,
        access: windows.DWORD,
        inherit: windows.BOOL,
        options: windows.DWORD,
    ) callconv(.winapi) windows.BOOL;

    pub extern "kernel32" fn GetFileType(file: windows.HANDLE) callconv(.winapi) windows.DWORD;

    pub extern "kernel32" fn GetFinalPathNameByHandleW(
        file: windows.HANDLE,
        path: [*]u16,
        cch: windows.DWORD,
        flags: windows.DWORD,
    ) callconv(.winapi) windows.DWORD;

    pub extern "kernel32" fn QueryFullProcessImageNameW(
        process: windows.HANDLE,
        flags: windows.DWORD,
        name: [*]u16,
        size: *windows.DWORD,
    ) callconv(.winapi) windows.BOOL;

    pub extern "kernel32" fn GetFullPathNameW(
        name: [*:0]const u16,
        out_len: windows.DWORD,
        out: [*]u16,
        file_part: ?*[*:0]u16,
    ) callconv(.winapi) windows.DWORD;

    pub extern "kernel32" fn CreateFileW(
        name: [*:0]const u16,
        access: windows.DWORD,
        share: windows.DWORD,
        security: ?*anyopaque,
        disposition: windows.DWORD,
        flags: windows.DWORD,
        template: ?windows.HANDLE,
    ) callconv(.winapi) windows.HANDLE;
};

const process_dup_handle: windows.DWORD = 0x0040;
const process_query_limited: windows.DWORD = 0x1000;
const duplicate_same_access: windows.DWORD = 0x0002;
const file_type_disk: windows.DWORD = 0x0001;
const file_read_attributes: windows.DWORD = 0x0080;
const file_share_all: windows.DWORD = 0x0001 | 0x0002 | 0x0004;
const open_existing: windows.DWORD = 3;
const file_flag_backup_semantics: windows.DWORD = 0x02000000;
const system_extended_handle_information: windows.SYSTEM.INFORMATION_CLASS = @enumFromInt(64);

pub fn query(gpa: std.mem.Allocator, arena: std.mem.Allocator, path: []const u8) QueryError!Outcome {
    const query_wide = try gpa.alloc(u16, 32_768);
    defer gpa.free(query_wide);
    const canonical = try gpa.alloc(u16, 32_768);
    defer gpa.free(canonical);
    const query_len = try canonicalWide(gpa, path, query_wide, canonical);
    const query_slice = query_wide[0..query_len];

    const query_norm_buf = try gpa.alloc(u16, query_slice.len);
    defer gpa.free(query_norm_buf);
    const query_norm = try match.normalize(u16, query_norm_buf, query_slice, true);

    const query_utf8 = try std.unicode.wtf16LeToWtf8Alloc(gpa, query_slice);
    defer gpa.free(query_utf8);
    const query_text_buf = try gpa.alloc(u8, query_utf8.len);
    defer gpa.free(query_text_buf);
    const query_text = try match.normalize(u8, query_text_buf, query_utf8, false);
    const shown = try arena.dupe(u8, query_text);

    const table = try loadHandleTable(gpa);
    defer gpa.free(table);

    var procs = std.AutoHashMap(u32, usize).init(gpa);
    defer {
        var it = procs.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* != 0) windows.CloseHandle(@ptrFromInt(entry.value_ptr.*));
        }
        procs.deinit();
    }

    var found = std.ArrayList(Acc).empty;
    defer found.deinit(gpa);
    var index_of = std.AutoHashMap(u32, usize).init(gpa);
    defer index_of.deinit();

    const scratch = try gpa.alloc(u16, 32_768);
    defer gpa.free(scratch);
    const norm_wide = try gpa.alloc(u16, 32_768);
    defer gpa.free(norm_wide);
    var display_utf8 = try gpa.alloc(u8, 32_768 * 3);
    defer gpa.free(display_utf8);

    const count_raw = std.mem.readInt(usize, table[0..8], .little);
    const max_fit = (table.len - 16) / 40;
    if (count_raw > max_fit) return error.NtQueryFailed;

    const self = win.GetCurrentProcess();
    var i: usize = 0;
    while (i < count_raw) : (i += 1) {
        const off = 16 + i * 40;
        const pid_raw = std.mem.readInt(usize, table[off + 8 ..][0..8], .little);
        const handle_raw = std.mem.readInt(usize, table[off + 16 ..][0..8], .little);
        if (pid_raw == 0 or pid_raw > std.math.maxInt(u32) or handle_raw == 0) continue;
        const pid: u32 = @intCast(pid_raw);

        const proc = try processHandle(&procs, pid) orelse continue;
        var dup: windows.HANDLE = undefined;
        if (!win.DuplicateHandle(proc, @ptrFromInt(handle_raw), self, &dup, 0, .FALSE, duplicate_same_access).toBool()) {
            continue;
        }
        defer windows.CloseHandle(dup);
        if (win.GetFileType(dup) != file_type_disk) continue;

        const wide_len = win.GetFinalPathNameByHandleW(dup, scratch.ptr, @intCast(scratch.len), 0);
        if (wide_len == 0 or wide_len >= scratch.len) continue;
        const wide = scratch[0..wide_len];

        const norm = match.normalize(u16, norm_wide, wide, true) catch continue;
        if (!match.coversNormalized(u16, norm, query_norm)) continue;

        const owned = try displayPath(gpa, arena, &display_utf8, wide);
        try addPath(gpa, arena, &found, &index_of, proc, pid, owned);
    }

    const hits = try arena.alloc(report.Hit, found.items.len);
    for (found.items, hits) |*src, *dst| {
        std.mem.sort([]const u8, src.paths.items, {}, lessPath);
        dst.* = .{ .pid = src.pid, .name = src.name, .paths = src.paths.items };
    }
    std.mem.sort(report.Hit, hits, {}, lessHit);

    return .{
        .path = shown,
        .hits = hits,
        .handles_seen = count_raw,
    };
}

fn canonicalWide(gpa: std.mem.Allocator, path: []const u8, full: []u16, opened: []u16) QueryError!usize {
    const user = try std.unicode.wtf8ToWtf16LeAllocZ(gpa, path);
    defer gpa.free(user);
    if (full.len > std.math.maxInt(windows.DWORD)) return error.PathTooLong;
    const n = win.GetFullPathNameW(user.ptr, @intCast(full.len), full.ptr, null);
    if (n == 0 or n >= full.len) return error.InvalidPath;
    full[n] = 0;

    const file = win.CreateFileW(
        full[0..n :0],
        file_read_attributes,
        file_share_all,
        null,
        open_existing,
        file_flag_backup_semantics,
        null,
    );
    if (file == windows.INVALID_HANDLE_VALUE) return n;
    defer windows.CloseHandle(file);

    const got = win.GetFinalPathNameByHandleW(file, opened.ptr, @intCast(opened.len), 0);
    if (got == 0 or got >= opened.len) return n;
    if (got > full.len) return error.PathTooLong;
    @memcpy(full[0..got], opened[0..got]);
    return got;
}

fn loadHandleTable(gpa: std.mem.Allocator) QueryError![]u8 {
    const size: usize = 8 * 1024 * 1024;
    var buf = try gpa.alloc(u8, size);
    errdefer gpa.free(buf);
    var attempt: u8 = 0;
    while (attempt < 8) : (attempt += 1) {
        if (buf.len > std.math.maxInt(windows.ULONG)) return error.NtQueryFailed;
        var ret_len: windows.ULONG = 0;
        const status = windows.ntdll.NtQuerySystemInformation(
            system_extended_handle_information,
            buf.ptr,
            @intCast(buf.len),
            &ret_len,
        );
        if (status == .SUCCESS) {
            if (buf.len < 16) return error.NtQueryFailed;
            return buf;
        }
        if (status == .ACCESS_DENIED) return error.AccessDenied;
        if (status != .INFO_LENGTH_MISMATCH) return error.NtQueryFailed;
        const grown: usize = if (ret_len > buf.len) @as(usize, ret_len) + (1 << 20) else buf.len * 2;
        if (grown > 512 * 1024 * 1024) return error.NtQueryFailed;
        const next = try gpa.alloc(u8, grown);
        gpa.free(buf);
        buf = next;
    }
    return error.NtQueryFailed;
}

fn processHandle(procs: *std.AutoHashMap(u32, usize), pid: u32) QueryError!?windows.HANDLE {
    const gop = try procs.getOrPut(pid);
    if (!gop.found_existing) {
        const opened = win.OpenProcess(process_dup_handle | process_query_limited, .FALSE, pid) orelse
            win.OpenProcess(process_dup_handle, .FALSE, pid);
        gop.value_ptr.* = if (opened) |handle| @intFromPtr(handle) else 0;
    }
    if (gop.value_ptr.* == 0) return null;
    return @ptrFromInt(gop.value_ptr.*);
}

fn addPath(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    found: *std.ArrayList(Acc),
    index_of: *std.AutoHashMap(u32, usize),
    process: windows.HANDLE,
    pid: u32,
    path: []const u8,
) QueryError!void {
    const gop = try index_of.getOrPut(pid);
    if (!gop.found_existing) {
        const acc = Acc{
            .pid = pid,
            .name = imageBase(arena, process),
            .paths = .empty,
        };
        try found.append(gpa, acc);
        gop.value_ptr.* = found.items.len - 1;
    }
    const acc = &found.items[gop.value_ptr.*];
    for (acc.paths.items) |have| {
        if (std.mem.eql(u8, have, path)) return;
    }
    try acc.paths.append(arena, path);
}

fn imageBase(arena: std.mem.Allocator, process: windows.HANDLE) []const u8 {
    var buf: [2048]u16 = undefined;
    var size: windows.DWORD = buf.len;
    if (!win.QueryFullProcessImageNameW(process, 0, &buf, &size).toBool()) return "";
    if (size == 0 or size > buf.len) return "";
    const wide = buf[0..size];
    var cut = wide;
    var i = wide.len;
    while (i > 0) {
        i -= 1;
        if (wide[i] == '\\' or wide[i] == '/') {
            cut = wide[i + 1 ..];
            break;
        }
    }
    return std.unicode.wtf16LeToWtf8Alloc(arena, cut) catch "";
}

fn displayPath(gpa: std.mem.Allocator, arena: std.mem.Allocator, utf8_buf: *[]u8, wide: []const u16) QueryError![]const u8 {
    const need = wide.len * 3 + 1;
    if (utf8_buf.len < need) {
        const grown = try gpa.alloc(u8, need);
        gpa.free(utf8_buf.*);
        utf8_buf.* = grown;
    }
    const n = std.unicode.wtf16LeToWtf8(utf8_buf.*[0..need], wide);
    const text_buf = try gpa.alloc(u8, n);
    defer gpa.free(text_buf);
    const text = match.normalize(u8, text_buf, utf8_buf.*[0..n], false) catch utf8_buf.*[0..n];
    return arena.dupe(u8, text);
}

fn lessPath(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn lessHit(_: void, a: report.Hit, b: report.Hit) bool {
    return a.pid < b.pid;
}
