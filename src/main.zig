const builtin = @import("builtin");
const std = @import("std");
const report = @import("report.zig");

const os = switch (builtin.os.tag) {
    .windows => @import("windows.zig"),
    else => @import("other.zig"),
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var path: ?[]const u8 = null;
    var as_json = false;
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try writeStdout(init.io, help);
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--json")) {
            as_json = true;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.log.err("unknown option: {s}", .{arg});
            try writeStdout(init.io, help);
            std.process.exit(2);
        } else if (path == null) {
            path = arg;
        } else {
            std.log.err("only one path is accepted", .{});
            try writeStdout(init.io, help);
            std.process.exit(2);
        }
    }
    const query_path = path orelse {
        try writeStdout(init.io, help);
        std.process.exit(2);
    };
    if (query_path.len == 0) {
        std.log.err("the path is empty", .{});
        std.process.exit(2);
    }

    if (builtin.os.tag == .windows) {
        std.debug.print("scanning open handles...\n", .{});
    }
    const outcome = os.query(init.gpa, arena, query_path) catch |err| {
        switch (err) {
            error.PlatformNotImplemented => {
                std.log.err(
                    "listing open handles is implemented for Windows only. This build is for {s}, and it has not been tried on a real {s} machine.",
                    .{ @tagName(builtin.os.tag), @tagName(builtin.os.tag) },
                );
            },
            error.AccessDenied => {
                std.log.err("Windows refused the handle table. An elevated terminal can see more, and still not protected processes.", .{});
            },
            error.InvalidPath => std.log.err("could not resolve the path: {s}", .{query_path}),
            error.PathTooLong => std.log.err("the path is too long", .{}),
            error.NtQueryFailed => std.log.err("reading the system handle table failed", .{}),
            error.InvalidWtf8 => std.log.err("the path is not valid WTF-8", .{}),
            error.OutOfMemory => std.log.err("out of memory", .{}),
        }
        std.process.exit(2);
    };

    if (as_json) {
        try writeJson(init.io, outcome);
    } else {
        try writeText(init.io, outcome);
    }
    std.process.exit(if (outcome.hits.len == 0) 1 else 0);
}

const help =
    \\who-locks — list processes that have a file or directory open
    \\
    \\Usage:
    \\  who-locks <path> [--json]
    \\  who-locks --help
    \\
    \\The path matches itself and anything inside it. A directory is open
    \\when a process holds the directory or a file under it. That is what
    \\stops the directory from being renamed or moved.
    \\
    \\Pass one absolute path as a single argument. A second path is rejected.
    \\One call scans the handle table once and takes a few seconds.
    \\
    \\Text on stdout is for a person. --json is for programs and agents.
    \\With --json, stdout is one JSON object and a newline:
    \\
    \\  {"version":1,"path":"...","matched":true,"handles_seen":N,
    \\   "processes":[{"pid":N,"name":"...","paths":["..."]}]}
    \\
    \\version is 1. matched is false when processes is empty.
    \\path, handles_seen, processes, pid, name, and paths keep these names.
    \\Parsers skip fields they do not know.
    \\
    \\Exit status, for text and for --json:
    \\  0  at least one matching process. JSON is valid, matched is true.
    \\  1  the scan finished and no readable handle matches.
    \\     JSON is valid, matched is false. This is an answer, not a crash.
    \\  2  bad usage, or the scan failed. stdout may be empty.
    \\     The reason is on stderr.
    \\
    \\"scanning open handles..." is progress on stderr. On status 2, stderr
    \\is the error. A protected process can stay invisible, so matched false
    \\does not prove the path is free.
    \\
;

fn writeText(io: std.Io, outcome: report.Outcome) !void {
    var buffer: [4096]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    const out = &file_writer.interface;

    try out.print("{s}\n\n", .{outcome.path});
    if (outcome.hits.len == 0) {
        try out.writeAll("no readable handle has this path open\n");
        try out.writeAll("protected processes, such as some antivirus services, stay invisible here\n");
    } else {
        for (outcome.hits) |hit| {
            if (hit.name.len == 0) {
                try out.print("{d}  (unknown)\n", .{hit.pid});
            } else {
                try out.print("{d}  {s}\n", .{hit.pid, hit.name});
            }
            for (hit.paths) |path| try out.print("  {s}\n", .{path});
            try out.writeByte('\n');
        }
    }
    try out.print("looked at {d} handles\n", .{outcome.handles_seen});
    try out.flush();
}

fn writeJson(io: std.Io, outcome: report.Outcome) !void {
    var buffer: [4096]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    const out = &file_writer.interface;
    try writeJsonTo(out, outcome);
    try out.flush();
}

fn writeJsonTo(out: *std.Io.Writer, outcome: report.Outcome) !void {
    try out.print("{{\"version\":{d},\"path\":", .{report.json_version});
    try writeJsonString(out, outcome.path);
    try out.print(",\"matched\":{s},\"handles_seen\":{d},\"processes\":[", .{
        if (outcome.hits.len == 0) "false" else "true",
        outcome.handles_seen,
    });
    for (outcome.hits, 0..) |hit, index| {
        if (index != 0) try out.writeByte(',');
        try out.print("{{\"pid\":{d},\"name\":", .{hit.pid});
        try writeJsonString(out, hit.name);
        try out.writeAll(",\"paths\":[");
        for (hit.paths, 0..) |path, path_index| {
            if (path_index != 0) try out.writeByte(',');
            try writeJsonString(out, path);
        }
        try out.writeAll("]}");
    }
    try out.writeAll("]}\n");
}

fn writeJsonString(out: *std.Io.Writer, text: []const u8) !void {
    try out.writeByte('"');
    for (text) |c| switch (c) {
        '"' => try out.writeAll("\\\""),
        '\\' => try out.writeAll("\\\\"),
        '\n' => try out.writeAll("\\n"),
        '\r' => try out.writeAll("\\r"),
        '\t' => try out.writeAll("\\t"),
        else => if (c < 0x20) {
            try out.print("\\u{x:0>4}", .{c});
        } else {
            try out.writeByte(c);
        },
    };
    try out.writeByte('"');
}

fn writeStdout(io: std.Io, text: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    const out = &file_writer.interface;
    try out.writeAll(text);
    try out.flush();
}

test {
    _ = @import("match.zig");
}

test "json contract version 1 names a holder" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    const hits = [_]report.Hit{
        .{
            .pid = 56488,
            .name = "claude.exe",
            .paths = &.{"E:\\job\\git\\app\\.git"},
        },
    };
    try writeJsonTo(&aw.writer, .{
        .path = "E:\\job\\git\\app\\.git",
        .hits = &hits,
        .handles_seen = 3,
    });
    try std.testing.expectEqualStrings(
        "{\"version\":1,\"path\":\"E:\\\\job\\\\git\\\\app\\\\.git\",\"matched\":true,\"handles_seen\":3,\"processes\":[{\"pid\":56488,\"name\":\"claude.exe\",\"paths\":[\"E:\\\\job\\\\git\\\\app\\\\.git\"]}]}\n",
        aw.written(),
    );
}

test "json contract version 1 reports an empty scan" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try writeJsonTo(&aw.writer, .{
        .path = "E:\\empty",
        .hits = &.{},
        .handles_seen = 1,
    });
    try std.testing.expectEqualStrings(
        "{\"version\":1,\"path\":\"E:\\\\empty\",\"matched\":false,\"handles_seen\":1,\"processes\":[]}\n",
        aw.written(),
    );
}

test "json escapes quotes and backslashes" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    const hits = [_]report.Hit{
        .{ .pid = 1, .name = "a\"b\\c", .paths = &.{"E:\\a"} },
    };
    try writeJsonTo(&aw.writer, .{
        .path = "E:\\a",
        .hits = &hits,
        .handles_seen = 1,
    });
    try std.testing.expectEqualStrings(
        "{\"version\":1,\"path\":\"E:\\\\a\",\"matched\":true,\"handles_seen\":1,\"processes\":[{\"pid\":1,\"name\":\"a\\\"b\\\\c\",\"paths\":[\"E:\\\\a\"]}]}\n",
        aw.written(),
    );
}
