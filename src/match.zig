const std = @import("std");

/// True when `holder` is `query` or a path inside it.
///
/// Comparison ignores ASCII case and the case of Russian Cyrillic
/// (А–Я, Ё). The `\\?\` and `\\?\UNC\` prefixes Windows returns from
/// GetFinalPathNameByHandle are stripped first. A drive root such as
/// `E:\` matches everything on that drive.
pub fn covers(holder: []const u8, query: []const u8) bool {
    var holder_buf: [4096]u8 = undefined;
    var query_buf: [4096]u8 = undefined;
    const holder_norm = normalize(u8, &holder_buf, holder, true) catch return false;
    const query_norm = normalize(u8, &query_buf, query, true) catch return false;
    return coversNormalized(u8, holder_norm, query_norm);
}

pub fn coversNormalized(comptime T: type, holder: []const T, query: []const T) bool {
    if (query.len == 0) return false;
    if (std.mem.eql(T, holder, query)) return true;
    if (holder.len <= query.len) return false;
    if (!std.mem.eql(T, holder[0..query.len], query)) return false;
    if (isSep(T, query[query.len - 1])) return true;
    return isSep(T, holder[query.len]);
}

/// Writes a comparable form of `path` into `out`: device prefix removed,
/// one trailing separator removed (a drive root keeps its slash), and,
/// when `fold_case` is set, ASCII and Russian Cyrillic case folded.
pub fn normalize(comptime T: type, out: []T, path: []const T, fold_case: bool) error{PathTooLong}![]T {
    var src = path;
    var written: usize = 0;
    if (startsWithAscii(T, src, "\\\\?\\UNC\\")) {
        if (out.len < 2) return error.PathTooLong;
        out[0] = '\\';
        out[1] = '\\';
        written = 2;
        src = src[8..];
    } else if (startsWithAscii(T, src, "\\\\?\\")) {
        src = src[4..];
    }
    if (written + src.len > out.len) return error.PathTooLong;
    @memcpy(out[written..][0..src.len], src);
    written += src.len;
    if (fold_case) fold(T, out[0..written]);
    if (written > 1 and isSep(T, out[written - 1])) {
        const drive_root = written == 3 and out[1] == ':' and isSep(T, out[2]);
        if (!drive_root) written -= 1;
    }
    return out[0..written];
}

fn isSep(comptime T: type, c: T) bool {
    return c == '\\' or c == '/';
}

fn startsWithAscii(comptime T: type, path: []const T, comptime ascii: []const u8) bool {
    if (path.len < ascii.len) return false;
    for (ascii, 0..) |c, i| {
        if (path[i] != c) return false;
    }
    return true;
}

fn fold(comptime T: type, buf: []T) void {
    if (T == u16) {
        for (buf) |*c| c.* = @intCast(lowerCp(c.*));
        return;
    }
    var i: usize = 0;
    while (i < buf.len) {
        const len = std.unicode.utf8ByteSequenceLength(buf[i]) catch {
            i += 1;
            continue;
        };
        if (i + len > buf.len) return;
        const cp = std.unicode.utf8Decode(buf[i..][0..len]) catch {
            i += 1;
            continue;
        };
        var encoded: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(lowerCp(cp), &encoded) catch {
            i += len;
            continue;
        };
        if (n == len) @memcpy(buf[i..][0..len], encoded[0..n]);
        i += len;
    }
}

fn lowerCp(cp: u21) u21 {
    if (cp >= 'A' and cp <= 'Z') return cp + 32;
    if (cp >= 0x0410 and cp <= 0x042F) return cp + 0x20;
    if (cp == 0x0401) return 0x0451;
    return cp;
}

test "exact path, ignoring case and the nt prefix" {
    try std.testing.expect(covers("\\\\?\\E:\\job\\git\\App", "e:\\job\\git\\app"));
}

test "a file inside the directory matches, a sibling does not" {
    try std.testing.expect(covers("E:\\job\\git\\app\\.git\\index", "E:\\job\\git\\app"));
    try std.testing.expect(!covers("E:\\job\\git\\application", "E:\\job\\git\\app"));
    try std.testing.expect(!covers("E:\\job\\git\\app", "E:\\job\\git\\app\\.git"));
}

test "drive root and unc prefix" {
    try std.testing.expect(covers("E:\\job", "E:\\"));
    try std.testing.expect(covers("\\\\?\\UNC\\server\\share\\a\\b", "\\\\server\\share"));
    try std.testing.expect(!covers("\\\\server\\share2\\a", "\\\\server\\share"));
}

test "trailing slash and russian case" {
    try std.testing.expect(covers("E:\\job\\git\\app\\.git", "E:\\job\\git\\app\\"));
    try std.testing.expect(covers("E:\\Путь\\файл", "E:\\путь"));
    try std.testing.expect(covers("E:\\Ёлка\\a", "E:\\ёлка"));
}
