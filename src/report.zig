/// JSON object schema. Fields are added, and existing names stay.
pub const json_version: u32 = 1;

pub const Hit = struct {
    pid: u32,
    /// File name of the executable, or an empty string when it could not be read.
    name: []const u8,
    /// Open paths under the query, with the `\\?\` prefix removed.
    paths: []const []const u8,
};

pub const QueryError = error{
    PlatformNotImplemented,
    AccessDenied,
    NtQueryFailed,
    InvalidPath,
    PathTooLong,
    OutOfMemory,
    InvalidWtf8,
};

pub const Outcome = struct {
    /// Path that was matched, absolute, without a `\\?\` prefix.
    path: []const u8,
    hits: []const Hit,
    handles_seen: usize,
};
