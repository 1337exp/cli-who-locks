# who-locks

**English** · [Русский](README.ru.md)

`who-locks` names the processes that have a file or directory open. Give it the folder Windows refuses to rename or move.

Version 0.1.0. It is a small program in Zig 0.16 and 0.17. Zig builds for other systems, so the Windows calls live in one file and the rest of the program is ordinary code. The scan itself exists for Windows. A build for another system compiles and then stops with a message.

## Run

[Zig 0.16 or 0.17](https://ziglang.org/download/).

```bash
zig build test
zig build
zig-out/bin/who-locks.exe E:\job\git\pkt-block-topo\.git
zig-out/bin/who-locks.exe --json E:\job\git\pkt-block-topo\.git
```

`zig build run -- <path>` runs the same binary. When nothing matches, the program exits with status 1, and `zig build run` treats that as a failed step. The exe under `zig-out/bin` is the straightforward way to use it.

## Programs and agents

A program or an agent asks with one absolute path, as a single argument:

```bash
who-locks --json E:\job\git\pkt-block-topo\.git
```

One call walks the handle table once and answers for that one path. A second path is rejected. The walk takes a few seconds, so the caller asks once and uses the answer.

stdout is one JSON object and a newline. stderr carries progress (`scanning open handles...`) and, when the scan fails, the reason. Read the exit status before the body:

| Status | Meaning | stdout |
| --- | --- | --- |
| 0 | At least one process | JSON, `matched` is true |
| 1 | The scan finished, and no readable handle matches | JSON, `matched` is false. This is an answer. |
| 2 | Bad usage, or the scan failed | May be empty. The reason is on stderr. |

Status 1 is easy to treat as a crash. It means the scan worked and `processes` is empty.

```json
{"version":1,"path":"E:\\job\\git\\pkt-block-topo\\.git","matched":true,"handles_seen":620027,"processes":[{"pid":56488,"name":"claude.exe","paths":["E:\\job\\git\\pkt-block-topo\\.git"]}]}
```

`version` is 1. `matched` is true when `processes` is non-empty. `path` is the absolute path that was matched, without a `\?\` prefix. `handles_seen` is how many handles the table held. Each process has `pid`, `name` (the file name, or `""` when it could not be read), and `paths` (the open paths under the query).

These names stay. New fields may appear later. A parser skips a field it does not know.

`matched: false` means no readable handle pointed at the path. A protected process can still hold it. Status 2 means the scan did not finish, and an empty stdout is not an answer.

The text format, without `--json`, is for a person at a terminal. `who-locks --help` prints the same contract.

## Sample

A real run on this machine. Claude Desktop had `E:\job\git\pkt-block-topo\.git` open, which is why that folder would not move.

```
scanning open handles...
E:\job\git\pkt-block-topo\.git

56488  claude.exe
  E:\job\git\pkt-block-topo\.git

looked at 614074 handles
```

`scanning open handles...` goes to stderr, so `--json` on stdout stays one object. who-locks prints the holder. Close that program, and the directory can be moved.

## What a match means

The path matches itself and anything inside it. ASCII case is ignored, and so is the case of Russian letters (А–Я and Ё).

`E:\work` matches `E:\work\.git\index`. `E:\workspace` is a different path. A drive root such as `E:\` matches the whole drive. A trailing slash does not matter. The `\?\` prefix that Windows puts on some paths is stripped before the comparison.

A directory is open when a process holds the directory itself or a file inside it. That is the situation in which a rename or a move fails.

## How

The scan runs in ordinary user mode. There is no driver in this program.

It asks Windows for the system handle table, duplicates each handle it is allowed to see, and reads the path when the handle points at a file or a directory. The table comes from `NtQuerySystemInformation` class 64 (`SystemExtendedHandleInformation`). That class is not a documented Win32 function. Sysinternals Handle reads the same kind of table. The path comes from `GetFinalPathNameByHandle`.

A driver is what you would add to force-close someone else's handle, or to look inside a protected process. who-locks does neither. It only lists what user mode can already see.

On this machine the table held about 600 thousand handles, and a scan took a few seconds.

## Checked

| Where | What happened |
| --- | --- |
| Windows 11 Pro, build 22631, x86_64, Zig 0.16.0 | The sample above. |
| Windows 11 Pro, build 22631, x86_64, Zig 0.17.0 | `zig build test` passes, and a `--json` scan runs. The program sources are unchanged. `build.zig` forwards `zig build run -- <path>` through `Build.args` on 0.16 and through `addPassthruArgs` on 0.17. |
| Linux, target `x86_64-linux-musl` | `zig build -Dtarget=x86_64-linux-musl` compiles. The binary was not run on Linux. It has no scanner. |
| macOS, target `x86_64-macos` | `zig build -Dtarget=x86_64-macos` compiles. The binary was not run on a Mac. It has no scanner. |

Windows 10 was not tried. The handle-table layout is undocumented, so a future Windows can break the scan. The program then exits with an error instead of inventing an owner.

## Limits

- The handle table is decoded for 64-bit Windows.
- Processes of the same user show up from a normal terminal. Processes of other users, and many services, show up from an elevated terminal.
- Protected processes, such as some antivirus services, can refuse to be opened. They stay invisible in an elevated terminal too. An empty result still leaves that possibility, and a non-empty result can still miss one of them.
- Case folding covers ASCII and Russian Cyrillic. Other alphabets are compared as written.
- A handle opened through a volume GUID (`\\?\Volume{...}\`) can be missed when the path you typed uses a drive letter.
- The program lists holders. Closing the handle is left to you.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | At least one matching process |
| 1 | No readable handle matches |
| 2 | Bad usage, or the scan failed |

The same three statuses apply to text and to `--json`. The fields are described in [Programs and agents](#programs-and-agents).

## Layout

```
src/main.zig      arguments, text, json
src/windows.zig   the handle table
src/match.zig     which path is inside which, with tests
src/other.zig     every OS other than Windows
src/report.zig    the shared result
```
