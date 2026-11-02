const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "who-locks",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "Run who-locks");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    // 0.17 removed Build.args. The old branch is what 0.16 compiles.
    if (comptime @import("builtin").zig_version.minor < 17) {
        if (b.args) |args| run_cmd.addArgs(args);
    } else {
        run_cmd.addPassthruArgs();
    }

    const tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
