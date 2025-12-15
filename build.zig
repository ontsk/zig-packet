const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create the library module
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Create library artifact
    const lib = b.addLibrary(.{
        .name = "zig-packet",
        .root_module = root_module,
    });
    b.installArtifact(lib);

    // Create module for consumers
    const packet_module = b.addModule("packet", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Example: simple dump demo
    const dump_module = b.createModule(.{
        .root_source_file = b.path("examples/dump.zig"),
        .target = target,
        .optimize = optimize,
    });
    dump_module.addImport("packet", packet_module);

    const dump_exe = b.addExecutable(.{
        .name = "dump",
        .root_module = dump_module,
    });
    b.installArtifact(dump_exe);

    // Run step for dump example
    const run_dump = b.addRunArtifact(dump_exe);
    run_dump.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_dump.addArgs(args);
    }

    const run_step = b.step("run", "Run the dump example");
    run_step.dependOn(&run_dump.step);

    // Tests
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib_tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);
}
