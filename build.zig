const std = @import("std");

const Fingerprint = @import("src/mod/common/Fingerprint.zig");

const nasm = @import("nasm");

const SUPPORTED_ARCH = &.{ .x86_64 };
const SUPPORTED_OS = &.{ .windows, .linux };

pub fn build(b: *std.Build) !void {
    const zon = parseZon(b, struct { version: []const u8 });

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // whitelisting doesnt really work the way we'd like here
    validateTarget(target.result);

    var version = std.SemanticVersion.parse(zon.version) catch {
        @panic("Cannot parse semantic version in build.zig.zon");
    };

    if (version.build != null) {
        @panic("Build metadata is not allowed in the version field of build.zig.zon; this is generated by the build system");
    }

    const fingerprint = Fingerprint.init("ribbon-lang.zig-api");

    const build_info_opts = b.addOptions();
    // build_info_opts.addOptionPath() -- cool!
    if (optimize != .Debug) {
        version.build = std.fmt.allocPrint(b.allocator, "{}", .{fingerprint}) catch @panic("OOM");
        build_info_opts.addOption(u256, "raw_fingerprint", fingerprint.value);
    } else {
        version.build = "debug";
        build_info_opts.addOption(u256, "raw_fingerprint", 0);
    }
    build_info_opts.addOption(std.SemanticVersion, "version", version);


    // create all modules //

    const abi_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/x64/abi.zig"),
        .target = target,
        .optimize = optimize,
    });

    const assembler_mod = b.dependency("X64EZ", .{
        .target = target,
        .optimize = optimize,
    }).module("X64EZ");

    const Buffer_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/common/Buffer.zig"),
        .target = target,
        .optimize = optimize,
    });

    const bytecode_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/bytecode.zig"),
        .target = target,
        .optimize = optimize,
    });

    const common_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/common.zig"),
        .target = target,
        .optimize = optimize,
    });

    const core_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/core.zig"),
        .target = target,
        .optimize = optimize,
    });

    const Fingerprint_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/common/Fingerprint.zig"),
        .target = target,
        .optimize = optimize,
    });

    const Formatter_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/common/Formatter.zig"),
        .target = target,
        .optimize = optimize,
    });

    const gen_mod = b.createModule(.{
        .root_source_file = b.path("src/bin/tools/gen.zig"),
        .target = target,
        .optimize = optimize,
    });

    const Id_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/common/Id.zig"),
        .target = target,
        .optimize = optimize,
    });

    const Instruction_mod = b.createModule(.{
        .root_source_file = null,
        .target = target,
        .optimize = optimize,
    });

    const Interner_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/common/Interner.zig"),
        .target = target,
        .optimize = optimize,
    });

    const interpreter_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/interpreter.zig"),
        .target = target,
        .optimize = optimize,
    });

    const ir_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/ir.zig"),
        .target = target,
        .optimize = optimize,
    });

    const isa_mod = b.createModule(.{
        .root_source_file = b.path("src/gen-base/zig/isa.zig"),
        .target = target,
        .optimize = optimize,
    });

    const machine_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/x64/machine.zig"),
        .target = target,
        .optimize = optimize,
    });

    const main_mod = b.createModule(.{
        .root_source_file = b.path("src/bin/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const meta_language_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/meta_language.zig"),
        .target = target,
        .optimize = optimize,
    });

    const platform_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/platform.zig"),
        .target = target,
        .optimize = optimize,
    });

    const ribbon_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const Stack_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/common/Stack.zig"),
        .target = target,
        .optimize = optimize,
    });

    const VirtualWriter_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/common/VirtualWriter.zig"),
        .target = target,
        .optimize = optimize,
    });



    // setup toolcalls //


    const gen_tool = b.addExecutable(.{
        .name = "gen",
        .root_module = gen_mod,
        .use_llvm = false,
        .use_lld = false,
    });


    const gen_isa = b.addRunArtifact(gen_tool);

    gen_isa.addArg("markdown");

    const Isa_markdown = gen_isa.addOutputFileArg("Isa.md");

    const Isa_markdown_install = b.addInstallFile(Isa_markdown, "docs/Isa.md");


    const gen_types = b.addRunArtifact(gen_tool);

    gen_types.addArg("types");

    const Instruction_src = gen_types.addOutputFileArg("Instruction.zig");
    const Instruction_src_install = b.addInstallFileWithDir(Instruction_src, .{ .custom = "tmp" }, "Instruction.zig");

    Instruction_mod.root_source_file = Instruction_src;


    // const gen_assembly = b.addRunArtifact(gen_tool);

    // gen_assembly.addArg("assembly");

    // const assembly_src = gen_assembly.addOutputFileArg("interpreter.asm");
    // const assembly_src_install = b.addInstallFileWithDir(assembly_src, .{ .custom = "tmp" }, "interpreter.asm");


    // const gen_assembly_header = b.addRunArtifact(gen_tool);

    // gen_assembly_header.addArg("assembly_header");

    // const assembly_header = gen_assembly_header.addOutputFileArg("ribbon.h.asm");
    // const assembly_header_install = b.addInstallFileWithDir(assembly_header, .{ .custom = "tmp" }, "ribbon.h.asm");


    // const gen_assembly_template = b.addRunArtifact(gen_tool);
    // gen_assembly_template.addArg("assembly_template");

    // const assembly_template = gen_assembly_template.addOutputFileArg("interpreter.template.asm");
    // const assembly_template_install = b.addInstallFileWithDir(assembly_template, .{ .custom = "tmp" }, "interpreter.template.asm");



    // const gen_object = b.addRunArtifact(b.dependency("nasm", .{
    //     .target = b.graph.host,
    //     .optimize = .ReleaseFast,
    // }).artifact("nasm"));

    // gen_object.addFileArg(assembly_src);

    // gen_object.addArg("-f");
    // gen_object.addArg(zigObjectFmtToNasm(target.result.ofmt));

    // if (optimize == .Debug or optimize == .ReleaseSafe) {
    //     gen_object.addArgs(&.{"-g", "-F dwarf", "-DDBG"});
    // }

    // gen_object.addArg("-o");
    // const assembly_obj = gen_object.addOutputFileArg("interpreter.o");
    // const assembly_obj_install = b.addInstallFileWithDir(assembly_obj, .{ .custom = "tmp" }, "interpreter.o");




    // create exports //

    const main_bin = b.addExecutable(.{
        .name = "ribbon",
        .root_module = main_mod,
        .linkage = .static,
    });

    const main_install = b.addInstallArtifact(main_bin, .{});



    // create tests //
    const abi_test = b.addTest(.{ .root_module = abi_mod });
    // assembler mod is a dep
    const Buffer_test = b.addTest(.{ .root_module = Buffer_mod });
    const bytecode_test = b.addTest(.{ .root_module = bytecode_mod });
    const common_test = b.addTest(.{ .root_module = common_mod });
    const core_test = b.addTest(.{ .root_module = core_mod });
    const Fingerprint_test = b.addTest(.{ .root_module = Fingerprint_mod });
    const Formatter_test = b.addTest(.{ .root_module = Formatter_mod });
    const gen_test = b.addTest(.{ .root_module = gen_mod });
    const Id_test = b.addTest(.{ .root_module = Id_mod });
    const Instruction_test = b.addTest(.{ .root_module = Instruction_mod });
    const Interner_test = b.addTest(.{ .root_module = Interner_mod });
    const interpreter_test = b.addTest(.{ .root_module = interpreter_mod });
    const ir_test = b.addTest(.{ .root_module = ir_mod });
    const isa_test = b.addTest(.{ .root_module = isa_mod });
    const machine_test = b.addTest(.{ .root_module = machine_mod });
    const main_test = b.addTest(.{ .root_module = main_mod });
    const meta_language_test = b.addTest(.{ .root_module = meta_language_mod });
    const platform_test = b.addTest(.{ .root_module = platform_mod });
    const ribbon_test = b.addTest(.{ .root_module = ribbon_mod });
    const Stack_test = b.addTest(.{ .root_module = Stack_mod });
    const VirtualWriter_test = b.addTest(.{ .root_module = VirtualWriter_mod });



    // add imports //

    abi_mod.addImport("assembler", assembler_mod);
    abi_mod.addImport("platform", platform_mod);

    // assembler_mod is a dep

    Buffer_mod.addImport("platform", platform_mod);

    bytecode_mod.addImport("platform", platform_mod);
    bytecode_mod.addImport("core", core_mod);
    bytecode_mod.addImport("Instruction", Instruction_mod);
    bytecode_mod.addImport("Id", Id_mod);
    bytecode_mod.addImport("Interner", Interner_mod);
    bytecode_mod.addImport("VirtualWriter", VirtualWriter_mod);

    common_mod.addImport("Formatter", Formatter_mod);
    common_mod.addImport("Id", Id_mod);
    common_mod.addImport("Interner", Interner_mod);
    common_mod.addImport("Stack", Stack_mod);
    common_mod.addImport("VirtualWriter", VirtualWriter_mod);

    core_mod.addImport("platform", platform_mod);
    core_mod.addImport("Id", Id_mod);
    core_mod.addImport("Buffer", Buffer_mod);
    core_mod.addImport("Stack", Stack_mod);

    Formatter_mod.addImport("platform", platform_mod);

    gen_mod.addImport("platform", platform_mod);
    gen_mod.addImport("isa", isa_mod);
    gen_mod.addImport("core", core_mod);
    gen_mod.addImport("assembler", assembler_mod);
    gen_mod.addImport("abi", abi_mod);

    gen_mod.addAnonymousImport("Isa_intro.md", .{ .root_source_file = b.path("src/gen-base/markdown/Isa_intro.md") });
    gen_mod.addAnonymousImport("Instruction_intro.zig", .{ .root_source_file = b.path("src/gen-base/zig/Instruction_intro.zig") });

    Id_mod.addImport("platform", platform_mod);

    Instruction_mod.addImport("platform", platform_mod);
    Instruction_mod.addImport("core", core_mod);
    Instruction_mod.addImport("Id", Id_mod);

    Interner_mod.addImport("platform", platform_mod);

    interpreter_mod.addImport("platform", platform_mod);
    interpreter_mod.addImport("core", core_mod);
    interpreter_mod.addImport("Instruction", Instruction_mod);
    // interpreter_mod.addObjectFile(assembly_obj);


    ir_mod.addImport("platform", platform_mod);
    ir_mod.addImport("Interner", Interner_mod);
    ir_mod.addImport("Id", Id_mod);

    isa_mod.addImport("platform", platform_mod);

    machine_mod.addImport("platform", platform_mod);
    machine_mod.addImport("core", core_mod);
    machine_mod.addImport("abi", abi_mod);
    machine_mod.addImport("assembler", assembler_mod);
    machine_mod.addImport("VirtualWriter", VirtualWriter_mod);

    main_mod.addImport("ribbon", ribbon_mod);

    meta_language_mod.addImport("platform", platform_mod);

    platform_mod.addImport("Fingerprint", Fingerprint_mod);
    platform_mod.addOptions("build_info", build_info_opts);

    ribbon_mod.addImport("abi", abi_mod);
    ribbon_mod.addImport("platform", platform_mod);
    ribbon_mod.addImport("Buffer", Buffer_mod);
    ribbon_mod.addImport("bytecode", bytecode_mod);
    ribbon_mod.addImport("common", common_mod);
    ribbon_mod.addImport("machine", machine_mod);
    ribbon_mod.addImport("core", core_mod);
    ribbon_mod.addImport("interpreter", interpreter_mod);
    ribbon_mod.addImport("ir", ir_mod);
    ribbon_mod.addImport("meta_language", meta_language_mod);

    Stack_mod.addImport("platform", platform_mod);

    VirtualWriter_mod.addImport("platform", platform_mod);



    // setup steps //

    const install_step = b.default_step;
    install_step.dependOn(&main_install.step);

    const run_step = b.step("run", "Run the ribbon driver");
    const run_main = b.addRunArtifact(main_bin);
    if (b.args) |args| {
        run_main.addArgs(args);
    }
    run_step.dependOn(&run_main.step);

    const dump_intermediates_step = b.step("dump-intermediates", "Dump intermediate files to zig-out");
    dump_intermediates_step.dependOn(&Instruction_src_install.step);
    // dump_intermediates_step.dependOn(&assembly_src_install.step);
    // dump_intermediates_step.dependOn(&assembly_obj_install.step);
    // dump_intermediates_step.dependOn(&assembly_header_install.step);
    // dump_intermediates_step.dependOn(&assembly_template_install.step);
    dump_intermediates_step.dependOn(&b.addInstallFile(Isa_markdown, "tmp/Isa.md").step);

    if (optimize == .Debug) { // debugging assembly codegen somewhat requires this atm TODO: re-evaluate when stable
        install_step.dependOn(dump_intermediates_step);
        run_step.dependOn(dump_intermediates_step);
    }

    // const write_assembly_header_step = b.step("asm-header", "Output the assembly header file for nasm language features");
    // write_assembly_header_step.dependOn(&assembly_header_install.step);

    // const write_assembly_template_step = b.step("asm-template", "Output an interpreter assembly template");
    // write_assembly_template_step.dependOn(&assembly_template_install.step);

    const check_step = b.step("check", "Run semantic analysis");
    check_step.dependOn(&abi_test.step);

    check_step.dependOn(&Buffer_test.step);
    check_step.dependOn(&bytecode_test.step);
    check_step.dependOn(&common_test.step);
    check_step.dependOn(&core_test.step);
    check_step.dependOn(&Fingerprint_test.step);
    check_step.dependOn(&Formatter_test.step);
    check_step.dependOn(&gen_test.step);
    check_step.dependOn(&Id_test.step);
    check_step.dependOn(&Instruction_test.step);
    check_step.dependOn(&Interner_test.step);
    check_step.dependOn(&interpreter_test.step);
    check_step.dependOn(&ir_test.step);
    check_step.dependOn(&isa_test.step);
    check_step.dependOn(&machine_test.step);
    check_step.dependOn(&main_test.step);
    check_step.dependOn(&meta_language_test.step);
    check_step.dependOn(&platform_test.step);
    check_step.dependOn(&ribbon_test.step);
    check_step.dependOn(&Stack_test.step);
    check_step.dependOn(&VirtualWriter_test.step);

    const test_step = b.step("unit-test", "Run all unit tests");
    test_step.dependOn(&b.addRunArtifact(abi_test).step);

    test_step.dependOn(&b.addRunArtifact(Buffer_test).step);
    test_step.dependOn(&b.addRunArtifact(bytecode_test).step);
    test_step.dependOn(&b.addRunArtifact(common_test).step);
    test_step.dependOn(&b.addRunArtifact(core_test).step);
    test_step.dependOn(&b.addRunArtifact(Fingerprint_test).step);
    test_step.dependOn(&b.addRunArtifact(Formatter_test).step);
    test_step.dependOn(&b.addRunArtifact(gen_test).step);
    test_step.dependOn(&b.addRunArtifact(Id_test).step);
    test_step.dependOn(&b.addRunArtifact(Instruction_test).step);
    test_step.dependOn(&b.addRunArtifact(Interner_test).step);
    test_step.dependOn(&b.addRunArtifact(interpreter_test).step);
    test_step.dependOn(&b.addRunArtifact(ir_test).step);
    test_step.dependOn(&b.addRunArtifact(isa_test).step);
    test_step.dependOn(&b.addRunArtifact(machine_test).step);
    test_step.dependOn(&b.addRunArtifact(main_test).step);
    test_step.dependOn(&b.addRunArtifact(meta_language_test).step);
    test_step.dependOn(&b.addRunArtifact(platform_test).step);
    test_step.dependOn(&b.addRunArtifact(ribbon_test).step);
    test_step.dependOn(&b.addRunArtifact(Stack_test).step);
    test_step.dependOn(&b.addRunArtifact(VirtualWriter_test).step);


    const docs_step = b.step("docs", "Generate documentation");

    docs_step.dependOn(&b.addInstallDirectory(.{
        .source_dir = ribbon_test.getEmittedDocs(),
        .install_dir = .{ .custom = "docs" },
        .install_subdir = "api",
    }).step);
    docs_step.dependOn(&Isa_markdown_install.step);


    const isa_step = b.step("isa", "Generate ISA documentation");

    isa_step.dependOn(&Isa_markdown_install.step);
}


fn parseZon(b: *std.Build, comptime T: type) T {
    const zonText = std.fs.cwd().readFileAllocOptions(b.allocator, "build.zig.zon", std.math.maxInt(usize), 2048, 1, 0)
        catch @panic("Unable to read build.zig.zon");

    var parseStatus = std.zon.parse.Status{};

    return std.zon.parse.fromSlice(
        T,
        b.allocator,
        zonText,
        &parseStatus,
        .{ .ignore_unknown_fields = true },
    ) catch |err| {
        std.debug.print("Error {s}:\n", .{@errorName(err)});

        var it = parseStatus.iterateErrors();

        while (it.next()) |parseErr| {
            const loc = parseErr.getLocation(&parseStatus);

            std.debug.print("[build.zig.zon:{}]: {s}\n", .{loc.line + 1, parseErr.fmtMessage(&parseStatus)});
        }

        std.process.exit(1);
    };
}


fn zigObjectFmtToNasm(zigFmt: std.Target.ObjectFormat) []const u8 {
    switch (zigFmt) {
        .coff => return "coff",
        .elf => return "elf64",

        else => std.debug.panic(
            \\
            \\
            \\Object format `{s}` is not supported by Ribbon.
            \\
            \\
            , .{@tagName(zigFmt)} ,
        ),
    }
}


fn validateTarget(target: std.Target) void {
    if (std.mem.indexOfScalar(std.Target.Cpu.Arch, SUPPORTED_ARCH, target.cpu.arch) == null) {
        if (target.cpu.arch.endian() == .big) {
            @panic(
                \\
                \\
                \\Ribbon does not build for big-endian architectures.
                \\
                \\
            );
        } else {
            std.debug.panic(
                \\
                \\
                \\Ribbon cannot yet build for {s} architectures;
                \\You can try checking current Issues/PRs for updates, or filing one yourself.
                \\We want this to work, but its a *lot* of work.
                \\
                \\
                , .{ @tagName(target.cpu.arch) } ,
            );
        }
    }

    if (std.mem.indexOfScalar(std.Target.Os.Tag, SUPPORTED_OS, target.os.tag) == null) {
        std.debug.panic(
            \\
            \\
            \\Ribbon cannot yet build for {s} operating systems.
            \\You can try disabling this check in the `build.zig file`.
            \\If it happens to work let us know on GitHub!
            \\
            \\
            , .{ @tagName(target.os.tag) } ,
        );
    }
}
