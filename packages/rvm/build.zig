const std = @import("std");
const Build = std.Build;
const Meta = @import("tools/Meta.zig");
const Utils = Meta.Utils;
const Builder = Utils.Build.Module;

const BuildMetaData = Meta.BuildMetaData;
const Snapshot = Builder.Snapshot;
const Manifest = Builder.Manifest;
const SourceTree = Builder.SourceTree;
const Compilation = Builder.Compilation;
const TypeUtils = Utils.Type;

const Builtin = @import("builtin");

const hostArch = Builtin.cpu.arch;
const hostOS = Builtin.os.tag;
const hostAbi = Builtin.abi;

const targets = BuildMetaData.releaseTargets;

const log = std.log.scoped(.build);

pub fn build(b: *Build) !void {
    const defaultTarget = b.standardTargetOptions(.{});
    const defaultOptimize = b.standardOptimizeOption(.{});

    const cwdPath = try std.fs.cwd().realpathAlloc(b.allocator, ".");
    const prefixPath = if (std.mem.startsWith(u8, b.install_prefix, cwdPath)) b.fmt(".{s}", .{b.install_prefix[cwdPath.len..]}) else b.install_prefix;

    const manifest = try Manifest.readFile(b.allocator, "build.zig.zon");

    const cliOptions = makeCliOptions(b);
    const buildOptions = makeBuildOptions(&cliOptions);

    const nativeConfig = makeConfig(b, &cliOptions, &manifest);
    nativeConfig.addOption(bool, "maximumInlining", false);

    try validatePackageDeps(&manifest, BuildMetaData.packageDeps);

    const nativeDependencies =
        TypeUtils.structConcat(.{
            BuildMetaData.packageDeps,
            .{ .config = nativeConfig },
        });

    const buildCommands = try makeBuildCommands(b);

    const nativeTarget = b.resolveTargetQuery(.{});
    const nativeOptimize = .Debug;

    const toolingTree = try SourceTree.getMap(b.allocator, BuildMetaData.paths.withTooling);
    const sourceTree = try SourceTree.getMap(b.allocator, BuildMetaData.paths.sourceOnly);

    const stripDebugInfo = buildOptions.stripDebugInfo;

    const compilationMetaModule = Compilation.Meta {
        .native = b.dependency("Utils", .{
            .target = nativeTarget,
            .optimize = nativeOptimize,
        }),
    };

    const nativeCompSet = try Compilation.init(
        b,
        "native",
        toolingTree,
        nativeDependencies,
        .{
            .meta = compilationMetaModule,
            .vis = .private,
            .target = nativeTarget,
            .optimize = nativeOptimize,
            .strip = nativeOptimize != .Debug,
            .fileGen = true,
            .tests = false,
        },
    );

    const testConfig = makeConfig(b, &cliOptions, &manifest);
    testConfig.addOption(bool, "maximumInlining", buildOptions.maximumInlining orelse (defaultOptimize != .Debug));

    const testDependencies =
        TypeUtils.structConcat(.{ BuildMetaData.packageDeps, .{
        .config = testConfig,
    } });

    const testCompSet = try Compilation.init(b, "tests", sourceTree, testDependencies, .{
        .meta = .{ .generative = nativeCompSet },
        .vis = .private,
        .target = defaultTarget,
        .optimize = defaultOptimize,
        .strip = defaultOptimize != .Debug,
        .fileGen = false,
        .tests = true,
    });

    var snapshotHelper = try nativeCompSet.getSnapshotHelper("tests/.snapshot");

    const defaultFullBuild = defaultFullBuild: {
        break :defaultFullBuild try fullBuild(b, nativeCompSet, &cliOptions, &manifest, &buildOptions, .public, defaultOptimize, stripDebugInfo, defaultTarget.query);
    };

    const defaultCommand: *Build.Step = b.default_step;
    {
        defaultCommand.dependOn(&defaultFullBuild.step);
    }

    const quickCommand: *Build.Step = buildCommands.get("quick").?;
    {
        quickCommand.dependOn(&defaultFullBuild.bin.step);
    }

    const runCommand: *Build.Step = buildCommands.get("run").?;
    {
        const run = b.addRunArtifact(defaultFullBuild.bin);

        if (b.args) |args| run.addArgs(args);

        runCommand.dependOn(&run.step);
    }

    const checkCommand: *Build.Step = buildCommands.get("check").?;
    {
        for (testCompSet.tests.items) |testName| {
            const t = try testCompSet.getTest(testName);

            checkCommand.dependOn(&t.step);
        }
    }

    const unitTestsCommand: *Build.Step = buildCommands.get("unit-tests").?;
    {
        for (testCompSet.tests.items) |testName| {
            const t = try testCompSet.getTest(testName);
            const testStep = b.addRunArtifact(t);
            unitTestsCommand.dependOn(&testStep.step);
        }
    }

    const cliTestsCommand: *Build.Step = buildCommands.get("cli-tests").?;
    {
        snapshotHelper.runWith(cliTestsCommand);

        const releaseHost = try fullBuild(b, nativeCompSet, &cliOptions, &manifest, &buildOptions, .private, .ReleaseFast, stripDebugInfo, nativeTarget.query);

        try cliTest(b, &buildOptions, &snapshotHelper, releaseHost.bin, cliTestsCommand, .Pass);
        try cliTest(b, &buildOptions, &snapshotHelper, releaseHost.bin, cliTestsCommand, .Fail);
    }

    const cTestsCommand: *Build.Step = buildCommands.get("c-tests").?;
    {
        snapshotHelper.runWith(cTestsCommand);

        if (hostOS == .linux and hostArch == .x86_64 and hostAbi == .gnu) {
            try cTest(b, cTestsCommand, &cliOptions, &manifest, &buildOptions, &snapshotHelper, prefixPath, nativeCompSet, stripDebugInfo, .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu }, null);
            try cTest(b, cTestsCommand, &cliOptions, &manifest, &buildOptions, &snapshotHelper, prefixPath, nativeCompSet, stripDebugInfo, .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu }, "wine64");
        } else {
            const warn = Build.Step.Run.create(b, "unsupported c-test host");
            warn.addArgs(&[_][]const u8{ "echo", b.fmt("\x1b[33mWarning\x1b[39m: c-tests are currently only supported on \x1b[32mx86_64-linux-gnu\x1b[39m, " ++ "current host is \x1b[31m{s}\x1b[39m; skipping c-tests", .{try (std.Target.Query{ .cpu_arch = hostArch, .os_tag = hostOS, .abi = hostAbi }).zigTriple(b.allocator)}) });
            cTestsCommand.dependOn(&warn.step);
        }
    }

    const headerCommand: *Build.Step = buildCommands.get("header").?;
    const headers = headerFiles: {
        const header = try nativeCompSet.getHeader("librvm");

        const writeHeader = b.addUpdateSourceFiles();

        const sourcePath = "include/rvm.h";

        writeHeader.addCopyFileToSource(header, sourcePath);

        headerCommand.dependOn(&writeHeader.step);

        break :headerFiles .{ .lazy = header, .source = sourcePath };
    };

    const readmeCommand: *Build.Step = buildCommands.get("readme").?;
    const readmes = readmeFiles: {
        const genPath = try nativeCompSet.getFile("README");
        const sourcePath = "./README.md";

        const writeReadme = b.addUpdateSourceFiles();

        writeReadme.addCopyFileToSource(genPath, sourcePath);

        readmeCommand.dependOn(&writeReadme.step);

        break :readmeFiles .{ .lazy = genPath, .source = sourcePath };
    };

    const releaseCommand: *Build.Step = buildCommands.get("release").?;
    {
        targetLoop: for (targets) |t| {
            if (b.args) |args| {
                for (args) |arg| {
                    const triple = try t.zigTriple(b.allocator);
                    if (matchArg(triple, arg)) {
                        break;
                    }
                } else {
                    continue :targetLoop;
                }
            }

            const rel = try fullBuild(b, nativeCompSet, &cliOptions, &manifest, &buildOptions, .private, .ReleaseFast, false, t);
            releaseCommand.dependOn(&rel.step);
        }
    }

    const verifyHeaderCommand: *Build.Step = buildCommands.get("verify-header").?;
    {
        const expectEqualBin = try nativeCompSet.getBinary("ExpectEqual");

        const verifyHeader = b.addRunArtifact(expectEqualBin);
        verifyHeader.addFileArg(headers.lazy);
        verifyHeader.addFileArg(b.path(headers.source));

        verifyHeader.expectExitCode(0);

        verifyHeaderCommand.dependOn(&verifyHeader.step);
    }

    const verifyReadmeCommand: *Build.Step = buildCommands.get("verify-readme").?;
    {
        const expectEqualBin = try nativeCompSet.getBinary("ExpectEqual");

        const verifyReadme = b.addRunArtifact(expectEqualBin);
        verifyReadme.addFileArg(readmes.lazy);
        verifyReadme.addFileArg(b.path(readmes.source));

        verifyReadme.expectExitCode(0);

        verifyReadmeCommand.dependOn(&verifyReadme.step);
    }

    const verifyTestsCommand: *Build.Step = buildCommands.get("verify-tests").?;
    {
        verifyTestsCommand.dependOn(buildCommands.get("test").?);
    }

    const fullCommand: *Build.Step = buildCommands.get("full").?;
    {
        inline for (BuildMetaData.fullCommandNames) |name| {
            const step = buildCommands.get(name).?;
            fullCommand.dependOn(step);
        }
    }

    const verifyCommand: *Build.Step = buildCommands.get("verify").?;
    {
        inline for (BuildMetaData.verifyCommandNames) |name| {
            const step = buildCommands.get(name).?;
            verifyCommand.dependOn(step);
        }
    }

    const testCommand: *Build.Step = buildCommands.get("test").?;
    {
        inline for (BuildMetaData.testCommandNames) |name| {
            const step = buildCommands.get(name).?;
            testCommand.dependOn(step);
        }
    }

    snapshotHelper.finalize();
}

fn matchArg(against: []const u8, arg: []const u8) bool {
    return std.mem.containsAtLeast(u8, against, 1, arg);
}

fn makeBuildCommands(b: *Build) !std.StringHashMap(*Build.Step) {
    var map = std.StringHashMap(*Build.Step).init(b.allocator);

    inline for (comptime std.meta.fieldNames(@TypeOf(BuildMetaData.commands))) |name| {
        const step = b.step(name, @field(BuildMetaData.commands, name));
        try map.put(name, step);
    }

    return map;
}

const CliOptions = opts: {
    const optionNames = std.meta.fieldNames(@TypeOf(BuildMetaData.options));
    const buildOptionNames = std.meta.fieldNames(@TypeOf(BuildMetaData.buildOptions));
    const totalFields = optionNames.len + buildOptionNames.len;
    var fields = [1]std.builtin.Type.StructField{undefined} ** totalFields;

    var i: usize = 0;
    for (optionNames) |fieldName| {
        const opt = @field(BuildMetaData.options, fieldName);
        fields[i] = .{
            .name = fieldName,
            .type = opt[0],
            .default_value = null,
            .is_comptime = false,
            .alignment = @alignOf(opt[0]),
        };
        i += 1;
    }

    for (buildOptionNames) |fieldName| {
        const opt = @field(BuildMetaData.buildOptions, fieldName);

        const ty = switch (@typeInfo(opt[0])) {
            .optional => opt[0],
            else => ?opt[0],
        };

        fields[i] = .{
            .name = fieldName,
            .type = ty,
            .default_value = null,
            .is_comptime = false,
            .alignment = @alignOf(opt[0]),
        };
        i += 1;
    }

    break :opts @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = &fields,
            .decls = &[0]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
};

fn makeCliOptions(b: *Build) CliOptions {
    var out: CliOptions = undefined;
    inline for (comptime std.meta.fieldNames(@TypeOf(BuildMetaData.options))) |dataOpt| {
        const opt = @field(BuildMetaData.options, dataOpt);
        if (opt.len == 3) {
            @field(out, dataOpt) = b.option(opt[0], dataOpt, opt[1]) orelse opt[2];
        }
    }
    inline for (comptime std.meta.fieldNames(@TypeOf(BuildMetaData.buildOptions))) |dataOpt| {
        const opt = @field(BuildMetaData.buildOptions, dataOpt);
        const ty = switch (@typeInfo(opt[0])) {
            .optional => |info| info.child,
            else => opt[0],
        };
        @field(out, dataOpt) = b.option(ty, dataOpt, opt[1]);
    }
    return out;
}

fn makeConfig(b: *Build, cliOptions: *const CliOptions, manifest: *const Manifest) *Build.Step.Options {
    const proto = TypeUtils.structConcat(.{
        .{
            .version = .{std.SemanticVersion},
        },
        BuildMetaData.options,
    });

    const config = b.addOptions();
    inline for (comptime std.meta.fieldNames(@TypeOf(proto))) |dataOpt| {
        const opt = @field(proto, dataOpt);
        switch (opt.len) {
            3 => {
                config.addOption(opt[0], dataOpt, @field(cliOptions, dataOpt));
            },
            2 => {
                config.addOption(opt[0], dataOpt, opt[1]);
            },
            1 => {
                config.addOption(opt[0], dataOpt, @field(manifest, dataOpt));
            },
            else => {
                @compileError("invalid config option `" ++ dataOpt ++ "`");
            },
        }
    }
    return config;
}

fn makeBuildOptions(cliOptions: *const CliOptions) BuildOptions {
    var options: BuildOptions = undefined;
    inline for (comptime std.meta.fieldNames(@TypeOf(BuildMetaData.buildOptions))) |dataOpt| {
        const opt = @field(BuildMetaData.buildOptions, dataOpt);
        if (comptime opt.len != 3) {
            if (comptime opt.len == 2) {
                @field(options, dataOpt) = @field(cliOptions, dataOpt);
            } else {
                @compileError("invalid build config option `" ++ dataOpt ++ "`");
            }
        } else {
            @field(options, dataOpt) = @field(cliOptions, dataOpt) orelse opt[2];
        }
    }
    return options;
}

const BuildOptions = ty: {
    const T = @TypeOf(BuildMetaData.buildOptions);
    const fieldNames = std.meta.fieldNames(T);
    var fields = [1]std.builtin.Type.StructField{undefined} ** fieldNames.len;
    for (fieldNames, 0..) |name, i| {
        const field = @field(BuildMetaData.buildOptions, name);
        const ty = field[0];
        fields[i] = .{
            .name = name,
            .type = ty,
            .default_value = null,
            .is_comptime = false,
            .alignment = @alignOf(ty),
        };
    }
    break :ty @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = &fields,
            .decls = &[0]std.builtin.Type.Declaration{},
            .is_tuple = false,
        },
    });
};

fn validatePackageDeps(manifest: *const Manifest, deps: anytype) !void {
    const manifestDepNames = manifest.dependencies.keys();
    const packageDepNames = comptime std.meta.fieldNames(@TypeOf(deps));

    inline for (packageDepNames) |depName| {
        if (!manifest.dependencies.contains(depName)) {
            log.err("missing dependency {s} in manifest", .{depName});
            return error.InvalidDeps;
        }
    }

    outer: for (manifestDepNames) |depName| {
        for (packageDepNames) |depName2| {
            if (std.mem.eql(u8, depName, depName2)) {
                continue :outer;
            }
        }

        log.warn("unused dependency {s} in manifest", .{depName});
    }
}

const FullBuild = struct {
    step: Build.Step,
    abi: std.Target.Abi,
    comp: *Compilation = undefined,
    mod: *Build.Module = undefined,
    lib: *Build.Step.Compile = undefined,
    bin: *Build.Step.Compile = undefined,
};

fn targetStep(owner: *Build, name: []const u8, abi: std.Target.Abi) !*FullBuild {
    const target = try owner.allocator.create(FullBuild);

    target.* = .{
        .step = Build.Step.init(.{
            .id = .custom,
            .name = name,
            .owner = owner,
            .makeFn = makeGuard,
        }),
        .abi = abi,
    };

    return target;
}

fn makeGuard(step: *Build.Step, opts: Build.Step.MakeOptions) anyerror!void {
    _ = opts;

    const target: *FullBuild = @fieldParentPtr("step", step);

    if (target.abi == .msvc and hostOS != .windows) {
        log.warn("skipping target {s} because host OS is not windows (cannot cross compile this abi)\n", .{step.name});
    }

    var all_cached = true;

    for (step.dependencies.items) |dep| {
        all_cached = all_cached and dep.result_cached;
    }

    step.result_cached = all_cached;
}

fn fullBuild(b: *Build, nativeCompSet: *Compilation, cliOptions: *const CliOptions, manifest: *const Manifest, buildOptions: *const BuildOptions, vis: SourceTree.EntryVis, optimize: std.builtin.OptimizeMode, stripDebugInfo: ?bool, t: std.Target.Query) !*FullBuild {
    const relTarget = b.resolveTargetQuery(t);
    const relPath = b.fmt("{s}-{s}", .{try relTarget.query.zigTriple(b.allocator), optimizeModeName(optimize)});


    const config = makeConfig(b, cliOptions, manifest);
    config.addOption(bool, "maximumInlining", buildOptions.maximumInlining orelse (optimize != .Debug));

    const dependencies =
        TypeUtils.structConcat(.{ BuildMetaData.packageDeps, .{
        .config = config,
    } });


    const comp = try Compilation.init(
        b,
        relPath,
        nativeCompSet.tree,
        dependencies,
        .{
            .meta = .{ .generative = nativeCompSet },
            .vis = vis,
            .target = relTarget,
            .optimize = optimize,
            .strip = stripDebugInfo orelse (optimize != .Debug),
            .fileGen = false,
            .tests = false,
        },
    );

    const target = try targetStep(b, relPath, comp.target.result.abi);

    target.comp = comp;

    if (comp.target.result.abi == .msvc) {
        if (comp.target.result.cpu.arch != hostArch or hostOS != .windows) {
            return target;
        }
    }

    const core = try comp.getModule("Core");

    target.mod = core;


    const libRibbon = try comp.getLibrary("librvm");

    target.lib = libRibbon;

    libRibbon.bundle_compiler_rt = true;

    const installLib = b.addInstallArtifact(libRibbon, .{
        .dest_sub_path = b.fmt("{s}rvm{s}", .{relTarget.result.libPrefix(), relTarget.result.staticLibSuffix()}),
        .dest_dir = .{
            .override = .{
                .custom = relPath,
            },
        },
    });

    target.step.dependOn(&installLib.step);

    const installInclude = b.addInstallFile(
        try nativeCompSet.getHeader("librvm"),
        b.fmt("{s}/include/rvm.h", .{relPath}),
    );
    target.step.dependOn(&installInclude.step);

    const installLicense = b.addInstallFile(
        b.path("LICENSE"),
        b.fmt("{s}/LICENSE", .{relPath}),
    );

    target.step.dependOn(&installLicense.step);

    const installReadme = b.addInstallFile(
        try nativeCompSet.getFile("README"),
        b.fmt("{s}/README.md", .{relPath}),
    );

    target.step.dependOn(&installReadme.step);

    const bin = try comp.getBinary("rvm");

    target.bin = bin;

    const installExe = b.addInstallArtifact(bin, .{
        .dest_dir = .{
            .override = .{
                .custom = relPath,
            },
        },
    });

    target.step.dependOn(&installExe.step);

    return target;
}

const ScriptTestKind = enum {
    Pass,
    Fail,
};

fn cliTest(b: *Build, buildOptions: *const BuildOptions, snapshotHelper: *Snapshot.Helper, bin: *Build.Step.Compile, step: *Build.Step, kind: ScriptTestKind) !void {
    const kindName = switch (kind) {
        .Pass => "pass",
        .Fail => "fail",
    };

    const kindPath = b.fmt("tests/{s}", .{kindName});
    const kindDir = try std.fs.cwd().makeOpenPath(kindPath, .{ .iterate = true });

    var iter = kindDir.iterate();

    testLoop: while (try iter.next()) |tEntry| {
        if (tEntry.kind == .file) {
            const localPath = b.fmt("{s}/{s}", .{ kindName, tEntry.name });
            if (b.args) |args| {
                for (args) |arg| {
                    if (matchArg(localPath, arg)) {
                        break;
                    }
                } else {
                    continue :testLoop;
                }
            }
            const tPath = b.fmt("./tests/{s}", .{localPath});
            const name = std.fs.path.stem(tEntry.name);
            const tTest = Build.Step.Run.create(b, b.fmt("{s} {s}", .{ kindName, name }));
            tTest.addArtifactArg(bin);
            tTest.addFileInput(b.path(tPath));
            tTest.addArg(tPath);

            const snapshotName = b.fmt("{s}:{s}", .{ kindName, name });

            tTest.expectExitCode(switch (kind) {
                .Pass => 0,
                .Fail => 1,
            });

            const expectedOutput =
                if (buildOptions.forceNewSnapshot) null
                else snapshotHelper.get(snapshotName);

            if (expectedOutput) |expect| {
                const text = try expect.toText(b.allocator);
                tTest.expectStdOutEqual(text.out);
                tTest.expectStdErrEqual(text.err);

                step.dependOn(&tTest.step);
            } else {
                const snapshot = Snapshot.LazyPair{ .out = tTest.captureStdOut(), .err = tTest.captureStdErr() };
                try snapshotHelper.put(snapshotName, snapshot);

                const warn = b.addSystemCommand(&[_][]const u8{ "echo", b.fmt("manual validation required, new snapshots added; capturing output of test [{s}] to the following paths:\n", .{tPath}) });
                warn.addFileArg(snapshot.out);
                warn.addFileArg(snapshot.err);
                step.dependOn(&warn.step);
            }
        }
    }
}

fn cTest(b: *Build, command: *Build.Step, cliOptions: *const CliOptions, manifest: *const Manifest, buildOptions: *const BuildOptions, snapshotHelper: *Snapshot.Helper, prefixPath: []const u8, nativeCompSet: *Compilation, stripDebugInfo: ?bool, t: std.Target.Query, runner: ?[]const u8) !void {
    const rel = try fullBuild(b, nativeCompSet, cliOptions, manifest, buildOptions, .private, .ReleaseFast, stripDebugInfo, t);

    if (b.args) |args| {
        for (args) |arg| {
            if (matchArg(rel.comp.triple, arg)) {
                break;
            }
        } else {
            return;
        }
    }

    const name = b.fmt("{s}-ctest", .{rel.comp.triple});
    const dir = b.fmt("{s}/{s}-{s}/", .{ prefixPath, rel.comp.triple, optimizeModeName(.ReleaseFast) });

    const compile = b.addSystemCommand(&[_][]const u8{ "zig", "cc", "-target", rel.comp.triple });
    compile.addFileInput(b.path("tests/test.c"));
    compile.step.dependOn(&rel.step);

    compile.addArg("-o");
    const testBin = compile.addOutputFileArg(b.fmt("{s}{s}", .{ name, rel.comp.target.result.exeFileExt() }));

    compile.addArgs(&[_][]const u8{
        "-I", b.fmt("{s}include/", .{dir}),
        "./tests/test.c",
        "-L", dir,
        "-lrvm",
    });

    compile.expectStdErrEqual("");
    compile.expectStdOutEqual("");
    compile.expectExitCode(0);

    const runTest = Build.Step.Run.create(b, name);
    if (runner) |r| runTest.addArg(r);
    runTest.addFileArg(testBin);
    runTest.expectExitCode(0);

    const expectedOutput =
        if (buildOptions.forceNewSnapshot) null
        else snapshotHelper.get(name);

    if (expectedOutput) |expect| {
        const text = try expect.toText(b.allocator);
        runTest.expectStdOutEqual(text.out);
        runTest.expectStdErrEqual(text.err);

        command.dependOn(&runTest.step);
    } else {
        const snapshot = Snapshot.LazyPair{ .out = runTest.captureStdOut(), .err = runTest.captureStdErr() };
        try snapshotHelper.put(name, snapshot);

        const warn = b.addSystemCommand(&[_][]const u8{ "echo", b.fmt("manual validation required, new snapshots added; capturing output of test [{s}] to the following paths:\n", .{name}) });
        warn.addFileArg(snapshot.out);
        warn.addFileArg(snapshot.err);

        command.dependOn(&warn.step);
    }
}

fn optimizeModeName(optimize: std.builtin.OptimizeMode) []const u8 {
    return switch (optimize) {
        .Debug => "debug",
        .ReleaseSafe => "release-safe",
        .ReleaseFast => "release-fast",
        .ReleaseSmall => "release-small",
    };
}
