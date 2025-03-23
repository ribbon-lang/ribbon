const std = @import("std");
const Build = std.Build;

const log = std.log.scoped(.@"build.zig");

pub const std_options = std.Options {
    .log_level = .warn,
};

const Fingerprint = @import("src/mod/common/Fingerprint.zig");

const Os = enum(u8) { generic_posix, windows, linux, macos, wasi, freestanding };
const Arch = enum(u8) { x86_64, aarch64, wasm64 };
const Mode = enum(u8) { debug, release };
const Target = packed struct {
    os: Os,
    arch: Arch,
    mode: Mode,

    fn toZigTarget(self: Target, b: *Build) Build.ResolvedTarget {
        return b.resolveTargetQuery(.{
            .os_tag = switch (self.os) {
                .generic_posix => null,
                .windows => .windows,
                .linux => .linux,
                .macos => .macos,
                .wasi => .wasi,
                .freestanding => .freestanding,
            },
            .cpu_arch = switch (self.arch) {
                .x86_64 => .x86_64,
                .aarch64 => .aarch64,
                .wasm64 => .wasm64,
            },
        });
    }

    fn toZigOptimize(self: Target) std.builtin.OptimizeMode {
        switch (self.mode) {
            .debug => return .Debug,
            .release => return .ReleaseFast,
        }
    }

    fn fromZigTargetAndMode(target: std.Target, mode: std.builtin.OptimizeMode) Target {
        return Target {
            .arch = switch (target.cpu.arch) {
                .x86_64 => .x86_64,
                .aarch64 => .aarch64,
                .wasm64 => .wasm64,
                else => exit("Ribbon does not support {s}", .{@tagName(target.cpu.arch)}),
            },
            .os = switch (target.os.tag) {
                // TODO: support some of the other operating systems zig enumerates
                // maybe some can be supported by translating to variants already here?
                .windows => .windows,
                .linux => .linux,
                .macos => .macos,
                .wasi => .wasi,
                .freestanding => .freestanding,
                else => other: {
                    warn("Ribbon does not officially support {s}", .{@tagName(target.os.tag)});
                    break :other .generic_posix;
                },
            },
            .mode = switch (mode) {
                .Debug => .debug,
                .ReleaseFast => .release,
                .ReleaseSmall => small: {
                    log.warn("Ribbon does not currently support --release=small; using --release=fast instead.", .{});
                    break :small .release;
                },
                .ReleaseSafe => safe: {
                    log.warn("Ribbon does not currently support --release=safe; using debug build instead.", .{});
                    break :safe .debug;
                },
            },
        };
    }
};



const ExternalReferenceKind = enum { module, artifact };

const KnownExternalReference = struct {
    package: []const u8,
    name: ?[]const u8 = null,
};

const ExternalReference = struct {
    package: []const u8,
    name: ?[]const u8 = null,
    kind: ExternalReferenceKind = .module,
};

const Path = union(enum) {
    static: []const u8,
    generated: ?Build.LazyPath,
};

const Reference = union(enum) {
    path: Path,
    external_data: ExternalReference,
    build_data: []const u8,

    fn staticFile(static: []const u8) Reference {
        return Reference{ .path = Path{ .static = static } };
    }

    const generated = Reference { .path = Path{ .generated = null } };

    fn generatedFile(gen: Build.LazyPath) Reference {
        return Reference{ .path = Path{ .generated = gen } };
    }

    fn external(package: []const u8, name: ?[]const u8, kind: ExternalReferenceKind) Reference {
        return Reference{ .external_data = ExternalReference{ .package = package, .name = name, .kind = kind } };
    }

    fn internal(data: []const u8) Reference {
        return Reference{ .build_data = data };
    }
};

const target_entry_types = struct {
    dependency: *Build.Dependency,
    module: *Build.Module,
    binary: *Build.Step.Compile,
    file: Build.LazyPath,
    task: *Build.Step.Run,
};

const config_entry_types = struct {
    dependency: Config.Dependency,
    module: Config.Module,
    binary: Config.Binary,
    file: Config.File,
    task: Config.Task,
};

const TargetTable = struct {
    dependency: std.StringHashMap(*Build.Dependency),
    module: std.StringHashMap(*Build.Module),
    binary: std.StringHashMap(*Build.Step.Compile),
    file: std.StringHashMap(Build.LazyPath),
    task: std.StringHashMap(*Build.Step.Run),

    fn init(allocator: std.mem.Allocator) TargetTable {
        return TargetTable{ .dependency = .init(allocator), .module = .init(allocator), .binary = .init(allocator), .file = .init(allocator), .task = .init(allocator) };
    }
};

const ConfigTable = struct {
    dependency: std.StringHashMap(Config.Dependency),
    module: std.StringHashMap(Config.Module),
    binary: std.StringHashMap(Config.Binary),
    file: std.StringHashMap(Config.File),
    task: std.StringHashMap(Config.Task),

    fn init(allocator: std.mem.Allocator) ConfigTable {
        return ConfigTable{ .dependency = .init(allocator), .module = .init(allocator), .binary = .init(allocator), .file = .init(allocator), .task = .init(allocator) };
    }
};

const Builder = struct {
    build: *Build,
    host: Target,
    dest: Target,
    config: ConfigTable,
    target: TargetTable,

    fn lookupConfig(self: *Builder, comptime kind: std.meta.FieldEnum(config_entry_types), name: []const u8) @FieldType(config_entry_types, @tagName(kind)) {
        const map = @field(self.config, @tagName(kind));
        return map.get(name) orelse exit("Cannot find {s} entry for `{s}`", .{@typeName(@FieldType(config_entry_types, @tagName(kind))), name});
    }

    fn init(b: *Build) *Builder {
        const zon = parseZon(b, struct { version: []const u8 });

        const target = b.standardTargetOptions(.{});
        const optimize = b.standardOptimizeOption(.{});

        var version = std.SemanticVersion.parse(zon.version) catch {
            exit("Cannot parse semantic version in build.zig.zon", .{});
        };

        log.info("Ribbon version: {}", .{version});

        if (version.build != null) {
            exit("Build metadata is not allowed in the version field of build.zig.zon; this is generated by the build system", .{});
        }

        const fingerprint = Fingerprint.init("ribbon-lang.zig-api");

        log.info("Build fingerprint: {}", .{fingerprint.value});

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

        const self = b.allocator.create(Builder) catch @panic("OOM");

        self.* = Builder {
            .build = b,
            .host = Target.fromZigTargetAndMode(b.graph.host.result, .Debug),
            .dest = Target.fromZigTargetAndMode(target.result, optimize),
            .config = .init(b.allocator),
            .target = .init(b.allocator),
        };

        return self;
    }

    fn loadConfig(self: *Builder, config: Config) void {
        inline for (comptime std.meta.fieldNames(config_entry_types)) |fieldName| {
            const T: type = comptime @FieldType(config_entry_types, fieldName);

            const inputs: []const T = @field(config, fieldName);
            const output: *std.StringHashMap(T) = &@field(self.config, fieldName);

            for (inputs) |input| {
                const name = switch (T) {
                    Config.Binary => switch (input) {
                        .result_bin => |x| x.name,
                        .custom_tool => |x| x.name,
                        .system_tool => |x| x,
                        .extern_tool => |x| x.package,
                    },
                    else => input.name,
                };

                if (name.len == 0) {
                    exit("{s} entries passed to loadConfig must have a non-empty name", .{@typeName(T)});
                }

                log.info("Loading {s} entry for `{s}`", .{@typeName(T), name});

                const entry = output.getOrPut(name) catch @panic("OOM");

                if (entry.found_existing) {
                    warn("[{s}]: overwriting entry for {s}\n", .{@typeName(T), name});
                }

                entry.value_ptr.* = input;
            }
        }

        log.info("Successfully loaded configs", .{});
    }
};

fn exit(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt, args);
    std.process.exit(1);
}

fn warn(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("Warning" ++ fmt, args);
}



const Config = struct {
    dependency: []const Dependency = &.{},
    module: []const Module = &.{},
    binary: []const Binary = &.{},
    file: []const File = &.{},
    task: []const Task = &.{},

    const Dependency = struct {
        name: []const u8,
        zon_name: ?[]const u8 = null,
        valid_arch: ?[]const Arch = null,
        fetch: union(enum) {
            standard: void,
            lazy: void,
            override: *const fn (*Builder) anyerror!void,
        } = .standard,
    };

    const Module = struct {
        name: []const u8,
        source: Reference,
        imports: []const Reference = &.{},
        embeds: []const Reference = &.{},
        valid_arch: ?[]const Arch = null,
    };

    const Binary = union(enum) {
        result_bin: InternalBinary,
        custom_tool: InternalBinary,
        system_tool: []const u8,
        extern_tool: KnownExternalReference,

        fn output(name: []const u8, root: ?Reference) Binary {
            return Binary{ .result_bin = InternalBinary{ .name = name, .root = root } };
        }

        fn tool(name: []const u8, root: ?Reference) Binary {
            return Binary{ .custom_tool = InternalBinary{ .name = name, .root = root } };
        }

        fn command(name: []const u8) Binary {
            return Binary{ .system_tool = name };
        }

        fn external(package: []const u8, name: ?[]const u8) Binary {
            return Binary{ .extern_tool = KnownExternalReference{ .package = package, .name = name } };
        }
    };

    const InternalBinary = struct {
        name: []const u8,
        root: ?Reference = null,
        linkage: std.builtin.LinkMode = .static,
        use_llvm: bool = false,
        use_lld: bool = false,
        valid_arch: ?[]const Arch = null,
        force_mode: ?Mode = null,
    };

    const File = struct {
        name: []const u8,
        source: Reference,

        fn generated(name: []const u8) File {
            return File{ .name = name, .source = .generated };
        }

        fn static(name: ?[]const u8, source: []const u8) File {
            const n = name orelse std.fs.path.basename(source);
            if (n.len == 0) exit("File name for source [{s}] cannot be empty", .{source});
            return File{ .name = n, .source = .staticFile(source) };
        }
    };

    const Task = struct {
        name: []const u8,
        main: Reference,
        args: TaskArgs,
        indirect_dependencies: []const Reference = &.{},
    };

    const TaskArgs = union(enum) {
        pass: void,
        static_set: []const TaskArg,
        uses_handler: struct {
            inputs: []const Reference = &.{},
            output: ?Reference = null,
            handler: *const fn (*Builder, *const Config.Task, *Build.Step.Run) ?Build.LazyPath,
        },

        fn static(args: []const TaskArg) TaskArgs {
            return TaskArgs{ .static_set = args };
        }

        fn custom(inputs: []const Reference, output: ?Reference, handler: *const fn (*Builder, *const Config.Task, *Build.Step.Run) ?Build.LazyPath) TaskArgs {
            return TaskArgs{ .uses_handler = .{ .inputs = inputs, .output = output, .handler = handler } };
        }
    };

    const TaskArg = union(enum) {
        standard: []const u8,
        input_ref: Reference,
        output_ref: Reference,

        fn text(arg: []const u8) TaskArg {
            return TaskArg{ .standard = arg };
        }

        fn input(ref: Reference) TaskArg {
            return TaskArg{ .input_ref = ref };
        }

        fn output(ref: Reference) TaskArg {
            return TaskArg{ .output_ref = ref };
        }
    };

    const Step = union(enum) {
        install: struct {
            outputs: []const Reference,
            folder: ?[]const u8 = null,
        },
        run: struct {
            tasks: []const Reference,
        },
    };
};

pub fn build(b: *Build) !void {
    var builder = Builder.init(b);

    builder.loadConfig(.{
        .dependency = &.{
            .{
                .name = "assembler",
                .zon_name = "X64EZ",
                .valid_arch = &.{ .x86_64 },
                .fetch = .lazy,
            },
            .{
                .name = "nasm",
                .valid_arch = &.{ .x86_64 },
                .fetch = .lazy,
            },
        },
        .module = &.{
            .{
                .name = "abi",
                .source = .staticFile("src/mod/x64/abi.zig"),
                .imports = &.{ .external("assembler", null, .module), .internal("platform") },
            },
            .{
                .name = "Buffer",
                .source = .staticFile("src/mod/common/Buffer.zig"),
                .imports = &.{ .internal("platform") },
            },
            .{
                .name = "bytecode",
                .source = .staticFile("src/mod/bytecode.zig"),
                .imports = &.{ .internal("platform"), .internal("core"), .internal("Instruction"), .internal("Id"), .internal("Interner"), .internal("VirtualWriter") },
            },
            .{
                .name = "common",
                .source = .staticFile("src/mod/common.zig"),
                .imports = &.{ .internal("Formatter"), .internal("Id"), .internal("Interner"), .internal("Stack"), .internal("VirtualWriter") },
            },
            .{
                .name = "core",
                .source = .staticFile("src/mod/core.zig"),
                .imports = &.{ .internal("platform"), .internal("Id"), .internal("Buffer"), .internal("Stack") },
            },
            .{
                .name = "Fingerprint",
                .source = .staticFile("src/mod/common/Fingerprint.zig"),
            },
            .{
                .name = "Formatter",
                .source = .staticFile("src/mod/common/Formatter.zig"),
                .imports = &.{ .internal("platform") },
            },
            .{
                .name = "gen",
                .source = .staticFile("src/bin/tools/gen.zig"),
                .imports = &.{ .internal("platform"), .internal("isa"), .internal("core"), .external("assembler", null, .module), .internal("abi") },
                .embeds = &.{ .internal("Isa_intro.md"), .internal("entry_points.asm"), .internal("instructions.asm"), .internal("Instruction_intro.zig") },
            },
            .{
                .name = "Id",
                .source = .staticFile("src/mod/common/Id.zig"),
                .imports = &.{ .internal("platform") },
            },
            .{
                // generated by gen tool
                .name = "Instruction",
                .source = .generated,
                .imports = &.{ .internal("platform"), .internal("core"), .internal("Id") },
            },
            .{
                .name = "Interner",
                .source = .staticFile("src/mod/common/Interner.zig"),
                .imports = &.{ .internal("platform") },
            },
            .{
                .name = "interpreter",
                .source = .staticFile("src/mod/interpreter.zig"),
                .imports = &.{ .internal("platform"), .internal("core") },
            },
            .{
                .name = "ir",
                .source = .staticFile("src/mod/ir.zig"),
                .imports = &.{ .internal("platform"), .internal("Interner"), .internal("Id") },
            },
            .{
                .name = "isa",
                .source = .staticFile("src/gen-base/zig/isa.zig"),
                .imports = &.{ .internal("platform") },
            },
            .{
                .name = "machine",
                .source = .staticFile("src/mod/x64/machine.zig"),
                .imports = &.{ .internal("platform"), .internal("core"), .internal("abi"), .internal("assembler"), .internal("VirtualWriter") },
            },
            .{
                .name = "main",
                .source = .staticFile("src/bin/main.zig"),
            },
            .{
                .name = "meta_language",
                .source = .staticFile("src/mod/meta_language.zig"),
                .imports = &.{ .internal("platform") },
            },
            .{
                .name = "platform",
                .source = .staticFile("src/mod/platform.zig"),
                .imports = &.{ .internal("Fingerprint") },
            },
            .{
                .name = "ribbon",
                .source = .staticFile("src/mod/root.zig"),
                .imports = &.{ .internal("abi"), .internal("platform"), .internal("Buffer"), .internal("bytecode"), .internal("common"), .internal("core"), .internal("interpreter"), .internal("ir"), .internal("meta_language") },
            },
            .{
                .name = "Stack",
                .source = .staticFile("src/mod/common/Stack.zig"),
                .imports = &.{ .internal("platform") },
            },
            .{
                .name = "VirtualWriter",
                .source = .staticFile("src/mod/common/VirtualWriter.zig"),
                .imports = &.{ .internal("platform") },
            },
        },
        .binary = &.{
            .output("ribbon", .internal("main")),
            .tool("gen", .internal("gen")),
            .external("nasm", null),
        },
        .file = &.{
            .static(null, "src/gen-base/markdown/Isa_intro.md"),
            .static(null, "src/gen-base/x64/entry_points.asm"),
            .static(null, "src/gen-base/x64/instructions.asm"),
            .static(null, "src/gen-base/zig/Instruction_intro.zig"),
            // generated by gen tool
            .generated("Instruction.zig"),
            .generated("interpreter.asm"),
            .generated("ribbon.h.asm"),
            .generated("interpreter.template.asm"),
            .generated("Isa.md"),
            .generated("Interpreter.o"),
        },
        .task = &.{
            .{
                .name = "gen-types",
                .main = .internal("gen"),
                .args = .static(&.{ .text("types"), .output(.internal("Instruction.zig")) }),
            },
            .{
                .name = "gen-asm",
                .main = .internal("gen"),
                .args = .static(&.{ .text("assembly"), .output(.internal("interpreter.asm")) }),
            },
            .{
                .name = "gen-asm-header",
                .main = .internal("gen"),
                .args = .static(&.{ .text("assembly-header"), .output(.internal("ribbon.h.asm")) }),
            },
            .{
                .name = "gen-template",
                .main = .internal("gen"),
                .args = .static(&.{ .text("assembly-template"), .output(.internal("interpreter.template.asm")) }),
            },
            .{
                .name = "gen-isa",
                .main = .internal("gen"),
                .args = .static(&.{ .text("markdown"), .output(.internal("Isa.md")) }),
            },
            .{
                .name = "run-main",
                .main = .internal("main"),
                .args = .pass,
            },
            .{
                .name = "run-nasm",
                .main = .external("nasm", null, .artifact),
                .args = .custom(
                    &.{.internal("interpreter.asm")},
                    .internal("Interpreter.o"),
                    &struct {
                        pub fn nasm_handler(self: *Builder, _: *const Config.Task, run: *Build.Step.Run) ?Build.LazyPath {
                            const zig_fmt = self.dest.toZigTarget(self.build).result.ofmt;
                            const nasm_fmt = switch (zig_fmt) {
                                // See https://nasm.us/doc/nasmdoc8.html;
                                // when eventually supporting for apple on arm, we will need to use a different assembler,
                                // additionally, supporting old apple x86_64 is not a priority.
                                // so these are all the formats we need to support translation to nasm for;
                                // coff for windows, elf for linux

                                .coff => "coff",
                                .elf => "elf64",

                                else => exit("Object format `{s}` is not supported by Ribbon", .{@tagName(zig_fmt)}),
                            };

                            run.addArgs(&.{ "-f", nasm_fmt });

                            if (self.dest.mode == .debug) {
                                run.addArgs(&.{ "-D DBG", "-g" });

                                switch (self.dest.os) {
                                    .windows => run.addArgs(&.{ "-F", "cv8" }),
                                    else => run.addArgs(&.{ "-F", "dwarf" }),
                                }
                            }

                            run.addArg("-o");

                            return run.addOutputFileArg("Interpreter.o");
                        }
                    }.nasm_handler,
                ),
            },
        },
    });
}



fn parseZon(b: *Build, comptime T: type) T {
    const zonText = std.fs.cwd().readFileAllocOptions(b.allocator, "build.zig.zon", std.math.maxInt(usize), 2048, 1, 0)
        catch exit("Unable to read build.zig.zon", .{});

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
