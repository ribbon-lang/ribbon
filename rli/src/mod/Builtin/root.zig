const std = @import("std");

const TypeUtils = @import("Utils").Type;

const Rli = @import("../root.zig");
const SExpr = Rli.SExpr;
const Source = Rli.Source;
const Interpreter = Rli.Interpreter;

const log = std.log.scoped(.rli);

const MetaModule = @This();

pub const Envs = GenEnvs;

pub const AllEnvs: EnvSet = allEnvs: {
    var set: EnvSet = undefined;
    for (EnvNames) |envName| {
        @field(set, envName) = true;
    }
    break :allEnvs set;
};

const GenEnvs = struct {
    pub const alist = @import("alist.zig");
    pub const arithmetic = @import("arithmetic.zig");
    pub const attr = @import("attr.zig");
    pub const binding = @import("binding.zig");
    pub const control = @import("control.zig");
    pub const conversion = @import("conversion.zig");
    pub const effect = @import("effect.zig");
    pub const env = @import("env.zig");
    pub const io = @import("io.zig");
    pub const list = @import("list.zig");
    pub const logical = @import("logical.zig");
    pub const meta = @import("meta.zig");
    pub const pair = @import("pair.zig");
    pub const parser = @import("parser.zig");
    pub const pattern = @import("pattern.zig");
    pub const procedure = @import("procedure.zig");
    pub const string = @import("string.zig");
    pub const symbol = @import("symbol.zig");
    pub const text = @import("text.zig");
    pub const @"type" = @import("type.zig");
};

pub const Scripts = struct {
    pub const module = @embedFile("module.bb");
};

pub const EnvSet = envSet: {
    var set = [1]std.builtin.Type.StructField{undefined} ** EnvNames.len;
    for (EnvNames, 0..) |envName, i| {
        set[i] = std.builtin.Type.StructField{ .name = envName, .type = bool, .alignment = 0, .is_comptime = false, .default_value = @ptrCast(&false) };
    }
    break :envSet @Type(.{ .@"struct" = std.builtin.Type.Struct{
        .fields = &set,
        .layout = .@"packed",
        .backing_integer = std.meta.Int(.unsigned, EnvNames.len),
        .decls = &.{},
        .is_tuple = false,
    } });
};

pub const EnvIterator = struct {
    set: EnvSet,
    index: usize = 0,

    pub fn from(envSet: EnvSet) EnvIterator {
        return EnvIterator{ .set = envSet };
    }

    pub fn reset(self: *EnvIterator) void {
        self.index = 0;
    }

    pub fn next(self: *EnvIterator) ?EnvName {
        if (self.index >= EnvNames.len) {
            return null;
        }

        inline for (EnvNames, 0..) |name, i| {
            if (i >= self.index) {
                if (@field(self.set, EnvNames[i])) {
                    self.index = i + 1;
                    return @field(EnvName, name);
                }
            }
        } else {
            self.index = std.math.maxInt(usize);
            return null;
        }
    }
};

pub const EnvNameTagType = u8;
pub const MAX_ENVS = std.math.maxInt(EnvNameTagType);
pub const MAX_DECLS = 10_000;

pub const EnvNames = std.meta.fieldNames(EnvName);

pub const EnvName = envName: {
    var envIndex: comptime_int = 0;
    var envFields = [1]std.builtin.Type.EnumField{undefined} ** MAX_ENVS;

    for (@typeInfo(GenEnvs).@"struct".decls) |decl| {
        const envName = decl.name;
        envFields[envIndex] = std.builtin.Type.EnumField{ .name = envName, .value = envIndex };
        envIndex += 1;
    }

    break :envName @Type(std.builtin.Type{ .@"enum" = .{
        .tag_type = EnvNameTagType,
        .fields = envFields[0..envIndex],
        .decls = &[0]std.builtin.Type.Declaration{},
        .is_exhaustive = true,
    } });
};


fn alistValue(at: *const Source.Attr, symbol: []const u8, itemData: anytype) !SExpr {
    const ItemT = @TypeOf(itemData);
    switch (@typeInfo(ItemT)) {
        .@"type" => {
            const T = itemData;
            if (std.meta.hasFn(T, "init")) {
                return try T.init(at);
            } else if (std.meta.hasFn(T, "fun")) {
                return try SExpr.Builtin(at, symbol, T.fun);
            }
        },
        .@"fn" => |fun| {
            switch (fun.params.len) {
                1 => return try itemData(at),
                3 => return try SExpr.Builtin(at, symbol, itemData),
                else => {},
            }
        },
        else => if (ItemT == SExpr) {
            return itemData;
        },
    }
    @compileLog("unsupported value", itemData);
    @compileError("unsupported value type in alistBuilder");
}



fn alistHelper(comptime E: type, comptime T: type, at: *const Source.Attr, list: anytype, tail: T, ctx: anytype, comptime callback: fn (@TypeOf(ctx), *const Source.Attr, SExpr, SExpr, T) E!T) (E || Interpreter.Result)!T {
    var frame = tail;

    inline for (list) |item| {
        const valueIndex = comptime if (item.len == 2) 1 else 2;
        if (comptime TypeUtils.isString(@TypeOf(item[0]))) {
            const symbol = try SExpr.Symbol(at, item[0]);
            const value = try alistValue(at, symbol.forceSymbolSlice(), item[valueIndex]);

            frame = try callback(ctx, at, symbol, value, frame);
        } else if (comptime TypeUtils.isTuple(@TypeOf(item[0]))) {
            const primaryName = item[0][0];
            const value = try alistValue(at, primaryName, item[valueIndex]);

            inline for (std.meta.fields(@TypeOf(item[0]))) |nameField| {
                const nameItem = @field(item[0], nameField.name);
                const symbol = try SExpr.Symbol(at, nameItem);

                frame = try callback(ctx, at, symbol, value, frame);
            }
        } else {
            @compileLog("unsupported key type", item[0]);
            @compileError("unsupported key type in alistBuilder");
        }
    }

    return frame;
}

fn alistBuilder(attr: *const Source.Attr, list: anytype) !SExpr {
    return alistHelper(SExpr, attr, list, try SExpr.Nil(attr), {}, struct {
        fn fun (_: void, at: *const Source.Attr, symbol: SExpr, value: SExpr, frame: SExpr) !SExpr {
            return SExpr.Cons(at, try SExpr.Cons(at, symbol, value), frame);
        }
    }.fun);
}

pub fn bindEnvs(at: *const Source.Attr, outputEnv: SExpr, builtinEnvs: EnvSet) !void {
    log.info("initializing builtin environments ...", .{});
    var envIterator = EnvIterator.from(builtinEnvs);
    while (envIterator.next()) |env| {
        bindBuiltinEnv(at, outputEnv, env) catch |err| {
            log.err("... failed to initialize builtin environment {s}", .{@tagName(env)});
            return err;
        };
        log.debug("... builtin environment {s} loaded", .{@tagName(env)});
    }
    log.info("... builtin environments loaded", .{});
}

pub fn bindScripts(comptime E: type, ctx: anytype, runFile: fn (@TypeOf(ctx), scriptName: []const u8, scriptContent: []const u8) E!SExpr) (E || Interpreter.Result)!void {
    inline for (comptime std.meta.declarations(Scripts)) |scriptDecl| {
        const scriptName = scriptDecl.name;
        log.info("running builtin script [{s}] ...", .{scriptName});
        const script = @field(Scripts, scriptName);
        const result = runFile(ctx, scriptName, script) catch |err| {
            log.err("... failed to bind built-in script [{s}]", .{scriptName});
            return err;
        };
        log.info("... finished builtin script [{s}], result:\n{}", .{ scriptName, result });
    }
}

fn bindBuiltinEnv(at: *const Source.Attr, outputEnv: SExpr, builtinEnv: EnvName) !void {
    inline for (comptime std.meta.fieldNames(EnvName)) |builtinName| {
        if (@field(EnvName, builtinName) == builtinEnv) {
            return try bindCustomEnv(at, outputEnv, @field(Envs, builtinName).Decls);
        }
    }
}

pub fn bindCustomEnv(attr: *const Source.Attr, outputEnv: SExpr, customEnv: anytype) !void {
    try alistHelper(Interpreter.Error, void, attr, customEnv, {}, outputEnv, struct {
        fn fun (env: SExpr, at: *const Source.Attr, symbol: SExpr, value: SExpr, _: void) !void {
            return Interpreter.extendEnvFrame(at, symbol, value, env);
        }
    }.fun);
}

/// equivalent to bindCustomEnv + bindBuiltinEnvs + bindScripts + modularizeEnv in the default environment
pub fn bind(comptime E: type, interpreter: *Interpreter, ctx: anytype, runFile: fn (@TypeOf(ctx), scriptName: []const u8, scriptContent: []const u8) E!SExpr, builtinEnvs: EnvSet, customEnv: anytype) (E || Interpreter.Result)!void {
    log.info("binding custom environment ...", .{});
    bindCustomEnv(interpreter.context.attr, interpreter.env, customEnv) catch |err| {
        log.err("... failed to bind custom environment", .{});
        return err;
    };
    log.info("... custom environment bound", .{});

    log.info("binding builtin environments ...", .{});
    bindEnvs(interpreter.context.attr, interpreter.env, builtinEnvs) catch |err| {
        log.err("... failed to bind builtin environments", .{});
        return err;
    };
    log.info("... builtin environments bound", .{});

    log.info("binding builtin scripts ...", .{});
    bindScripts(E, ctx, runFile) catch |err| {
        log.err("... failed to bind builtin scripts", .{});
        return err;
    };
    log.info("... builtin scripts bound", .{});

    log.info("modularizing environments ...", .{});
    interpreter.env = modularizeEnv(interpreter.context.attr, interpreter.env) catch |err| {
        log.err("... failed to modularize environment", .{});
        return err;
    };
    log.debug("... environment modularized", .{});
}

// TODO: handle additional script modularization besides the module script?
pub fn modularizeEnv(attr: *const Source.Attr, envSource: SExpr) !SExpr {
    @setEvalBranchQuota(2_000);

    log.info("modularizing environment", .{});

    const envDestination = envDest: {
        const nil = try SExpr.Nil(attr);
        break :envDest try SExpr.Cons(attr, nil, nil);
    };

    log.info("created destination environment", .{});

    const starModulesSym = try SExpr.Symbol(attr, "*modules*");
    const moduleSym = try SExpr.Symbol(attr, "module");
    const importSym = try SExpr.Symbol(attr, "import");

    log.info("created symbols", .{});

    const modulesPair: SExpr =
        if (try Interpreter.envLookupPair(starModulesSym, envSource))
            |x| if (x.isCons()) x else return error.NoModuleSystem
        else return error.NoModuleSystem;

    log.info("found modules pair", .{});

    const modules = &modulesPair.forceCons().cdr;

    const NameSet = struct {primary: []const u8, secondary: []const []const u8};

    inline for (EnvNames) |envName| {
        const builtinEnv = @field(Envs, envName);

        var globalNames = [1]NameSet{ undefined } ** builtinEnv.Decls.len;
        var exportNames = [1]NameSet{ undefined } ** builtinEnv.Decls.len;

        var globalCount: usize = 0;
        var exportCount: usize = 0;
        inline for (builtinEnv.Decls) |item| {
            const nameSet =
                if (comptime TypeUtils.isString(@TypeOf(item[0]))) single: {
                    const primary = item[0];
                    break :single NameSet { .primary = primary, .secondary = &.{} };
                } else if (comptime TypeUtils.isTuple(@TypeOf(item[0]))) set: {
                    var items = [1][]const u8 {undefined} ** item[0].len;
                    inline for (item[0], 0..) |name, i| items[i] = name;
                    const secondary = items[0..];
                    break :set NameSet { .primary = item[0][0], .secondary = secondary };
                } else {
                    @compileLog("unsupported key type", item[0]);
                    @compileError("unsupported key type in alistBuilder");
                };

            if (nameSet.primary.len <= envName.len
            or !std.mem.startsWith(u8, nameSet.primary, envName)
            or nameSet.primary[envName.len] != '/') {
                globalNames[globalCount] = nameSet;
                globalCount += 1;
            } else if (nameSet.primary.len > envName.len) {
                if (try Interpreter.envLookup(try SExpr.Symbol(attr, nameSet.primary), envSource)) |_| {
                    exportNames[exportCount] = nameSet;
                    exportCount += 1;
                }
            }
        }

        log.info("extracted names from environment, globals {}, exports {}", .{ globalCount, exportCount });

        if (exportCount > 0) {
            var exportPairs = [1]SExpr {undefined} ** builtinEnv.Decls.len;

            for (exportNames[0..exportCount], 0..) |exportNameSet, i| {
                const exportSymbol = try SExpr.Symbol(attr, exportNameSet.primary[envName.len + 1..]);
                const localSymbol = try SExpr.Symbol(attr, exportNameSet.primary);
                exportPairs[i] = try SExpr.Cons(attr, localSymbol, exportSymbol);

                for (exportNameSet.secondary) |secondaryName| {
                    const symbol = try SExpr.Symbol(attr, secondaryName);
                    if (try Interpreter.envLookup(symbol, envSource)) |value| {
                        try Interpreter.extendEnvFrame(attr, symbol, value, envDestination);
                    }
                }
            }

            log.info("created export pairs and extended global env with secondaries as globals", .{});

            const newModule = try SExpr.List(attr, &.{
                try SExpr.Symbol(attr, envName),
                    try SExpr.Cons(attr,
                        try SExpr.Symbol(attr, "env"),
                        envSource,
                    ),
                    try SExpr.Cons(attr,
                        try SExpr.Symbol(attr, "exports"),
                        try SExpr.List(attr, exportPairs[0..exportCount]),
                    ),
            });

            modules.* = try SExpr.Cons(attr, newModule, modules.*);
        }

        log.info("created new module and added to modules list", .{});

        for (globalNames[0..globalCount]) |gNameSet| {
            const symbol = try SExpr.Symbol(attr, gNameSet.primary);
            if (try Interpreter.envLookup(symbol, envSource)) |value| {
                try Interpreter.extendEnvFrame(attr, symbol, value, envDestination);
            }

            for (gNameSet.secondary) |secondaryName| {
                    const secondarySymbol = try SExpr.Symbol(attr, secondaryName);
                    if (try Interpreter.envLookup(secondarySymbol, envSource)) |value| {
                    try Interpreter.extendEnvFrame(attr, secondarySymbol, value, envDestination);
                }
            }
        }

        log.info("extended global env with globals, finished env {s}", .{envName});
    }

    const moduleMacro: SExpr =
        try Interpreter.envLookup(moduleSym, envSource)
        orelse return error.NoModuleSystem;

    const importMacro: SExpr =
        try Interpreter.envLookup(importSym, envSource)
        orelse return error.NoModuleSystem;

    log.info("found module and import macros", .{});

    try Interpreter.extendEnvFrame(attr, moduleSym, moduleMacro, envDestination);
    try Interpreter.extendEnvFrame(attr, importSym, importMacro, envDestination);

    log.info("extended destination env with module and import macros", .{});

    return envDestination;
}
