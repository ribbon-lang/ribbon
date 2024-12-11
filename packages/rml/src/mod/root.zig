const std = @import("std");
const zig_builtin = @import("builtin");

const MiscUtils = @import("Utils").Misc;
const TypeUtils = @import("Utils").Type;
const TextUtils = @import("Utils").Text;

pub const log = std.log.scoped(.rml);

const Rml = @This();

pub const TypeId = TypeUtils.TypeId;

pub const IOError = MiscUtils.IOError;
pub const SimpleHashContext = MiscUtils.SimpleHashContext;
pub const Ordering = MiscUtils.Ordering;
pub const compare = MiscUtils.compare;
pub const equal = MiscUtils.equal;
pub const hashWith = MiscUtils.hashWith;

pub const BUILTIN_NAMESPACES = .{
    .array = Rml.array.ObjectMemory,
    .block = Rml.block.Memory,
    .env = Rml.env.Memory,
    .interpreter = Rml.interpreter.Memory,
    .map = Rml.map.ObjectMemory,
    .parser = Rml.parser.Memory,
    .pattern = Rml.pattern.Memory,
    .procedure = Rml.procedure.Memory,
    .string = Rml.string.Memory,
    .symbol = Rml.symbol.Memory,
    .writer = Rml.writer.Memory,
};

pub const array = @import("array.zig");
pub const bindgen = @import("bindgen.zig");
pub const block = @import("block.zig");
pub const env = @import("env.zig");
pub const interpreter = @import("interpreter.zig");
pub const map = @import("map.zig");
pub const object = @import("object.zig");
pub const parser = @import("parser.zig");
pub const pattern = @import("pattern.zig");
pub const procedure = @import("procedure.zig");
pub const source = @import("source.zig");
pub const Storage = @import("Storage.zig");
pub const string = @import("string.zig");
pub const symbol = @import("symbol.zig");
pub const writer = @import("writer.zig");

pub const int = i64;
pub const float = f64;
pub const char = TextUtils.Char;
pub const str = []const u8;
pub const nil = extern struct {};
pub const Nil = Obj(nil);

pub const Result = interpreter.Result;
pub const EvalError = interpreter.EvalError;
pub const SyntaxError = parser.SyntaxError;
pub const OOM = error{OutOfMemory};
pub const MemoryLeak = error{MemoryLeak};
pub const Unexpected = error{Unexpected};
pub const SymbolAlreadyBound = env.SymbolAlreadyBound;
pub const Error = IOError || OOM || EvalError || SyntaxError || Unexpected;

pub const Bool = Obj(bool);
pub const Int = Obj(i64);
pub const Float = Obj(f64);
pub const Char = Obj(TextUtils.Char);
pub const Env = env.Env;
pub const Interpreter = interpreter.Interpreter;
pub const Parser = parser.Parser;
pub const Pattern = pattern.Pattern;
pub const Procedure = procedure.Procedure;
pub const Origin = source.Origin;
pub const Array = array.Array;
pub const ObjectArray = array.ObjectArray;
pub const Block = block.Block;
pub const Map = map.Map;
pub const ObjectMap = map.ObjectMap;
pub const String = string.String;
pub const Symbol = symbol.Symbol;
pub const Writer = writer.Writer;
pub const ptr = object.ptr;
pub const const_ptr = object.const_ptr;
pub const Obj = object.Obj;
pub const ObjData = object.ObjData;
pub const Object = object.Object;
pub const Header = object.Header;
pub const ref = object.ref;
pub const Wk = object.Wk;
pub const Weak = object.Weak;
pub const getObj = object.getObj;
pub const getHeader = object.getHeader;
pub const getTypeId = object.getTypeId;
pub const getRml = object.getRml;
pub const forceObj = object.forceObj;
pub const castObj = object.castObj;
pub const upgradeCast = object.upgradeCast;
pub const downgradeCast = object.downgradeCast;

test {
    std.testing.refAllDeclsRecursive(@This());
}


storage: Storage,
cwd: ?std.fs.Dir,
out: ?std.io.AnyWriter,
main_interpreter: Interpreter = undefined,


/// caller must close cwd and out
pub fn init(allocator: std.mem.Allocator, cwd: ?std.fs.Dir, out: ?std.io.AnyWriter, args: []const []const u8) OOM! *Rml {
    const self = try allocator.create(Rml);
    errdefer allocator.destroy(self);

    self.* = Rml {
        .storage = try Storage.init(allocator),
        .cwd = cwd,
        .out = out,
    };
    errdefer self.storage.deinit();

    self.storage.origin = try Origin.fromStr(self, "(system)");

    log.debug("initializing interpreter ...", .{});
    var envDeinit = false;
    const namespace_env = try Env.init(self, self.storage.origin);
    errdefer if (!envDeinit) namespace_env.deinit();

    bindgen.bindNamespaces(self, namespace_env, BUILTIN_NAMESPACES) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => @panic(@errorName(err)),
    };

    const main_env = try Env.init(self, self.storage.origin);
    errdefer if (!envDeinit) main_env.deinit();

    self.main_interpreter = interpreter: {
        if (Interpreter.init(self, self.storage.origin, .{namespace_env, main_env})) |x| {
            log.debug("... interpreter ready", .{});
            break :interpreter x;
        } else |err| {
            log.err("... failed to initialize interpreter", .{});
            return err;
        }
    };
    errdefer {
        envDeinit = true;
        self.main_interpreter.deinit();
    }

    // TODO args
    _ = args;

    return self;
}

pub fn deinit(self: *Rml) MemoryLeak! void {
    log.debug("deinitializing Rml", .{});

    self.main_interpreter.deinit();
    self.storage.deinit();

    defer self.storage.object.destroy(self);

    if (self.storage.object_count != 0) {
        log.err("memory management problem detected, object_count: {}", .{self.storage.object_count});
        return error.MemoryLeak;
    } else {
        log.debug("no memory management problem detected", .{});
    }
}

pub fn expectedOutput(self: *Rml, comptime fmt: []const u8, args: anytype) void {
    if (self.out) |out| {
        log.info(fmt, args);
        out.print(fmt ++ "\n", args) catch @panic("failed to write to host-provided out");
    }
}


// TODO run
pub fn runString(self: *Rml, fileName: []const u8, text: []const u8) Error! Object {
    log.info("running [{s}] ...", .{fileName});
    const result = try MiscUtils.todo(noreturn, .{self, text});
    log.info("... finished [{s}], result: {}", .{ fileName, result });

    return result;
}

pub fn runFile(self: *Rml, fileName: []const u8) Error! Object {
    const src = try self.readFile(fileName);
    defer self.storage.object.free(src);

    return self.runString(fileName, src);
}

pub fn readFile(self: *Rml, fileName: []const u8) Error! []const u8 {
    log.info("reading [{s}] ...", .{fileName});
    return if (self.storage.read_file_callback) |cb| try cb(self, fileName)
        else error.AccessDenied;
}

pub fn errorCast(err: anyerror) Error {
    if (TypeUtils.narrowErrorSet(Error, err)) |e| {
        return e;
    } else {
        log.err("unexpected error in errorCast: {s}", .{@errorName(err)});
        return error.Unexpected;
    }
}
