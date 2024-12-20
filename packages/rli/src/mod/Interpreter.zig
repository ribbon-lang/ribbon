const std = @import("std");

const MiscUtils = @import("Utils").Misc;
const TextUtils = @import("Utils").Text;
const TypeUtils = @import("Utils").Type;
const Config = @import("Config");

const Rli = @import("root.zig");
const Builtin = Rli.Builtin;
const SExpr = Rli.SExpr;
const Context = Rli.Context;
const Parser = Rli.Parser;
const Source = Rli.Source;

const log = Rli.log;


cwd: std.fs.Dir,
context: *Context,
errorStack: ?std.ArrayList(*const Source.Attr),
errorCause: ?[]const u8,
attr: ?*const Source.Attr,
env: SExpr,
callerEnv: SExpr,
evidence: SExpr,
globalEvidence: SExpr,
callStack: std.ArrayList(*const Source.Attr),
terminationData: ?TerminationData = null,

const TerminationData = struct {
    ctxId: SExpr,
    value: SExpr,
};

const Interpreter = @This();

pub const Result = Signal || Error;
pub const Signal = error{Terminate};
pub const Error = TextUtils.Error || Context.Error || EvaluationError || Parser.SyntaxError;
pub const EvaluationError = error{
    Panic,
    NotEvaluatable,
    NotCallable,
    TypeError,
    RangeError,
    NotEnoughArguments,
    TooManyArguments,
    DivisionByZero,
    UnboundSymbol,
    InvalidContext,
    EnvironmentUnderflow,
    CallStackOverflow,
    MissingDynamic,
    UnexpectedTerminate,
    MissingTerminationData,
    NoModuleSystem,
};

pub fn readerCall(interpreter: *Interpreter, parser: *Parser, readerName: SExpr, start: Source.Pos, comments: []const Source.Comment) (Error || Parser.SyntaxError)!?SExpr {
    const at = readerName.getAttr();

    var out: NativeWithOut = undefined;
    const body = try SExpr.List(at, &.{
        try SExpr.List(at, &.{
            readerName,
            try SExpr.Quote(try parser.toSExpr(at)),
            try SExpr.Quote(try SExpr.from(at, start)),
            try SExpr.Quote(try SExpr.from(at, comments)),
        })
    });

    interpreter.nativeWith(readerName.getAttr(), body, &out, struct {
        pub fn exception (e: *Interpreter, a: *const Source.Attr, args: SExpr) Result!SExpr {
            const eArgs = try e.expectAtLeastN(1, args);
            return invoke(e, a, eArgs.head[0], eArgs.tail);
        }

        pub fn fail (e: *Interpreter, a: *const Source.Attr, args: SExpr) Result!SExpr {
            const eArgs = try e.expectAtLeastN(1, args);
            return invoke(e, a, eArgs.head[0], eArgs.tail);
        }
    }) catch |res| {
        if (res == Signal.Terminate) {
            return EvaluationError.UnexpectedTerminate;
        } else if (Interpreter.asError(res)) |r| {
            return r;
        } else if (Parser.asSyntaxError(res)) |r| {
            return r;
        } else unreachable;
    };

    switch (out) {
        .Evaluated => return out.Evaluated,
        .Terminated => return out.Terminated.toError(Parser.SyntaxError),
    }

    return error.UnboundSymbol;
}

pub fn asResult(r: anyerror) ?Result {
    return TypeUtils.narrowErrorSet(Result, r);
}

pub fn asSignal(r: anyerror) ?Signal {
    return TypeUtils.narrowErrorSet(Signal, r);
}

pub fn asEvaluationError(e: anyerror) ?EvaluationError {
    return TypeUtils.narrowErrorSet(EvaluationError, e);
}

pub fn asError(e: anyerror) ?Error {
    return TypeUtils.narrowErrorSet(Error, e);
}

pub fn isResult(r: anyerror) bool {
    return TypeUtils.isInErrorSet(Result, r);
}

pub fn isSignal(r: anyerror) bool {
    return TypeUtils.isInErrorSet(Signal, r);
}

pub fn isEvaluationError(e: anyerror) bool {
    return TypeUtils.isInErrorSet(EvaluationError, e);
}

pub fn isError(e: anyerror) bool {
    return TypeUtils.isInErrorSet(Error, e);
}

pub const ExternMessage = enum(u8) {
    SigTerminate,

    ErrPanic,
    ErrNotEvaluatable,
    ErrNotCallable,
    ErrTypeError,
    ErrRangeError,
    ErrNotEnoughArguments,
    ErrTooManyArguments,
    ErrDivisionByZero,
    ErrUnboundSymbol,
    ErrInvalidContext,
    ErrEnvironmentUnderflow,
    ErrCallStackOverflow,
    ErrMissingDynamic,
    ErrUnexpectedTerminate,
    ErrMissingTerminationData,

    ErrOutOfMemory,
    ErrBadEncoding,
};

pub const RichError = struct {
    err: Error,
    msg: ?[]const u8,
    attr: ?*const Source.Attr,
    stack: ?std.ArrayList(*const Source.Attr),

    const Self = @This();

    pub fn initFromInterpreter(interpreter: *const Interpreter, err: Error) Self {
        return Self{ .err = err, .msg = interpreter.errorCause, .attr = interpreter.attr, .stack = interpreter.errorStack };
    }

    pub fn format(self: *const Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("Evaluation error", .{});
        if (self.attr) |attr| {
            try writer.print(" at {}", .{attr});
        }
        try writer.print(": ", .{});

        try self.printError(writer);

        if (self.msg) |cause| {
            try writer.print("\n\t{s}", .{cause});
        }

        if (self.stack) |stack| {
            try writer.writeAll("\n\n\tstack trace:");
            for (0..stack.items.len) |i| {
                const attr = stack.items[stack.items.len - i - 1];
                try writer.print("\n\t\t{}", .{attr});
            }
        }
    }

    fn printError(self: *const Self, writer: anytype) !void {
        switch (self.err) {
            EvaluationError.Panic => return writer.print("Panic", .{}),
            EvaluationError.NotEvaluatable => return writer.print("Expression is not evaluatable", .{}),
            EvaluationError.NotCallable => return writer.print("Expression is not callable", .{}),
            EvaluationError.TypeError => return writer.print("Type error", .{}),
            EvaluationError.RangeError => return writer.print("Range error", .{}),
            EvaluationError.NotEnoughArguments => return writer.print("Not enough arguments", .{}),
            EvaluationError.TooManyArguments => return writer.print("Too many arguments", .{}),
            EvaluationError.DivisionByZero => return writer.print("Division by zero", .{}),
            EvaluationError.UnboundSymbol => return writer.print("Unbound symbol", .{}),
            EvaluationError.InvalidContext => return writer.print("Invalid context", .{}),
            EvaluationError.EnvironmentUnderflow => return writer.print("Environment underflow (no frame to pop)", .{}),
            EvaluationError.CallStackOverflow => return writer.print("Call stack overflow (max call depth is {})", .{Config.MAX_DEPTH}),
            EvaluationError.MissingDynamic => return writer.print("Missing dynamic binding", .{}),
            EvaluationError.UnexpectedTerminate => return writer.print("Unexpected `terminate`", .{}),
            EvaluationError.MissingTerminationData => return writer.print("Missing termination data", .{}),
            EvaluationError.NoModuleSystem => return writer.print("No module system", .{}),

            TextUtils.Error.BadEncoding => return writer.print("Bad text encoding", .{}),

            Context.Error.OutOfMemory => return writer.print("Out of memory", .{}),

            Parser.SyntaxError.UnexpectedEOF => return writer.print("Syntax error: unexpected eof", .{}),
            Parser.SyntaxError.UnexpectedInput => return writer.print("Syntax error: unexpected input", .{}),
        }
    }
};

pub fn init(context: *Context, cwd: std.fs.Dir) Error!*Interpreter {
    const nil = try SExpr.Nil(context.attr);

    const ptr = try context.allocator.create(Interpreter);

    ptr.* = Interpreter{
        .cwd = cwd,
        .context = context,
        .errorCause = null,
        .errorStack = null,
        .attr = null,
        .env = try SExpr.List(context.attr, &[1]SExpr{try SExpr.List(context.attr, &[0]SExpr{})}),
        .callerEnv = nil,
        .evidence = try SExpr.List(context.attr, &[1]SExpr{try SExpr.List(context.attr, &[0]SExpr{})}),
        .globalEvidence = nil,
        .callStack = std.ArrayList(*const Source.Attr).init(context.allocator),
    };

    return ptr;
}

pub fn deinit(interpreter: *Interpreter) void {
    if (interpreter.errorCause) |cause| {
        interpreter.context.allocator.free(cause);
    }
    if (interpreter.errorStack) |stack| {
        stack.deinit();
    }
    interpreter.context.allocator.destroy(interpreter);
}

pub const SavedEvaluationEnvs = struct { SExpr, SExpr };

pub fn save(interpreter: *const Interpreter) !SavedEvaluationEnvs {
    return .{ try copyEnv(interpreter.context.attr, interpreter.env), try copyEnv(interpreter.context.attr, interpreter.callerEnv) };
}

pub fn restore(interpreter: *Interpreter, envs: SavedEvaluationEnvs) void {
    interpreter.env = envs[0];
    interpreter.callerEnv = envs[1];

    if (interpreter.errorCause) |cause| {
        interpreter.context.allocator.free(cause);
        interpreter.errorCause = null;
    }

    if (interpreter.errorStack) |stack| {
        stack.deinit();
        interpreter.errorStack = null;
    }

    interpreter.attr = null;

    interpreter.callStack.clearRetainingCapacity();
}

pub fn exit(interpreter: *Interpreter, err: Error, attr: *const Source.Attr) Error {
    interpreter.attr = attr;
    interpreter.errorCause = null;
    return err;
}

pub fn abort(interpreter: *Interpreter, err: Error, attr: *const Source.Attr, comptime fmt: []const u8, args: anytype) Error {
    interpreter.attr = attr;
    interpreter.errorCause = try std.fmt.allocPrint(interpreter.context.allocator, fmt, args);
    interpreter.errorStack = try interpreter.callStack.clone();
    return err;
}

pub fn errDiagnosticFilled(interpreter: *const Interpreter) bool {
    return interpreter.errorCause != null;
}

pub fn errFmt(interpreter: *const Interpreter, err: Error) RichError {
    return RichError.initFromInterpreter(interpreter, err);
}

pub fn envLookupPair(symbol: SExpr, env: SExpr) Error!?SExpr {
    var it = env.iter();

    while (try it.next()) |frame| {
        if (try alistLookup(symbol, frame)) |pair| {
            return pair;
        }
    }

    return null;
}

pub fn envLookup(symbol: SExpr, env: SExpr) Error!?SExpr {
    const pair = try envLookupPair(symbol, env) orelse return null;

    if (pair.castCons()) |xp| {
        return xp.cdr;
    } else {
        return EvaluationError.TypeError;
    }
}

pub fn envBase(env: SExpr) Error!SExpr {
    var frameIter = env.iter();
    var lastList = frameIter.list;

    while (try frameIter.next()) |_| {
        if (frameIter.isDone()) break else {
            lastList = frameIter.list;
        }
    }

    return lastList;
}

pub fn envKeys(env: SExpr, allocator: std.mem.Allocator) Error![]SExpr {
    var keyset = SExpr.HashSet.init(allocator);
    defer keyset.deinit();

    try envKeysToSet(env, &keyset);

    return try allocator.dupe(SExpr, keyset.keys());
}

pub fn envKeyStrs(env: SExpr, allocator: std.mem.Allocator) Error![]const []const u8 {
    var keyset = SExpr.HashSet.init(allocator);
    defer keyset.deinit();

    try envKeysToSet(env, &keyset);

    var buf = std.ArrayList([]const u8).init(allocator);
    defer buf.deinit();

    for (keyset.keys()) |key| {
        try buf.append(key.forceSymbolSlice());
    }

    return try buf.toOwnedSlice();
}

pub fn envKeysToSet(env: SExpr, keyset: *SExpr.HashSet) Error!void {
    var current = env;
    while (!current.isNil()) {
        const xp = current.castCons() orelse return EvaluationError.TypeError;

        try alistKeysToSet(xp.car, keyset);

        current = xp.cdr;
    }
}

pub fn alistKeys(frame: SExpr) Error![]SExpr {
    const allocator = frame.getAttr().context.allocator;

    var keyset = SExpr.HashSet.init(allocator);
    defer keyset.deinit();

    try alistKeysToSet(frame, &keyset);

    return allocator.dupe(SExpr, keyset.keys());
}

pub fn alistKeysToSet(frame: SExpr, keyset: *SExpr.HashSet) Error!void {
    var current = frame;
    while (!current.isNil()) {
        const xp = current.castCons() orelse return EvaluationError.TypeError;
        const binding = xp.car;
        const rest = xp.cdr;

        const bindingXp = binding.castCons() orelse return EvaluationError.TypeError;

        if (bindingXp.car.isSymbol()) {
            try keyset.put(bindingXp.car, {});
        }

        current = rest;
    }
}

pub fn alistRemove(key: SExpr, alist: SExpr) Error!?SExpr {
    if (alist.isNil()) {
        return null;
    }

    if (alist.castCons()) |xp| {
        const binding = xp.car;
        const rest = xp.cdr;

        const bindingXp = binding.castCons() orelse {
            Rli.log.err("alistLookup: expected binding to be a cons, got {}: `{}` in alist `{}`", .{ binding.getTag(), binding, alist });
            return EvaluationError.TypeError;
        };

        if (MiscUtils.equal(bindingXp.car, key)) {
            return rest;
        } else {
            const newRest = try alistRemove(key, rest) orelse return null;
            return try SExpr.Cons(alist.getAttr(), binding, newRest);
        }
    } else {
        return EvaluationError.TypeError;
    }
}

pub fn alistLookup(key: SExpr, alist: SExpr) Error!?SExpr {
    var current = alist;

    while (!current.isNil()) {
        const xp = current.castCons() orelse return EvaluationError.TypeError;
        const binding = xp.car;
        const rest = xp.cdr;

        const bindingXp = binding.castCons() orelse {
            Rli.log.err("alistLookup: expected binding to be a cons, got {}: `{}` in alist `{}`", .{ binding.getTag(), binding, alist });
            return EvaluationError.TypeError;
        };

        if (MiscUtils.equal(bindingXp.car, key)) {
            return binding;
        }

        current = rest;
    }

    return null;
}

pub fn copyEnv(at: *const Source.Attr, env: SExpr) Error!SExpr {
    var newEnv = try SExpr.Nil(at);
    var current = env;

    while (!current.isNil()) {
        const xp = current.castCons() orelse return EvaluationError.TypeError;
        const frame = xp.car;
        const rest = xp.cdr;

        const newFrame = try copyFrame(at, frame);

        newEnv = try SExpr.Cons(at, newFrame, newEnv);

        current = rest;
    }

    return newEnv;
}

pub fn copyFrame(at: *const Source.Attr, frame: SExpr) Error!SExpr {
    var current = frame;
    var newFrame = try SExpr.Nil(at);

    while (!current.isNil()) {
        const xp = current.castCons() orelse return EvaluationError.TypeError;
        const binding = xp.car;
        const rest = xp.cdr;

        const newBinding = try copyBinding(at, binding);

        newFrame = try SExpr.Cons(at, newBinding, newFrame);

        current = rest;
    }

    return newFrame;
}

pub fn copyBinding(at: *const Source.Attr, binding: SExpr) Error!SExpr {
    const bindingXp = binding.castCons() orelse return EvaluationError.TypeError;
    return try SExpr.Cons(at, bindingXp.car, bindingXp.cdr);
}

pub fn validateEnv(env: SExpr) Error!void {
    var current = env;

    while (!current.isNil()) {
        const xp = current.castCons() orelse return EvaluationError.TypeError;
        const frame = xp.car;
        const rest = xp.cdr;

        try validateFrame(frame);

        current = rest;
    }
}

pub fn validateFrame(frame: SExpr) Error!void {
    var current = frame;

    while (!current.isNil()) {
        const xp = current.castCons() orelse return EvaluationError.TypeError;
        const binding = xp.car;
        const rest = xp.cdr;

        const bindingXp = binding.castCons() orelse return EvaluationError.TypeError;

        if (!bindingXp.car.isSymbol()) {
            return EvaluationError.TypeError;
        }

        current = rest;
    }
}

pub fn pushFrame(frame: SExpr, env: *SExpr) Error!void {
    const newEnv = try SExpr.Cons(frame.getAttr(), frame, env.*);
    env.* = newEnv;
}

pub fn popFrame(env: *SExpr) Error!SExpr {
    if (env.castCons()) |xp| {
        env.* = xp.cdr;
        return xp.car;
    } else if (env.isNil()) {
        return EvaluationError.EnvironmentUnderflow;
    } else {
        return EvaluationError.TypeError;
    }
}

pub fn getFrame(frameOffset: usize, env: SExpr) Error!SExpr {
    var current = env;
    for (0..frameOffset) |_| {
        if (current.isNil()) {
            return EvaluationError.EnvironmentUnderflow;
        }

        const xp = current.castCons() orelse return EvaluationError.TypeError;
        current = xp.cdr;
    }

    return (current.castCons() orelse return EvaluationError.EnvironmentUnderflow).car;
}

pub fn pushNewFrame(at: *const Source.Attr, env: *SExpr) Error!void {
    try pushFrame(try SExpr.Nil(at), env);
}

pub fn extendEnvFrame(at: *const Source.Attr, symbol: SExpr, value: SExpr, env: SExpr) Error!void {
    const frame = (env.castCons() orelse return EvaluationError.TypeError).car;

    const pair = try SExpr.Cons(at, symbol, value);

    const frameExt = try SExpr.Cons(at, pair, frame);

    env.forceCons().car = frameExt;
}

pub fn extendFrame(at: *const Source.Attr, symbol: SExpr, value: SExpr, frame: *SExpr) Error!void {
    const pair = try SExpr.Cons(at, symbol, value);
    frame.* = try SExpr.Cons(at, pair, frame.*);
}

pub fn nativeFetch(interpreter: *Interpreter, at: *const Source.Attr, prompt: []const u8) Result!SExpr {
    const symbol = try SExpr.Symbol(at, prompt);
    return liftFetch(interpreter, at, symbol);
}

pub fn nativePrompt(interpreter: *Interpreter, at: *const Source.Attr, prompt: []const u8, args: anytype) Result!SExpr {
    const symbol = try SExpr.Symbol(at, prompt);
    const argsList = SExpr.MappedList(at, args, SExpr.Quote) catch |err| {
        return interpreter.abort(err, at,
            "failed to map argument list:" ++ switch (@TypeOf(args)) {SExpr => "`{}`", else => "`{any}`"},
            .{args});
    };
    return liftPrompt(interpreter, at, symbol, argsList);
}

pub fn nativeInvoke(interpreter: *Interpreter, at: *const Source.Attr, callback: SExpr, args: anytype) Result!SExpr {
    const argsList = SExpr.MappedList(at, args, SExpr.Quote) catch |err| {
        return interpreter.abort(err, at,
            "failed to map argument list:" ++ switch (@TypeOf(args)) {SExpr => "`{}`", else => "`{any}`"},
            .{args});
    };
    return invoke(interpreter, at, callback, argsList);
}

pub const NativeWithOut = union(enum) { Evaluated: SExpr, Terminated: SExpr };

pub fn nativeWith(
    interpreter: *Interpreter, at: *const Source.Attr,
    body: SExpr,
    out: *NativeWithOut,
    comptime HandlerSet: type,
) Result!void {
    const baseEv = interpreter.evidence;
    try pushNewFrame(at, &interpreter.evidence);
    defer interpreter.evidence = baseEv;

    const contextId = try SExpr.Int(at, @intCast(interpreter.context.genId()));


    inline for (comptime std.meta.declarations(HandlerSet)) |decl| {
        log.debug("adding native handler for `{s}`", .{decl.name});

        const promptSym = try SExpr.Symbol(at, decl.name);
        const wrappedHandler = try wrapNativeHandler(interpreter, at, contextId, decl.name, promptSym, @field(HandlerSet, decl.name));

        try extendEnvFrame(at, promptSym, wrappedHandler, interpreter.evidence);
        log.debug("added native handler for `{}`", .{promptSym});
    }

    log.debug("running nativeWith encapsulated body {}", .{body});
    const value = interpreter.runProgram(body) catch |res| {
        log.debug("nativeWith caught error {}", .{res});
        if (res == Signal.Terminate) {
            const terminationData = interpreter.terminationData orelse {
                log.debug("nativeWith missing termination data", .{});
                return EvaluationError.MissingTerminationData;
            };
            if (MiscUtils.equal(terminationData.ctxId, contextId)) {
                log.debug("nativeWith early-terminate on my context", .{});
                out.* = .{ .Terminated = terminationData.value };
                interpreter.terminationData = null;
                return;
            }
        }
        return res;
    };

    log.debug("nativeWith did not early-terminate", .{});

    out.* = .{ .Evaluated = value };
}

fn wrapNativeHandler(interpreter: *Interpreter, at: *const Source.Attr, ctxId: SExpr, comptime handlerName: []const u8, promptSym: SExpr, handler: SExpr.Types.Builtin.Proc) Result!SExpr {
    var env = interpreter.env;

    const handlerSym = try SExpr.Symbol(at, "builtin-handler");
    const terminatorSym = try SExpr.Symbol(at, "terminator");
    const argsSym = try SExpr.Symbol(at, "args");

    try pushNewFrame(at, &env);
    try extendEnvFrame(at, handlerSym, try SExpr.Builtin(at, "native-handler-" ++ handlerName, handler), env);
    try extendEnvFrame(at, terminatorSym, try wrapTerminator(interpreter, at, ctxId, promptSym, "native-terminator", valueTerminator), env);

    const lList = try SExpr.List(at, &.{ try SExpr.Symbol(at, "..."), argsSym });
    const closureBody = try SExpr.List(at, &.{
        try SExpr.Quasi(
            try SExpr.List(at, &.{
                try SExpr.Unquote(try SExpr.ToQuote(handlerSym)),
                try SExpr.Unquote(terminatorSym),
                try SExpr.UnquoteSplicing(argsSym)
            })
        ),
    });

    return try SExpr.Function(at, .Macro, lList, env, closureBody);
}


pub fn wrapTerminator(interpreter: *Interpreter, at: *const Source.Attr, ctxId: SExpr, promptName: SExpr, comptime terminatorName: []const u8, comptime terminator: fn (*Interpreter, *const Source.Attr, SExpr) Result!SExpr) Result!SExpr {
    var env = interpreter.env;

    const terminateSym = try SExpr.Symbol(at, "builtin-terminate");
    const valSym = try SExpr.Symbol(at, "val");

    try pushNewFrame(at, &env);
    try extendEnvFrame(at, terminateSym, try SExpr.Builtin(at, terminatorName, struct {
        pub fn fun(a: *Interpreter, b: *const Source.Attr, c: SExpr) Result!SExpr {
            log.debug("wrappedTerminator-{s} {}", .{terminatorName, c});
            return terminator(a, b, c);
        }
    }.fun), env);

    const val = try SExpr.List(at, &.{ try SExpr.Symbol(at, "?"), valSym });
    const lList = try SExpr.List(at, &.{val});
    const invoker = try SExpr.List(at, &.{ terminateSym, ctxId, promptName, valSym });
    const body = try SExpr.List(at, &.{invoker});

    return try SExpr.Function(at, .Lambda, lList, env, body);
}

pub fn valueTerminator(interpreter: *Interpreter, _: *const Source.Attr, args: SExpr) Result!SExpr {
    log.debug("valueTerminator {}", .{args});
    const buf = try interpreter.expectN(3, args);
    const ctxId = buf[0];
    const value = try interpreter.eval(buf[2]);
    interpreter.terminationData = .{
        .ctxId = ctxId,
        .value = value,
    };
    return Signal.Terminate;
}

pub fn liftFetch(interpreter: *Interpreter, at: *const Source.Attr, name: SExpr) Result!SExpr {
    const binding =
        if (try envLookupPair(name, interpreter.evidence) orelse try alistLookup(name, interpreter.globalEvidence)) |pair| pair.forceCons().cdr else {
        return interpreter.abort(EvaluationError.MissingDynamic, at,
            "unhandled fetch `{}`", .{name});
    };

    return binding;
}

pub fn liftPrompt(interpreter: *Interpreter, at: *const Source.Attr, name: SExpr, args: SExpr) Result!SExpr {
    log.debug("liftPrompt {} {}", .{name, args});
    const handler = try liftFetch(interpreter, at, name);

    return interpreter.invoke(at, handler, args);
}

pub fn eval(interpreter: *Interpreter, sexpr: SExpr) Result!SExpr {
    switch (sexpr.getTag()) {
        inline .Nil,
        .Bool,
        .Int,
        .Char,
        .Float,
        .String,
        => {
            return sexpr;
        },

        .Symbol => {
            if (try envLookupPair(sexpr, interpreter.env)) |pair| {
                return pair.forceCons().cdr;
            } else {
                const sym = sexpr.forceSymbolSlice();

                if (std.mem.eql(u8, sym, "unquote") or std.mem.eql(u8, sym, "unquote-splicing")) {
                    return interpreter.abort(EvaluationError.InvalidContext, sexpr.getAttr(), "encountered `{s}` outside of quasiquote", .{sym});
                } else if (std.mem.eql(u8, sym, "terminate")) {
                    return interpreter.abort(EvaluationError.UnexpectedTerminate, sexpr.getAttr(), "encountered `terminate` outside of effect handler", .{});
                } else {
                    return interpreter.abort(EvaluationError.UnboundSymbol, sexpr.getAttr(), "unbound symbol `{s}`", .{sym});
                }
            }
        },

        .Cons => {
            const xp = sexpr.forceCons();
            const fun = try interpreter.eval(xp.car);
            return @call(.always_inline, invoke, .{ interpreter, xp.attr, fun, xp.cdr });
        },

        else => return interpreter.abort(EvaluationError.NotEvaluatable, sexpr.getAttr(), "cannot evaluate {}", .{sexpr.getTag()}),
    }
}

pub fn evalListRecursive(interpreter: *Interpreter, sList: SExpr) Result!SExpr {
    const xp =
        if (sList.castCons()) |c| c
        else if (sList.isNil()) return sList
        else {
            return interpreter.abort(EvaluationError.TypeError, sList.getAttr(), "expected a list, got {}", .{sList.getTag()});
        };
    const newCar = try interpreter.eval(xp.car);
    const newCdr = try interpreter.evalListRecursive(xp.cdr);
    return try SExpr.Cons(sList.getAttr(), newCar, newCdr);
}

pub fn evalList(interpreter: *Interpreter, sList: SExpr) Result![]const SExpr {
    return evalListInRange(interpreter, sList, 0, std.math.maxInt(usize));
}

pub fn evalListOfT(interpreter: *Interpreter, comptime T: type, sList: SExpr) Result![]const T {
    return evalListOfTInRange(interpreter, T, sList, 0, std.math.maxInt(usize));
}

pub fn evalListInRange(interpreter: *Interpreter, sList: SExpr, minLength: usize, maxLength: usize) Result![]const SExpr {
    return evalListOfInRange(interpreter, sList, minLength, maxLength, "", passAll);
}

pub fn evalListOfTInRange(interpreter: *Interpreter, comptime T: type, sList: SExpr, minLength: usize, maxLength: usize) Result![]const T {
    var listBuf = std.ArrayList(T).init(interpreter.context.allocator);

    var tail = sList;

    while (!tail.isNil()) {
        const xp: *SExpr.Types.Cons = (tail.castCons() orelse {
            return interpreter.abort(Error.TypeError, tail.getAttr(), "expected a list, got {}", .{tail.getTag()});
        });

        tail = xp.cdr;

        const head =
            (try interpreter.eval(xp.car)).to(T) catch |err| {
                return interpreter.abort(err, xp.car.getAttr(), "expected {s}, got {}", .{ @typeName(T), xp.car.getTag() });
            };


        try listBuf.append(head);
    }

    const len = listBuf.items.len;

    if (len < minLength) {
        return interpreter.abort(Error.NotEnoughArguments, sList.getAttr(), "expected at least {} arguments, got {}", .{ minLength, len });
    }

    if (len > maxLength) {
        return interpreter.abort(Error.TooManyArguments, sList.getAttr(), "expected at most {} arguments, got {}", .{ maxLength, len });
    }

    listBuf.shrinkAndFree(len);

    return listBuf.items;
}

pub fn evalListOfInRange(interpreter: *Interpreter, sList: SExpr, minLength: usize, maxLength: usize, comptime expected: []const u8, predicate: fn (SExpr) bool) Result![]const SExpr {
    var listBuf = std.ArrayList(SExpr).init(interpreter.context.allocator);

    var tail = sList;

    while (!tail.isNil()) {
        const xp: *SExpr.Types.Cons = (tail.castCons() orelse {
            return interpreter.abort(Error.TypeError, tail.getAttr(), "expected a list, got {}", .{tail.getTag()});
        });

        tail = xp.cdr;

        const head = try interpreter.eval(xp.car);

        if (!predicate(head)) {
            return interpreter.abort(Error.TypeError, xp.car.getAttr(), "expected {s}, got {}", .{ expected, head.getTag() });
        }

        try listBuf.append(head);
    }

    const len = listBuf.items.len;

    if (len < minLength) {
        return interpreter.abort(Error.NotEnoughArguments, sList.getAttr(), "expected at least {} arguments, got {}", .{ minLength, len });
    }

    if (len > maxLength) {
        return interpreter.abort(Error.TooManyArguments, sList.getAttr(), "expected at most {} arguments, got {}", .{ maxLength, len });
    }

    listBuf.shrinkAndFree(len);

    return listBuf.items;
}

pub fn invoke(interpreter: *Interpreter, at: *const Source.Attr, fun: SExpr, sArgs: SExpr) Result!SExpr {
    log.debug("invoke {} {}", .{fun, sArgs});
    switch (fun.getTag()) {
        .Nil,
        .Bool,
        .Int,
        .Char,
        .Float,
        .String,
        .Symbol,
        .Cons,
        .ExternData,
        => {
            return interpreter.abort(Error.NotCallable, at,
                "expected a function or builtin, got {}: `{}`", .{fun.getTag(), fun});
        },

        .Function => {
            return @call(.always_inline, runFunction, .{ interpreter, at, fun, sArgs });
        },

        .Builtin => return @call(.always_inline, runBuiltin, .{ interpreter, at, fun, sArgs }),

        .ExternFunction => return @call(.always_inline, runExternFunction, .{ interpreter, at, fun, sArgs }),
    }
}

fn mkPatternRichError(interpreter: *Interpreter, err: EvaluationError, at: *const Source.Attr, comptime fmt: []const u8, args: anytype) Error!RichError {
    return RichError{
        .err = err,
        .msg = try std.fmt.allocPrint(interpreter.context.allocator, fmt, args),
        .attr = at,
        .stack = try interpreter.callStack.clone(),
    };
}

fn mkPatternLiteError(_: *Interpreter, _: EvaluationError, _: *const Source.Attr, comptime _: []const u8, _: anytype) Error!void {
    return {};
}

pub const PatternLite = Pattern(void, mkPatternLiteError);
pub const PatternRich = Pattern(RichError, mkPatternRichError);

fn Pattern(comptime E: type, comptime mkError: fn (*Interpreter, EvaluationError, *const Source.Attr, comptime []const u8, anytype) Result!E) type {
    return struct {
        pub const Error = E;
        pub const LLResult = union(enum) {
            Error: E,
            Okay: SExpr,
        };

        pub inline fn run(interpreter: *Interpreter, at: *const Source.Attr, list: SExpr, args: SExpr) Result!LLResult {
            var bindings = SExpr.HashMapOf(?SExpr).init(interpreter.context.allocator);
            defer bindings.deinit();

            if (try runImpl(interpreter, at, &bindings, list, args)) |err| {
                return LLResult{ .Error = err };
            } else {
                return LLResult{ .Okay = try frameFromHashMap(at, &bindings) };
            }
        }

        fn runImpl(interpreter: *Interpreter, at: *const Source.Attr, bindings: *SExpr.HashMapOf(?SExpr), expected: SExpr, given: SExpr) Result!?E {
            // log.debug("running pattern {} on {}", .{expected, given});
            switch (expected.getTag()) {
                .Nil,
                .Bool,
                .Int,
                .Char,
                .Float,
                .String,
                => if (MiscUtils.equal(given, expected)) {
                    return null;
                } else {
                    return patternError(interpreter, EvaluationError.TypeError, at,
                        "expected {}, got {}", .{ expected, given });
                },

                .Symbol => if (std.mem.eql(u8, expected.forceSymbolSlice(), "_")) {
                    return null;
                } else {
                    return bind(interpreter, at, bindings, expected, given);
                },

                .Cons => {
                    log.debug("{}: checking cons pattern {}:{} on {}:{}", .{at, expected.getAttr(), expected, given.getAttr(), given});
                    var currentExpected = expected;
                    var currentGiven = given;
                    while (!currentExpected.isNil()) {
                        const xpExpected = currentExpected.castCons() orelse { // pairs of the form `(a . a)`
                            return runImpl(interpreter, at, bindings, currentExpected, currentGiven);
                        };

                        {
                            var err: ?E = null;
                            if (try specialImpl(interpreter, at, bindings, xpExpected.car, xpExpected.cdr, currentGiven, &err)) {
                                return err;
                            }
                        }

                        const elemExpected = xpExpected.car;

                        if (isRest(elemExpected)) {
                            if (try runImpl(interpreter, at, bindings, elemExpected, currentGiven)) |err| {
                                return err;
                            }

                            if (!xpExpected.cdr.isNil()) {
                                return interpreter.abort(EvaluationError.TypeError, xpExpected.attr,
                                    "invalid pattern, expected rest parameter to end list got {}", .{xpExpected.cdr.getTag()});
                            }

                            return null;
                        }

                        if (currentGiven.castCons()) |xpGiven| {
                            const elemGiven = xpGiven.car;

                            if (try runImpl(interpreter, at, bindings, elemExpected, elemGiven)) |err| {
                                return err;
                            }

                            currentGiven = xpGiven.cdr;
                        } else if (currentGiven.isNil() and isOptional(elemExpected)) {
                            if (try runImpl(interpreter, at, bindings, elemExpected, currentGiven)) |err| {
                                return err;
                            }
                        } else {
                            return patternError(interpreter, EvaluationError.NotEnoughArguments, at,
                                "expected more items in input list; comparing `{}` to `{}`", .{expected, given});
                        }

                        currentExpected = xpExpected.cdr;
                    }

                    if (currentGiven.isNil()) {
                        return null;
                    } else if (currentGiven.isCons()) {
                        return patternError(interpreter, EvaluationError.TooManyArguments, at,
                            "expected less items in input list; comparing `{}` to `{}` (leaves `{}`)", .{expected, given, currentGiven});
                    } else {
                        return patternError(interpreter, EvaluationError.TypeError, at,
                            "expected a list, got {}; comparing `{}` to `{}`", .{currentGiven.getTag(), expected, given});
                    }
                },

                .Function,
                .Builtin,
                .ExternData,
                .ExternFunction,
                => {
                    return interpreter.abort(EvaluationError.TypeError, at,
                        "invalid pattern element ({} is not supported)", .{expected.getTag()});
                },
            }
        }

        fn isRest(list: SExpr) bool {
            if (list.castCons()) |xp| {
                return xp.car.isExactSymbol("...");
            }

            return false;
        }

        fn isOptional(list: SExpr) bool {
            if (list.castCons()) |xp| {
                if (xp.car.isExactSymbol("?") or xp.car.isExactSymbol("...")) {
                    return true;
                } else if (xp.car.isExactSymbol("@")) {
                    if (xp.cdr.castCons()) |xp2| {
                        if (xp2.cdr.castCons()) |xp3| {
                            return isOptional(xp3.car);
                        }
                    }
                }
            }

            return false;
        }

        inline fn bind(interpreter: *Interpreter, at: *const Source.Attr, bindings: *SExpr.HashMapOf(?SExpr), symbol: SExpr, given: ?SExpr) Result!?E {
            std.debug.assert(symbol.isSymbol());

            if (bindings.get(symbol)) |existing| {
                if (existing) |e| {
                    if (given) |g| {
                        if (!MiscUtils.equal(e, g)) {
                            return patternError(interpreter, EvaluationError.TypeError, at, "expected {}, got {}", .{ e, g });
                        }
                    }
                } else {
                    try bindings.put(symbol, given);
                }
            } else {
                try bindings.put(symbol, given);
            }

            return null;
        }

        pub inline fn binders(interpreter: *Interpreter, at: *const Source.Attr, expected: SExpr) Result![]SExpr {
            var set = SExpr.HashSet.init(interpreter.context.allocator);
            defer set.deinit();

            try bindersImpl(interpreter, at, expected, &set);

            return try interpreter.context.allocator.dupe(SExpr, set.keys());
        }

        pub fn validate(interpreter: *Interpreter, expect: SExpr) Result!void {
            var set = SExpr.HashSet.init(interpreter.context.allocator);
            defer set.deinit();

            try bindersImpl(interpreter, expect.getAttr(), expect, &set);
        }

        fn specialImpl(interpreter: *Interpreter, at: *const Source.Attr, bindings: *SExpr.HashMapOf(?SExpr), symbol: SExpr, rest: SExpr, given: SExpr, errOut: *?E) Result!bool {
            if (symbol.isExactSymbol("quote")) {
                log.debug("recognized quote", .{});
                const xp = try interpreter.castList(at, rest);
                if (!xp.cdr.isNil()) {
                    return interpreter.abort(EvaluationError.TypeError, xp.attr,
                        "pattern element contains invalid quote, tail of body is {}", .{xp.cdr.getTag()});
                }

                const q = xp.car;
                if (q.isSymbol()) {
                    if (MiscUtils.equal(q, given)) {
                        errOut.* = null;
                    } else {
                        errOut.* = try patternError(interpreter, EvaluationError.TypeError, at,
                            "expected {}, got {}", .{ q, given });
                    }
                    return true;
                } else {
                    return interpreter.abort(EvaluationError.TypeError, xp.attr,
                        "pattern element contains invalid quote, body is {} (should be Symbol)", .{q.getTag()});
                }
            } else if (symbol.isExactSymbol("unquote")) {
                log.debug("recognized unquote", .{});
                const xp = try interpreter.castList(at, rest);
                const uq = try interpreter.eval(xp.car);

                if (!xp.cdr.isNil()) {
                    return interpreter.abort(EvaluationError.TypeError, xp.attr,
                        "pattern element contains invalid unquote, tail of body is {}", .{xp.cdr.getTag()});
                }

                errOut.* = try runImpl(interpreter, at, bindings, uq, given);
                return true;
            } else if (symbol.isExactSymbol(":")) {
                log.debug("recognized predicate", .{});
                const xp = try interpreter.castList(at, rest);
                const predE = xp.car;

                try interpreter.validateNil(at, xp.cdr);

                const res = try interpreter.nativeInvoke(at, try interpreter.eval(predE), &[1]SExpr { given });

                if (res.coerceNativeBool()) {
                    errOut.* = null;
                } else {
                    errOut.* = try patternError(interpreter, EvaluationError.RangeError, at,
                        "predicate `{}` failed on value `{}`", .{ predE, given });
                }
                return true;
            } else if (symbol.isExactSymbol("->")) {
                log.debug("recognized transformer", .{});
                const xp = try interpreter.castList(at, rest);
                const predE = xp.car;

                const body = try SExpr.List(at, &.{try SExpr.Cons(at, predE, try SExpr.List(at, &.{try SExpr.Quote(given)}))});

                log.debug("-> {}", .{body});

                var out: NativeWithOut = undefined;
                try interpreter.nativeWith(at, body, &out, struct {
                    pub fn fail(e: *Interpreter, a: *const Source.Attr, x: SExpr) Result!SExpr {
                        log.debug("-> fail", .{});
                        const eArgs = try e.expectAtLeastN(1, x);
                        return try invoke(e, a, eArgs.head[0], eArgs.tail);
                    }
                });

                log.debug("-> out: {}", .{out});

                switch (out) {
                    .Evaluated => |x| {
                        if (!xp.cdr.isNil()) {
                            log.debug("-> ran: {}", .{x});
                            log.debug("-> applying rest: {}", .{xp.cdr});
                            errOut.* = try runImpl(interpreter, at, bindings, xp.cdr, x);
                        } else {
                            errOut.* = null;
                        }
                    },
                    .Terminated => |_| {
                        log.debug("-> failed", .{});
                        errOut.* = try patternError(interpreter, EvaluationError.RangeError, at,
                            "view pattern `{}` failed on value `{}`", .{ predE, given });
                    },
                }

                return true;
            } else if (symbol.isExactSymbol("?")) {
                log.debug("recognized optional", .{});

                if (given.isNil()) {
                    const varBinders = try binders(interpreter, at, rest);
                    defer interpreter.context.allocator.free(varBinders);

                    for (varBinders) |binder| {
                        // cannot fail because given is null
                        _ = try bind(interpreter, at, bindings, binder, null);
                    }

                    errOut.* = null;
                } else {
                    errOut.* = try runImpl(interpreter, at, bindings, rest, given);
                }

                return true;
            } else if (symbol.isExactSymbol("@")) {
                log.debug("recognized alias", .{});
                const xp = try interpreter.castList(at, rest);

                const atSym = xp.car;

                if (!atSym.isSymbol()) {
                    return interpreter.abort(EvaluationError.TypeError, xp.attr,
                        "invalid pattern, expected a symbol to follow `@`, got {}", .{atSym.getTag()});
                }

                const xp2 = xp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                    "invalid pattern, expected a value to follow symbol in `@`, got {}", .{xp.cdr.getTag()});
                const vx = xp2.car;

                if (!xp2.cdr.isNil()) {
                    if (try runImpl(interpreter, at, bindings, xp.cdr, given)) |err| {
                        errOut.* = err;
                    } else {
                        errOut.* = try bind(interpreter, at, bindings, atSym, given);
                    }
                } else {
                    if (try runImpl(interpreter, at, bindings, vx, given)) |err| {
                        errOut.* = err;
                    } else {
                        errOut.* = try bind(interpreter, at, bindings, atSym, given);
                    }
                }

                return true;
            } else if (symbol.isExactSymbol("...")) {
                log.debug("recognized rest", .{});
                const xp = try interpreter.castList(at, rest);

                var restSym = xp.car;

                const invalid = invalid: {
                    if (!restSym.isSymbol()) {
                        if (restSym.castCons()) |rxp| {
                            if (rxp.car.isExactSymbol("unquote")) {
                                const xp2 = rxp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                    "invalid pattern, malformed unquote in rest parameter, got {}", .{rxp.cdr.getTag()});
                                restSym = try interpreter.eval(xp2.car);

                                if (!xp2.cdr.isNil()) {
                                    return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                        "invalid pattern, expected only a value to follow `,` in rest parameter unquote, got {}", .{xp2.cdr.getTag()});
                                }

                                if (!restSym.isSymbol()) {
                                    return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                        "invalid pattern, expected unquote inside rest parameter to evaluate to a symbol, got {}", .{restSym.getTag()});
                                }

                                break :invalid false;
                            }
                        }

                        break :invalid true;
                    }

                    break :invalid false;
                };

                if (invalid) {
                    return interpreter.abort(EvaluationError.TypeError, xp.attr,
                        "invalid pattern, expected a symbol to follow `...`, got {}", .{restSym.getTag()});
                }

                if (!xp.cdr.isNil()) {
                    return interpreter.abort(EvaluationError.TypeError, xp.attr,
                        "invalid pattern, expected only a symbol to follow `...`, got {}", .{xp.cdr.getTag()});
                }

                errOut.* = try bind(interpreter, at, bindings, restSym, given);
                return true;
            }

            log.debug("did not recognize a special pattern in {}", .{symbol});


            return false;
        }

        fn bindersImpl(interpreter: *Interpreter, at: *const Source.Attr, expected: SExpr, out: *SExpr.HashSet) Result!void {
            switch (expected.getTag()) {
                inline .Nil,
                .Bool,
                .Int,
                .Char,
                .Float,
                .String,
                => return,

                .Symbol => {
                    if (!out.contains(expected)) {
                        try out.put(expected, {});
                    }
                    return;
                },

                .Cons => {
                    var xp = expected.forceCons();
                    if (xp.car.isExactSymbol("quote")) {
                        xp = xp.cdr.castCons() orelse {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "pattern element contains invalid quote, body is {}", .{xp.cdr.getTag()});
                        };

                        if (!xp.cdr.isNil()) {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "pattern element contains invalid quote, tail of body is {}", .{xp.cdr.getTag()});
                        }

                        const q = xp.car;
                        if (q.isSymbol()) {
                            return;
                        } else {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "pattern element contains invalid quote, body is {} (should be symbol)", .{q.getTag()});
                        }
                    } else if (xp.car.isExactSymbol("unquote")) {
                        xp = xp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                            "pattern element contains invalid unquote, body is {}", .{xp.cdr.getTag()});

                        const uq = try interpreter.eval(xp.car);

                        if (!xp.cdr.isNil()) {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "pattern element contains invalid unquote, tail of body is {}", .{xp.cdr.getTag()});
                        }

                        return bindersImpl(interpreter, at, uq, out);
                    } else if (xp.car.isExactSymbol(":")) {
                        xp = xp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                            "invalid pattern, expected a value to follow `:`, got {}", .{xp.cdr.getTag()});

                        if (!xp.cdr.isNil()) {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "invalid pattern, expected only a value to follow `:`, got {}", .{xp.cdr.getTag()});
                        }

                        return;
                    } else if (xp.car.isExactSymbol("->")) {
                        xp = xp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                            "invalid pattern, expected a value to follow `->`, got {}", .{xp.cdr.getTag()});

                        return bindersImpl(interpreter, at, xp.cdr, out);
                    } else if (xp.car.isExactSymbol("?")) {
                        xp = xp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                            "invalid pattern, expected a var to follow `?`, got {}", .{xp.cdr.getTag()});
                        const vx = xp.car;

                        if (!xp.cdr.isNil()) {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "invalid pattern, expected only a value to follow `?`, got {}", .{xp.cdr.getTag()});
                        }

                        return bindersImpl(interpreter, at, vx, out);
                    } else if (xp.car.isExactSymbol("@")) {
                        xp = xp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                            "invalid pattern, expected a var to follow `@`, got {}", .{xp.cdr.getTag()});
                        const atSym = xp.car;

                        if (!atSym.isSymbol()) {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "invalid pattern, expected a symbol to follow `@`, got {}", .{atSym.getTag()});
                        }

                        xp = xp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, at,
                            "invalid pattern, expected a value to follow symbol in `@`, got {}", .{xp.cdr.getTag()});
                        const vx = xp.car;

                        if (!xp.cdr.isNil()) {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "invalid pattern, expected only a value to follow `@`, got {}", .{xp.cdr.getTag()});
                        }

                        if (!out.contains(atSym)) {
                            try out.put(atSym, {});
                        }

                        return bindersImpl(interpreter, at, vx, out);
                    } else if (xp.car.isExactSymbol("...")) {
                        xp = xp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                            "invalid pattern, expected a symbol to follow `...`, got {}", .{xp.cdr.getTag()});
                        var restSym = xp.car;

                        const invalid = invalid: {
                            if (!restSym.isSymbol()) {
                                if (restSym.castCons()) |rxp| {
                                    if (rxp.car.isExactSymbol("unquote")) {
                                        const xp2 = rxp.cdr.castCons() orelse return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                            "invalid pattern, malformed unquote in rest parameter, got {}", .{rxp.cdr.getTag()});
                                        restSym = try interpreter.eval(xp2.car);

                                        if (!xp2.cdr.isNil()) {
                                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                                "invalid pattern, expected only a value to follow `,` in rest parameter unquote, got {}", .{xp2.cdr.getTag()});
                                        }

                                        if (!restSym.isSymbol()) {
                                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                                "invalid pattern, expected unquote inside rest parameter to evaluate to a symbol, got {}", .{restSym.getTag()});
                                        }

                                        break :invalid false;
                                    }
                                }

                                break :invalid true;
                            }

                            break :invalid false;
                        };

                        if (invalid) {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "invalid pattern, expected a symbol to follow `...`, got {}", .{restSym.getTag()});
                        }

                        if (!xp.cdr.isNil()) {
                            return interpreter.abort(EvaluationError.TypeError, xp.attr,
                                "invalid pattern, expected only a symbol to follow `...`, got {}", .{xp.cdr.getTag()});
                        }

                        if (!out.contains(restSym)) {
                            try out.put(restSym, {});
                        }

                        return;
                    }

                    var currentExpected = expected;
                    while (!currentExpected.isNil()) {
                        const xpExpected = currentExpected.castCons() orelse { // MiscUtils pairs of the form `(a . a)`
                            return bindersImpl(interpreter, at, currentExpected, out);
                        };

                        const elemExpected = xpExpected.car;

                        try bindersImpl(interpreter, at, elemExpected, out);

                        currentExpected = xpExpected.cdr;
                    }
                },

                inline .Function,
                .Builtin,
                .ExternData,
                .ExternFunction,
                => {
                    return interpreter.abort(EvaluationError.TypeError, at,
                        "invalid pattern element ({} is not supported)", .{expected.getTag()});
                },
            }
        }

        inline fn patternAbort(interpreter: *Interpreter, err: EvaluationError, at: *const Source.Attr, comptime fmt: []const u8, args: anytype) Result!LLResult {
            return LLResult{
                .Error = (try patternError(interpreter, err, at, fmt, args)).?,
            };
        }

        inline fn patternError(interpreter: *Interpreter, err: EvaluationError, at: *const Source.Attr, comptime fmt: []const u8, args: anytype) Result!?E {
            log.debug("pattern error {}: {} " ++ fmt, .{at, err} ++ args);
            return try @call(.always_inline, mkError, .{ interpreter, err, at, fmt, args });
        }
    };
}

pub fn frameFromHashMap(at: *const Source.Attr, map: *const SExpr.HashMapOf(?SExpr)) Error!SExpr {
    const nil = try SExpr.Nil(at);
    var frame = nil;

    var iter = map.iterator();
    while (iter.next()) |rawPair| {
        const key = rawPair.key_ptr.*;
        const value = if (rawPair.value_ptr.*) |val| val else nil;
        const pair = try SExpr.Cons(at, key, value);
        frame = try SExpr.Cons(at, pair, frame);
    }

    return frame;
}

pub fn envFromHashMap(at: *const Source.Attr, map: *const SExpr.HashMapOf(?SExpr)) Error!SExpr {
    const frame = try frameFromHashMap(at, map);

    return try SExpr.Cons(at, frame, try SExpr.Nil(at));
}

pub fn runFunction(interpreter: *Interpreter, at: *const Source.Attr, sFun: SExpr, args: SExpr) Result!SExpr {
    log.debug("call depth {}\n", .{interpreter.callStack.items.len});
    if (interpreter.callStack.items.len > Config.MAX_DEPTH) {
        for (interpreter.callStack.items) |item| {
            log.err("{}", .{item});
        }
        return interpreter.exit(Error.CallStackOverflow, at);
    }

    try interpreter.callStack.append(at);
    defer _ = interpreter.callStack.pop();

    const fun = sFun.forceFunction();

    const eArgs = switch (fun.kind) {
        .Lambda => try interpreter.evalListRecursive(args),
        .Macro => args,
    };

    const frame = switch (try PatternRich.run(interpreter, at, fun.args, eArgs)) {
        .Okay => |frame| frame,
        .Error => |rich| return interpreter.abort(rich.err, rich.attr orelse at,
            "{s}", .{rich.msg orelse "failed to bind pattern"}),
    };

    const result = result: {
        const callerEnv = interpreter.env;
        interpreter.env = fun.env;

        const oldCallerEnv = interpreter.callerEnv;
        interpreter.callerEnv = callerEnv;

        defer {
            interpreter.env = callerEnv;
            interpreter.callerEnv = oldCallerEnv;
        }

        try pushFrame(frame, &interpreter.env);

        break :result try @call(.always_inline, runProgram, .{ interpreter, fun.body });
    };

    return switch (fun.kind) {
        .Lambda => result,
        .Macro => try interpreter.eval(result),
    };
}

pub fn runBuiltin(interpreter: *Interpreter, at: *const Source.Attr, sBuiltin: SExpr, sArgs: SExpr) Result!SExpr {
    const builtin = sBuiltin.forceBuiltin();
    return try builtin.getProc()(interpreter, at, sArgs);
}

pub fn runExternFunction(interpreter: *Interpreter, at: *const Source.Attr, sExternFunction: SExpr, sArgs: SExpr) Result!SExpr {
    const externFunction = sExternFunction.forceExternFunction();

    var msg: ExternMessage = undefined;
    var out: SExpr = undefined;

    if (externFunction.proc(interpreter, at, &msg, &out, sArgs)) {
        return out;
    } else {
        return resultFromExtern(msg);
    }
}

pub fn runProgram(interpreter: *Interpreter, program: SExpr) Result!SExpr {
    var tail = program;
    var result = try SExpr.Nil(interpreter.context.attr);

    while (!tail.isNil()) {
        const list: *SExpr.Types.Cons = (tail.castCons() orelse {
            return interpreter.abort(EvaluationError.TypeError, tail.getAttr(), "expected an expression list, got {}", .{tail.getTag()});
        });

        log.debug("runProgram {}", .{list.car});
        result = try interpreter.eval(list.car);

        tail = list.cdr;
    }

    return result;
}

pub fn resultFromExtern(err: ExternMessage) Result {
    switch (err) {
        ExternMessage.SigTerminate => return Signal.Terminate,

        ExternMessage.ErrPanic => return EvaluationError.Panic,
        ExternMessage.ErrNotEvaluatable => return EvaluationError.NotEvaluatable,
        ExternMessage.ErrNotCallable => return EvaluationError.NotCallable,
        ExternMessage.ErrTypeError => return EvaluationError.TypeError,
        ExternMessage.ErrRangeError => return EvaluationError.RangeError,
        ExternMessage.ErrNotEnoughArguments => return EvaluationError.NotEnoughArguments,
        ExternMessage.ErrTooManyArguments => return EvaluationError.TooManyArguments,
        ExternMessage.ErrDivisionByZero => return EvaluationError.DivisionByZero,
        ExternMessage.ErrUnboundSymbol => return EvaluationError.UnboundSymbol,
        ExternMessage.ErrInvalidContext => return EvaluationError.InvalidContext,
        ExternMessage.ErrEnvironmentUnderflow => return EvaluationError.EnvironmentUnderflow,
        ExternMessage.ErrCallStackOverflow => return EvaluationError.CallStackOverflow,
        ExternMessage.ErrMissingDynamic => return EvaluationError.MissingDynamic,
        ExternMessage.ErrUnexpectedTerminate => return EvaluationError.UnexpectedTerminate,
        ExternMessage.ErrMissingTerminationData => return EvaluationError.MissingTerminationData,

        ExternMessage.ErrOutOfMemory => return Context.Error.OutOfMemory,
        ExternMessage.ErrBadEncoding => return TextUtils.Error.BadEncoding,
    }
}

pub fn externFromResult(res: Result) ExternMessage {
    switch (res) {
        Signal.Terminate => return ExternMessage.SigTerminate,

        EvaluationError.Panic => return ExternMessage.ErrPanic,
        EvaluationError.NotEvaluatable => return ExternMessage.ErrNotEvaluatable,
        EvaluationError.NotCallable => return ExternMessage.ErrNotCallable,
        EvaluationError.TypeError => return ExternMessage.ErrTypeError,
        EvaluationError.RangeError => return ExternMessage.ErrRangeError,
        EvaluationError.NotEnoughArguments => return ExternMessage.ErrNotEnoughArguments,
        EvaluationError.TooManyArguments => return ExternMessage.ErrNotEnoughArguments,
        EvaluationError.DivisionByZero => return ExternMessage.ErrDivisionByZero,
        EvaluationError.UnboundSymbol => return ExternMessage.ErrUnboundSymbol,
        EvaluationError.InvalidContext => return ExternMessage.ErrInvalidContext,
        EvaluationError.EnvironmentUnderflow => return ExternMessage.ErrEnvironmentUnderflow,
        EvaluationError.CallStackOverflow => return ExternMessage.ErrCallStackOverflow,
        EvaluationError.MissingDynamic => return ExternMessage.ErrMissingDynamic,
        EvaluationError.UnexpectedTerminate => return ExternMessage.ErrUnexpectedTerminate,
        EvaluationError.MissingTerminationData => return ExternMessage.ErrMissingTerminationData,

        Context.Error.OutOfMemory => return ExternMessage.ErrOutOfMemory,
    }
}

pub fn validateNil(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isNil()) {
        return interpreter.abort(Error.TypeError, at,
            "expected Nil, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateNumber(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isNumber()) {
        return interpreter.abort(Error.TypeError, at,
            "expected an Int, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateInt(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isInt()) {
        return interpreter.abort(Error.TypeError, at,
            "expected an Int or a Float, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateBool(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isBool()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a Bool, got {}: `{}", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateChar(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isChar()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a Char, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateFloat(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isFloat()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a Float, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateString(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isString()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a String, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateStringSlice(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr, slice: []const u8) Error!void {
    if (!sexpr.isExactString(slice)) {
        return interpreter.abort(Error.TypeError, at,
            "expected a String `{}`, got {}: `{}`", .{ slice, sexpr.getTag(), sexpr });
    }
}

pub fn validateSymbol(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isSymbol()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a Symbol, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateSymbolSlice(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr, slice: []const u8) Error!void {
    if (!sexpr.isExactSymbol(slice)) {
        return interpreter.abort(Error.TypeError, at,
            "expected a Symbol `{s}`, got {}: `{}`", .{ slice, sexpr.getTag(), sexpr });
    }
}

pub fn validatePair(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isCons()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a pair, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateList(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isCons()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a list, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}
pub fn validateListOrNil(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isCons() and !sexpr.isNil()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a list, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateFunction(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isFunction()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a function, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateBuiltin(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isBuiltin()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a Builtin, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateExternData(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isExternData()) {
        return interpreter.abort(Error.TypeError, at,
            "expected an ExternData, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateExternDataPtr(interpreter: *Interpreter, comptime T: type, at: *const Source.Attr, sexpr: SExpr) Error!void {
    const externData = try interpreter.castExternData(at, sexpr);

    if (externData.castPtr(T) == null) {
        return interpreter.abort(Error.TypeError, at,
            "expected an ExternData of type {s}, got {s}", .{ @typeName(T), externData.typeNameSlice() });
    }
}

pub fn validateExternFunction(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isExternFunction()) {
        return interpreter.abort(Error.TypeError, at,
            "expected an ExternFunction, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn validateCallable(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!void {
    if (!sexpr.isCallable()) {
        return interpreter.abort(Error.TypeError, at,
            "expected a callable, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castNil(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!MiscUtils.Unit {
    if (sexpr.castNil()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected Nil, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castInt(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!i64 {
    if (sexpr.castInt()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected an Int, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castBool(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!bool {
    if (sexpr.castBool()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a Bool, got {}: `{}", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castChar(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!TextUtils.Char {
    if (sexpr.castChar()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a Char, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castFloat(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!f64 {
    if (sexpr.castFloat()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a Float, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castString(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!*SExpr.Types.String {
    if (sexpr.castString()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a String, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castStringSlice(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error![]const u8 {
    const str = try interpreter.castString(at, sexpr);

    return str.toSlice();
}

pub fn castSymbol(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!*SExpr.Types.Symbol {
    if (sexpr.castSymbol()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a Symbol, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castSymbolSlice(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error![]const u8 {
    const sym = try interpreter.castSymbol(at, sexpr);

    return sym.toSlice();
}

pub fn castPair(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!*SExpr.Types.Cons {
    if (sexpr.castCons()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a pair, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castPairTuple(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!struct { SExpr, SExpr } {
    const pair = try interpreter.castPair(at, sexpr);

    return .{ pair.car, pair.cdr };
}

pub fn castList(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!*SExpr.Types.Cons {
    if (sexpr.castCons()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a list, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castFunction(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!*SExpr.Types.Function {
    if (sexpr.castFunction()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a function, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castBuiltin(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!*SExpr.Types.Builtin {
    if (sexpr.castBuiltin()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a Builtin, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castExternData(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!*SExpr.Types.ExternData {
    if (sexpr.castExternData()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected an ExternData, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn castExternDataPtr(interpreter: *Interpreter, comptime T: type, at: *const Source.Attr, sexpr: SExpr) Error!*T {
    const externData = try interpreter.castExternData(at, sexpr);

    return externData.castPtr(T) orelse {
        return interpreter.abort(Error.TypeError, at,
            "expected an ExternData of type {s}, got {s}", .{ @typeName(T), externData.typeNameSlice() });
    };
}

pub fn castExternFunction(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!*SExpr.Types.ExternFunction {
    if (sexpr.castExternFunction()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected an ExternFunction, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn coerceNativeInt(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!i64 {
    if (sexpr.coerceNativeInt()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a number, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn coerceNativeFloat(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!f64 {
    if (sexpr.coerceNativeFloat()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a number, got {}: `{}", .{ sexpr.getTag(), sexpr });
    }
}

pub fn coerceNativeChar(interpreter: *Interpreter, at: *const Source.Attr, sexpr: SExpr) Error!TextUtils.Char {
    if (sexpr.coerceNativeChar()) |x| {
        return x;
    } else {
        return interpreter.abort(Error.TypeError, at,
            "expected a Char, got {}: `{}`", .{ sexpr.getTag(), sexpr });
    }
}

pub fn errorToException(interpreter: *Interpreter, at: *const Source.Attr, err: anyerror) Result!SExpr {
    return interpreter.nativePrompt(at, "exception", &[_]SExpr {try SExpr.Symbol(at, @errorName(err))});
}

pub inline fn argIterator(interpreter: *Interpreter, shouldEval: bool, args: SExpr) Result!ArgIterator {
    return ArgIterator.init(interpreter, shouldEval, args);
}

pub const ArgIterator = struct {
    interpreter: *Interpreter,
    at: *const Source.Attr,
    shouldEval: bool,
    tail: SExpr,
    index: usize,

    pub fn init(interpreter: *Interpreter, shouldEval: bool, args: SExpr) Result!ArgIterator {
        const at = args.getAttr();
        if (args.isNil() or args.isCons()) {
            return .{
                .interpreter = interpreter,
                .at = at,
                .shouldEval = shouldEval,
                .tail = args,
                .index = 0,
            };
        } else {
            return interpreter.abort(Error.TypeError, at,
                "expected an argument list, got {}: `{}`", .{ args.getTag(), args });
        }
    }

    pub fn next(self: *ArgIterator) Result!?SExpr {
        if (self.tail.isNil()) {
            return null;
        }

        const xp = try self.interpreter.castList(self.at, self.tail);

        self.index += 1;

        self.tail = xp.cdr;

        return if (self.shouldEval) try self.interpreter.eval(xp.car) else xp.car;
    }

    pub fn atLeast(self: *ArgIterator) Result!SExpr {
        const arg = try self.next();

        if (arg) |a| {
            return a;
        } else {
            return self.interpreter.abort(Error.NotEnoughArguments, self.at,
                "expected at least {} argument(s)", .{self.index + 1});
        }
    }

    pub fn hasNext(self: *ArgIterator) bool {
        return !self.tail.isNil();
    }

    pub fn assertDone(self: *ArgIterator) Result!void {
        if (!self.tail.isNil()) {
            if (self.tail.isCons()) {
                return self.interpreter.abort(Error.TooManyArguments, self.at,
                    "expected at most {} arguments, got {}", .{ self.index, self.index + 1 });
            } else {
                return self.interpreter.abort(Error.TypeError, self.at,
                    "expected an argument list, got {}: `{}`", .{ self.tail.getTag(), self.tail });
            }
        }
    }

    pub fn nextWithIndex(self: *ArgIterator) Result!?struct { SExpr, usize } {
        const i = self.index;
        return .{ try self.next() orelse return null, i };
    }
};

pub fn expect0(interpreter: *Interpreter, args: SExpr) Result!void {
    if (!args.isNil()) {
        if (args.isCons()) {
            return interpreter.abort(Error.TooManyArguments, args.getAttr(), "expected no arguments, got: `{}`", .{args});
        } else {
            return interpreter.abort(Error.TypeError, args.getAttr(), "expected an empty argument list, got {}: `{}`", .{ args.getTag(), args });
        }
    }
}

pub fn expectN(interpreter: *Interpreter, comptime N: usize, args: SExpr) Result![N]SExpr {
    var eArgs = [1]SExpr{ undefined } ** N;
    _ = try interpreter.expectSmallList(args, N, &eArgs);
    return eArgs;
}

pub fn expectAtLeastN(interpreter: *Interpreter, comptime N: usize, args: SExpr) Result!struct { head: [N]SExpr, tail: SExpr } {
    var eArgs = [1]SExpr{ undefined } ** N;
    const tail = try interpreter.expectSmallListAtLeast(args, &eArgs);
    return .{ .head = eArgs, .tail = tail };
}


pub fn expectMaybe1(interpreter: *Interpreter, args: SExpr) Result!?SExpr {
    var eArgs = [1]SExpr{undefined};
    const len = try interpreter.expectSmallList(args, 0, &eArgs);
    return if (len == 1) return eArgs[0] else null;
}

pub fn evalMaybe1(interpreter: *Interpreter, args: SExpr) Result!?SExpr {
    var eArgs = [1]SExpr{undefined};
    const len = try interpreter.expectSmallList(args, 0, &eArgs);
    return if (len == 1) return try interpreter.eval(eArgs[0]) else null;
}


pub fn evalN(interpreter: *Interpreter, comptime N: usize, args: SExpr) Result![N]SExpr {
    var eArgs = [1]SExpr{ undefined } ** N;
    _ = try interpreter.evalSmallList(args, N, &eArgs);
    return eArgs;
}


pub fn evalAtLeastN(interpreter: *Interpreter, comptime N: usize, args: SExpr) Result!struct { head: [N]SExpr, tail: SExpr } {
    var eArgs = [1]SExpr{ undefined } ** N;
    const tail = try interpreter.evalSmallListAtLeast(args, &eArgs);
    return .{ .head = eArgs, .tail = tail };
}

pub fn expectSmallListOf(interpreter: *Interpreter, sexpr: SExpr, minLength: usize, buf: []SExpr, comptime expected: []const u8, comptime predicate: fn (SExpr) bool) Result!usize {
    var tail = sexpr;
    var i: usize = 0;

    while (!tail.isNil()) {
        const cons = (tail.castCons() orelse {
            return interpreter.abort(Error.TypeError, tail.getAttr(), "expected a list, got {}", .{tail.getTag()});
        });

        tail = cons.cdr;

        const elem = cons.car;

        if (!@call(.always_inline, predicate, .{elem})) {
            return interpreter.abort(Error.TypeError, tail.getAttr(), "expected {s}, got {}", .{ expected, elem.getTag() });
        }

        if (i < buf.len) {
            buf[i] = elem;
        }

        i += 1;
    }

    if (minLength == 0 and i == 0) {
        if (!tail.isNil()) {
            return interpreter.abort(Error.TypeError, tail.getAttr(), "expected a list, got {}", .{tail.getTag()});
        }
    }

    if (i > buf.len) {
        return interpreter.abort(Error.TooManyArguments, sexpr.getAttr(), "expected at most {} arguments, got {}", .{ buf.len, i });
    }

    if (i < minLength) {
        return interpreter.abort(Error.NotEnoughArguments, sexpr.getAttr(), "expected at least {} arguments, got {}", .{ minLength, i });
    }

    return i;
}

pub fn expectSmallListOfAtLeast(interpreter: *Interpreter, sexpr: SExpr, buf: []SExpr, comptime expected: []const u8, comptime predicate: fn (SExpr) bool) Result!SExpr {
    var tail = sexpr;
    var i: usize = 0;

    while (!tail.isNil() and i < buf.len) {
        const cons = (tail.castCons() orelse {
            return interpreter.abort(Error.TypeError, tail.getAttr(), "expected a list, got {}", .{tail.getTag()});
        });

        tail = cons.cdr;

        const elem = cons.car;

        if (!@call(.always_inline, predicate, .{elem})) {
            return interpreter.abort(Error.TypeError, elem.getAttr(), "expected {s}, got {}", .{ expected, elem.getTag() });
        }

        buf[i] = elem;
        i += 1;
    }

    if (i < buf.len) {
        return interpreter.abort(Error.NotEnoughArguments, sexpr.getAttr(), "expected at least {} arguments, got {}", .{ buf.len, i });
    }

    return tail;
}

pub fn evalSmallListAtLeast(interpreter: *Interpreter, sexpr: SExpr, buf: []SExpr) Result!SExpr {
    const tail = try interpreter.expectSmallListAtLeast(sexpr, buf);
    for (0..buf.len) |i| {
        buf[i] = try interpreter.eval(buf[i]);
    }
    return tail;
}

pub fn expectSmallListAtLeast(interpreter: *Interpreter, sexpr: SExpr, buf: []SExpr) Result!SExpr {
    return expectSmallListOfAtLeast(interpreter, sexpr, buf, "", passAll);
}

fn passAll(_: SExpr) bool {
    return true;
}

pub fn evalSmallList(interpreter: *Interpreter, sexpr: SExpr, minLength: usize, buf: []SExpr) Result!usize {
    const len = try expectSmallList(interpreter, sexpr, minLength, buf);
    for (0..len) |i| {
        buf[i] = try interpreter.eval(buf[i]);
    }
    return len;
}

pub fn expectSmallList(interpreter: *Interpreter, sexpr: SExpr, minLength: usize, buf: []SExpr) Result!usize {
    return expectSmallListOf(interpreter, sexpr, minLength, buf, "", passAll);
}
