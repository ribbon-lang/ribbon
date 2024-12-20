const std = @import("std");

const procedure = @import("procedure.zig");

const Rli = @import("../root.zig");
const Source = Rli.Source;
const SExpr = Rli.SExpr;
const Interpreter = Rli.Interpreter;

pub const Doc =
    \\This module provides special forms for defining and manipulating
    \\bindings in the current environment.
    \\
    \\`let` creates a new environment frame with the given bindings,
    \\and evaluates the body in that frame.
    \\> ##### Example
    \\> ```lisp
    \\> (let ((x (+ 1 1))
    \\>       (fun f (x) (+ x 1))
    \\>       (macro m (x) `(f ,x)))
    \\>   (action1 x)
    \\>   (action2 (f x))
    \\>   (action3 (m x)))
    \\> ```
    \\
    \\`def`, `def fun`, and `def macro` forms mirror the syntax of `let`,
    \\but bind individual symbols in the current environment.
    \\> ##### Example
    \\> ```lisp
    \\> (def x (+ 1 1))
    \\> (def fun f (x) (+ x 1))
    \\> (action1 x)
    \\> (action2 (f x))
    \\> ```
    \\
    \\`bound?` and `set!` can be used to query and manipulate
    \\bindings created with any of the above forms.
    \\
;

pub const Decls = .{
    .{ "def", "define a new variable", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            try bindDef(interpreter, at, args, struct {
                fn fun(i: *Interpreter, attr: *const Source.Attr, name: SExpr, obj: SExpr) Interpreter.Result!void {
                    try Interpreter.extendEnvFrame(attr, name, obj, i.env);
                }
            }.fun);
            return SExpr.Nil(at);
        }
    } },
    .{ "let", "create local value bindings", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const res = try interpreter.expectAtLeastN(1, args);
            const defs = res.head[0];
            const body = res.tail;
            const baseEnv = interpreter.env;
            try Interpreter.pushNewFrame(at, &interpreter.env);
            defer interpreter.env = baseEnv;
            try bindDefs(interpreter, defs, struct {
                fn fun(i: *Interpreter, attr: *const Source.Attr, name: SExpr, obj: SExpr) Interpreter.Result!void {
                    try Interpreter.extendEnvFrame(attr, name, obj, i.env);
                }
            }.fun);
            return try interpreter.runProgram(body);
        }
    } },
    .{ "bound?", "check if a given symbol is bound in the current env", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const symbol = (try interpreter.expectN(1, args))[0];
            try interpreter.validateSymbol(at, symbol);
            return try SExpr.Bool(at, try Interpreter.envLookupPair(symbol, interpreter.env) != null);
        }
    } },
    .{ "set!", "set the value of a symbol in the current env. symbol must already be bound. returns old value", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const buf = try interpreter.expectN(2, args);
            const symbol = buf[0];
            try interpreter.validateSymbol(at, symbol);
            const value = try interpreter.eval(buf[1]);
            if (try Interpreter.envLookupPair(symbol, interpreter.env)) |pair| {
                const xp = pair.forceCons();
                const out = xp.cdr;
                xp.cdr = value;
                return out;
            } else {
                return interpreter.abort(Interpreter.Error.UnboundSymbol, at, "cannot set unbound symbol `{}`", .{symbol});
            }
        }
    } },
};

pub const DefKind = enum {
    Fun,
    Macro,
    Var,

    pub fn matchSymbol(kindSymbol: SExpr) DefKind {
        const kStr = if (kindSymbol.castSymbolSlice()) |s| s else return .Var;
        return if (std.mem.eql(u8, kStr, "fun")) .Fun else if (std.mem.eql(u8, kStr, "macro")) .Macro else .Var;
    }

    pub fn constructObject(self: DefKind, interpreter: *Interpreter, at: *const Source.Attr, def: SExpr) Interpreter.Result!SExpr {
        return switch (self) {
            .Fun => procedure.function(interpreter, at, .Lambda, def),
            .Macro => procedure.function(interpreter, at, .Macro, def),
            .Var => interpreter.runProgram(def),
        };
    }
};

pub fn bindDefs(interpreter: *Interpreter, defs: SExpr, comptime bind: fn (*Interpreter, *const Source.Attr, SExpr, SExpr) Interpreter.Result!void) Interpreter.Result!void {
    var iter = try interpreter.argIterator(false, defs);

    while (try iter.next()) |info| try bindDef(interpreter, info.getAttr(), info, bind);
}

pub fn bindDef(interpreter: *Interpreter, at: *const Source.Attr, info: SExpr, comptime bind: fn (*Interpreter, *const Source.Attr, SExpr, SExpr) Interpreter.Result!void) Interpreter.Result!void {
    var res = try interpreter.expectAtLeastN(1, info);

    switch (DefKind.matchSymbol(res.head[0])) {
        .Fun => {
            try interpreter.validateSymbol(res.head[0].getAttr(), res.head[0]);
            res = try interpreter.expectAtLeastN(1, res.tail);

            const obj = try procedure.function(interpreter, at, .Lambda, res.tail);
            return bind(interpreter, at, res.head[0], obj);
        },
        .Macro => {
            try interpreter.validateSymbol(res.head[0].getAttr(), res.head[0]);
            res = try interpreter.expectAtLeastN(1, res.tail);

            const obj = try procedure.function(interpreter, at, .Macro, res.tail);
            return bind(interpreter, at, res.head[0], obj);
        },
        .Var => {
            switch (try Interpreter.PatternRich.run(interpreter, res.head[0].getAttr(), res.head[0], try interpreter.runProgram(res.tail))) {
                .Okay => |frame| {
                    var it = frame.iter();
                    while (try it.next()) |pair| {
                        const xp = pair.forceCons();
                        try bind(interpreter, at, xp.car, xp.cdr);
                    }
                    return;
                },
                else => |err| {
                    return interpreter.abort(error.TypeError, at, "{}", .{err});
                },
            }
        }
    }
}
