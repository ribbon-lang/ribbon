const std = @import("std");

const MiscUtils = @import("Utils").Misc;

const Rli = @import("../root.zig");
const Source = Rli.Source;
const SExpr = Rli.SExpr;
const Interpreter = Rli.Interpreter;

const arithmetic = @import("arithmetic.zig");

pub const Doc =
    \\This module provides special forms for controlling the flow of execution.
    \\
    \\`if` is a one or two option conditional branch.
    \\> ##### Example
    \\> ```lisp
    \\> (if x (conditional-action))
    \\> (if y (conditional-action) (else-action))
    \\> ```
    \\
    \\`cond` is a multi-option conditional branch.
    \\> ##### Example
    \\> ```lisp
    \\> (cond
    \\>   (x (conditional-action1))
    \\>   (y (conditional-action2))
    \\>   (else (default-action)))
    \\> ```
    \\
    \\`match` uses lambda lists to perform structural pattern matching on an input.
    \\> ##### Example
    \\> ```lisp
    \\> (match x
    \\>   ((0) (conditional-action0))
    \\>   ((x) (conditional-action1 x))
    \\>   ((x y) (conditional-action2 x y))
    \\>   ((x y . z) (conditional-action3 x y z))
    \\>   (else (default-action)))
    \\> ```
    \\For more information on the syntax of lambda lists, see the [`Pattern` module](#pattern).
    \\
    \\`do` allows for sequencing expressions.
    \\> ##### Example
    \\> ```lisp
    \\> (do
    \\>   (action1)
    \\>   (action2))
    \\> ```
;

pub const Decls = .{
    .{ "for", "runs an inner loop with a number in a given range; ie `(for (x [ITERATOR]) print-ln(x))` where `[ITERATOR]` can be anything suiting the pattern `(.. a? b)|(..= a? b) incr?`; `break` and `continue` effects are available in the body", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            Rli.log.debug("for start", .{});
            const xArgs = try interpreter.expectAtLeastN(1, args);
            const loopArgs = try interpreter.expectAtLeastN(2, xArgs.head[0]);
            const varName = loopArgs.head[0];
            try interpreter.validateSymbol(at, varName);
            const range = try interpreter.expectAtLeastN(2, loopArgs.head[1]);
            const rangeKind = range.head[0].to(enum { @"..", @"..=" }) catch |err| {
                return interpreter.abort(err, range.head[0].getAttr(), "expected range kind `..` or `..=`", .{});
            };
            const pole1 = try interpreter.eval(range.head[1]);
            try interpreter.validateNumber(range.head[1].getAttr(), pole1);

            const AB = struct { SExpr, SExpr };
            const a, const b = if (range.tail.castCons()) |xp| range: {
                Rli.log.debug("custom range start", .{});
                const end = try interpreter.eval(xp.car);
                try interpreter.validateNumber(xp.car.getAttr(), end);
                break :range AB{ pole1, end };
            } else range: {
                Rli.log.debug("default range start", .{});
                try interpreter.validateNil(range.tail.getAttr(), range.tail);
                break :range AB{ try SExpr.Int(range.tail.getAttr(), 0), pole1 };
            };

            const incr = if (loopArgs.tail.castCons()) |xp| incr: {
                Rli.log.debug("custom incr", .{});
                const incr = try interpreter.eval(xp.car);
                try interpreter.validateNumber(xp.car.getAttr(), incr);
                try interpreter.validateNil(xp.cdr.getAttr(), xp.cdr);
                break :incr incr;
            } else def: {
                Rli.log.debug("default incr", .{});
                try interpreter.validateNil(loopArgs.tail.getAttr(), loopArgs.tail);
                break :def try SExpr.Int(loopArgs.tail.getAttr(), 1);
            };

            const body = xArgs.tail;

            var i = a;

            Rli.log.debug("for loop start {} {} {} {}", .{varName, i, b, incr});

            var out = try SExpr.Nil(at);

            while (switch (rangeKind) {
                .@".." => MiscUtils.less(i, b),
                .@"..=" => MiscUtils.lessOrEqual(i, b),
            }) : (i = try arithmetic.castedBinOp(.add, interpreter, loopArgs.head[1].getAttr(), i, incr)) {
                Rli.log.debug("for loop step {i}", .{i});

                const env = interpreter.env;
                defer interpreter.env = env;

                try Interpreter.pushNewFrame(body.getAttr(), &interpreter.env);
                try Interpreter.extendEnvFrame(varName.getAttr(), varName, i, interpreter.env);

                var nativeOut: Interpreter.NativeWithOut = undefined;

                Rli.log.debug("for loop body start {}", .{body});

                try interpreter.nativeWith(body.getAttr(), body, &nativeOut, struct {
                    pub fn @"break"(interp: *Interpreter, att: *const Source.Attr, xs: SExpr) !SExpr {
                        Rli.log.debug("for loop break", .{});
                        const eArgs = try interp.expectN(1, xs);
                        const terminator = eArgs[0];
                        return interp.nativeInvoke(att, terminator, &[_]SExpr {try SExpr.Symbol(att, "break")});
                    }

                    pub fn @"continue"(interp: *Interpreter, att: *const Source.Attr, xs: SExpr) !SExpr {
                        Rli.log.debug("for loop continue", .{});
                        const eArgs = try interp.expectN(1, xs);
                        const terminator = eArgs[0];
                        return interp.nativeInvoke(att, terminator, &[_]SExpr {try SExpr.Symbol(att, "continue")});
                    }
                });

                Rli.log.debug("for loop body end", .{});

                switch (nativeOut) {
                    .Evaluated => |res| {
                        Rli.log.debug("for loop evaluated step {}", .{i});
                        out = res;
                    },
                    .Terminated => |sym| {
                        Rli.log.debug("terminated {}", .{sym});
                        const symStr = try interpreter.castSymbolSlice(at, sym);
                        if (std.mem.eql(u8, symStr, "break")) { break; }
                        else if (std.mem.eql(u8, symStr, "continue")) { continue; }
                        else return interpreter.abort(Interpreter.Error.InvalidContext, sym.getAttr(), "expected `break` or `continue`, got `{s}`", .{sym});
                    }
                }
            }

            return out;
        }
    } },
    .{ "if", "two-option conditional branch", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var buf = [3]SExpr{ undefined, undefined, undefined };
            const len = try interpreter.expectSmallList(args, 2, &buf);
            const cond = buf[0];
            const then = buf[1];
            const els: ?SExpr = if (len == 3) buf[2] else null;
            const condval = try interpreter.eval(cond);
            if (condval.coerceNativeBool()) {
                return try interpreter.eval(then);
            } else if (els) |elsx| {
                return try interpreter.eval(elsx);
            } else {
                return try SExpr.Nil(at);
            }
        }
    } },
    .{ "when", "single-option conditional branch, taken if the condition is true", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const eArgs = try interpreter.evalAtLeastN(1, args);
            const cond = eArgs.head[0];
            const then = eArgs.tail;
            if (cond.coerceNativeBool()) {
                return try interpreter.runProgram(then);
            } else {
                return try SExpr.Nil(at);
            }
        }
    } },
    .{ "unless", "single-option conditional branch, taken if the condition is false", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const eArgs = try interpreter.evalAtLeastN(1, args);
            const cond = eArgs.head[0];
            const then = eArgs.tail;
            if (!cond.coerceNativeBool()) {
                return try interpreter.runProgram(then);
            } else {
                return try SExpr.Nil(at);
            }
        }
    } },
    .{ "cond", "multi-option conditional branch", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var eArgs = try interpreter.argIterator(false, args);
            while (try eArgs.next()) |seg| {
                const buf = try interpreter.expectAtLeastN(1, seg);
                const cond = buf.head[0];
                const then = buf.tail;
                const condval = if (cond.isExactSymbol("else")) {
                    if (eArgs.hasNext()) {
                        return interpreter.abort(Interpreter.Error.TooManyArguments, at, "expected else to be the last cond clause", .{});
                    }
                    return try interpreter.runProgram(then);
                } else try interpreter.eval(cond);
                if (condval.coerceNativeBool()) {
                    return try interpreter.runProgram(then);
                }
            }
            return try SExpr.Nil(at);
        }
    } },
    .{ "match", "pattern based matching on any inputt", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const res = try interpreter.evalAtLeastN(1, args);
            const scrutinee = res.head[0];
            const cases = res.tail;
            var eArgs = try interpreter.argIterator(false, cases);
            while (try eArgs.next()) |x| {
                const case = try interpreter.expectAtLeastN(1, x);
                const lList = case.head[0];
                const then = case.tail;
                if (lList.isExactSymbol("else")) {
                    Rli.log.debug("Running else {}", .{then});
                    if (eArgs.hasNext()) {
                        return interpreter.abort(Interpreter.Error.TooManyArguments, at, "expected else to be the last match case", .{});
                    }
                    return try interpreter.runProgram(then);
                }
                Rli.log.debug("Running llist {} on {}", .{lList, scrutinee});
                switch (try Interpreter.PatternLite.run(interpreter, lList.getAttr(), lList, scrutinee)) {
                    .Okay => |frame| {
                        Rli.log.debug("llist Okay", .{});
                        try Interpreter.pushFrame(frame, &interpreter.env);
                        defer _ = Interpreter.popFrame(&interpreter.env) catch unreachable;
                        return try interpreter.runProgram(then);
                    },
                    else => {
                        Rli.log.debug("llist Fail", .{});
                    },
                }
            }
            return SExpr.Nil(at);
        }
    } },
    .{ "do", "allows sequencing expressions", struct {
        pub fn fun(interpreter: *Interpreter, _: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            return try interpreter.runProgram(args);
        }
    } },

    .{ "panic", "runs `format` on the values provided and then triggers a panic with the resulting string", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var eArgs = try interpreter.argIterator(true, args);
            var out = std.ArrayList(u8).init(interpreter.context.allocator);
            defer out.deinit();
            const writer = out.writer();
            var i: usize = 0;
            while (try eArgs.next()) |next| {
                try writer.print("{display}", .{next});
                i += 1;
            }
            return interpreter.abort(Interpreter.Error.Panic, at, "{s}", .{try out.toOwnedSlice()});
        }
    } },
    .{ "panic-at", "uses the first argument as the source attribution for the panic; runs `format` on subsequent values provided and then triggers a panic with the resulting string", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var eArgs = try interpreter.argIterator(true, args);
            const fst = try eArgs.atLeast();
            const eat = try interpreter.castExternDataPtr(Source.Attr, at, fst);
            var out = std.ArrayList(u8).init(interpreter.context.allocator);
            defer out.deinit();
            const writer = out.writer();
            while (try eArgs.next()) |next| {
                try writer.print("{display}", .{next});
            }
            return interpreter.abort(Interpreter.Error.Panic, eat, "{s}", .{try out.toOwnedSlice()});
        }
    } },
    .{ "throw", "prompts `exception` with the value provided; this is a shortcut for `(prompt exception arg)`", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const msg = (try interpreter.evalN(1, args))[0];
            return interpreter.nativePrompt(at, "exception", &[1]SExpr{msg});
        }
    } },
    .{ "stop", "prompts `fail`; this is a shortcut for `(prompt fail)`", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, _: SExpr) Interpreter.Result!SExpr {
            Rli.log.debug("stop", .{});
            return interpreter.nativePrompt(at, "fail", &[0]SExpr{});
        }
    } },
    .{ "assert", "asserts that a condition is true; if it is not, triggers a panic with the subsequent arguments, or with the condition itself if none were provided", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const eArgs = try interpreter.evalAtLeastN(1, args);
            const cond = eArgs.head[0];
            if (cond.coerceNativeBool()) {
                return try SExpr.Nil(at);
            } else {
                var it = try interpreter.argIterator(true, eArgs.tail);
                if (!it.hasNext()) {
                    try it.assertDone();
                    return interpreter.abort(Interpreter.Error.Panic, at, "assert failed: {display}", .{args});
                } else {
                    var out = std.ArrayList(u8).init(interpreter.context.allocator);
                    defer out.deinit();
                    const writer = out.writer();
                    while (try it.next()) |next| {
                        try writer.print("{display}", .{next});
                    }
                    return interpreter.abort(Interpreter.Error.Panic, at, "assert failed: {s}", .{try out.toOwnedSlice()});
                }
            }
        }
    } },
    .{ "assert-eq", "asserts that the first two values provided are equal, using structural equality on objects; if they are not, triggers a panic with any subsequent values provided, or with the condition if none were", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const eArgs = try interpreter.expectAtLeastN(2, args);
            const a = try interpreter.eval(eArgs.head[0]);
            const b = try interpreter.eval(eArgs.head[1]);
            if (MiscUtils.equal(a, b)) {
                return try SExpr.Nil(at);
            } else {
                var it = try interpreter.argIterator(true, eArgs.tail);
                if (!it.hasNext()) {
                    try it.assertDone();
                    return interpreter.abort(Interpreter.Error.Panic, at,
                        "assert-eq failed:\n\ta: {} = {}\n\tb: {} = {}",
                        .{eArgs.head[0], a, eArgs.head[1], b});
                } else {
                    var out = std.ArrayList(u8).init(interpreter.context.allocator);
                    defer out.deinit();
                    const writer = out.writer();
                    while (try it.next()) |next| {
                        try writer.print("{display}", .{next});
                    }
                    return interpreter.abort(Interpreter.Error.Panic, at, "assert-eq failed: {s}", .{try out.toOwnedSlice()});
                }
            }
        }
    } },
    .{ "assert-eq-addr", "asserts that the first two values provided are equal, using address equality on objects; if they are not, triggers a panic with any subsequent values provided, or with the condition if none were", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const eArgs = try interpreter.expectAtLeastN(2, args);
            const a = try interpreter.eval(eArgs.head[0]);
            const b = try interpreter.eval(eArgs.head[1]);
            if (MiscUtils.equalAddress(a, b)) {
                return try SExpr.Nil(at);
            } else {
                var it = try interpreter.argIterator(true, eArgs.tail);
                if (!it.hasNext()) {
                    try it.assertDone();
                    return interpreter.abort(Interpreter.Error.Panic, at,
                        "assert-eq-addr failed:\n\ta: {} = {}\n\tb: {} = {}",
                        .{eArgs.head[0], a, eArgs.head[1], b});
                } else {
                    var out = std.ArrayList(u8).init(interpreter.context.allocator);
                    defer out.deinit();
                    const writer = out.writer();
                    while (try it.next()) |next| {
                        try writer.print("{display}", .{next});
                    }
                    return interpreter.abort(Interpreter.Error.Panic, at, "assert-eq-addr failed: {s}", .{try out.toOwnedSlice()});
                }
            }
        }
    } },
    .{ "assert-at", "asserts that a condition is true; if it is not, triggers a panic with the subsequent arguments, or with the condition itself if none were provided", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const eArgs0 = try interpreter.evalAtLeastN(1, args);
            const eat = try interpreter.castExternDataPtr(Source.Attr, at, eArgs0.head[0]);
            const eCondInput = try interpreter.expectAtLeastN(1, eArgs0.tail);
            const cond = try interpreter.eval(eCondInput.head[0]);
            const tail = eCondInput.tail;
            if (cond.coerceNativeBool()) {
                return try SExpr.Nil(at);
            } else {
                var it = try interpreter.argIterator(true, tail);
                if (!it.hasNext()) {
                    try it.assertDone();
                    return interpreter.abort(Interpreter.Error.Panic, eat, "assert failed: {}", .{eCondInput.head[0]});
                } else {
                    var out = std.ArrayList(u8).init(interpreter.context.allocator);
                    defer out.deinit();
                    const writer = out.writer();
                    while (try it.next()) |next| {
                        try writer.print("{display}", .{next});
                    }
                    return interpreter.abort(Interpreter.Error.Panic, eat, "assert failed: {s}", .{try out.toOwnedSlice()});
                }
            }
        }
    } },
    .{ "assert-eq-at", "asserts that the first two values provided are equal, using structural equality on objects; if they are not, triggers a panic with any subsequent values provided, or with the equality inputs if none were", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const eArgs0 = try interpreter.evalAtLeastN(1, args);
            const eat = try interpreter.castExternDataPtr(Source.Attr, at, eArgs0.head[0]);
            const eEqInputs = try interpreter.expectAtLeastN(2, eArgs0.tail);
            const rEqInputs = [2]SExpr{ try interpreter.eval(eEqInputs.head[0]), try interpreter.eval(eEqInputs.head[1]) };
            const tail = eEqInputs.tail;
            if (MiscUtils.equal(rEqInputs[0], rEqInputs[1])) {
                return try SExpr.Nil(at);
            } else {
                var it = try interpreter.argIterator(true, tail);
                if (!it.hasNext()) {
                    try it.assertDone();
                    return interpreter.abort(Interpreter.Error.Panic, eat, "assert-eq failed: ({} {})", .{ eEqInputs.head[0], eEqInputs.head[1] });
                } else {
                    var out = std.ArrayList(u8).init(interpreter.context.allocator);
                    defer out.deinit();
                    const writer = out.writer();
                    while (try it.next()) |next| {
                        try writer.print("{display}", .{next});
                    }
                    return interpreter.abort(Interpreter.Error.Panic, eat, "assert-eq failed: {s}", .{try out.toOwnedSlice()});
                }
            }
        }
    } },
    .{ "assert-eq-addr-at", "asserts, using the location provided as the first argument, that the next two values provided are equal, using address equality on objects; if they are not, triggers a panic with any subsequent values provided, or with the equality inputs if none were", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const eArgs0 = try interpreter.evalAtLeastN(1, args);
            const eat = try interpreter.castExternDataPtr(Source.Attr, at, eArgs0.head[0]);
            const eEqInputs = try interpreter.expectAtLeastN(2, eArgs0.tail);
            const rEqInputs = [2]SExpr{ try interpreter.eval(eEqInputs.head[0]), try interpreter.eval(eEqInputs.head[1]) };
            const tail = eEqInputs.tail;
            if (MiscUtils.equalAddress(rEqInputs[0], rEqInputs[1])) {
                return try SExpr.Nil(at);
            } else {
                var it = try interpreter.argIterator(true, tail);
                if (!it.hasNext()) {
                    try it.assertDone();
                    return interpreter.abort(Interpreter.Error.Panic, eat, "assert-eq-addr failed: ({} {})", .{ eEqInputs.head[0], eEqInputs.head[1] });
                } else {
                    var out = std.ArrayList(u8).init(interpreter.context.allocator);
                    defer out.deinit();
                    const writer = out.writer();
                    while (try it.next()) |next| {
                        try writer.print("{display}", .{next});
                    }
                    return interpreter.abort(Interpreter.Error.Panic, eat, "assert-eq-addr failed: {s}", .{try out.toOwnedSlice()});
                }
            }
        }
    } },
    .{ "e-assert", "asserts that a condition is true; if it is not, prompts `exception` with the second value provided or with the symbol `AssertionFailed` if one is not", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var buf = [2]SExpr{ undefined, undefined };
            const len = try interpreter.evalSmallList(args, 1, &buf);
            const cond = buf[0];
            const msg =
                if (len == 2) buf[1] else try SExpr.Symbol(at, "AssertionFailed");
            if (cond.coerceNativeBool()) {
                return try SExpr.Nil(at);
            } else {
                return interpreter.nativePrompt(at, "exception", &[1]SExpr{msg});
            }
        }
    } },
    .{ "e-assert-eq", "asserts that the first two values provided are equal, using structural equality on objects; if they are not, prompts `exception` with any subsequent values provided, or with the condition if none were", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var buf = [3]SExpr{ undefined, undefined, undefined };
            const len = try interpreter.evalSmallList(args, 2, &buf);
            const a = buf[0];
            const b = buf[1];
            const msg =
                if (len == 3) buf[2] else try SExpr.Symbol(at, "AssertionFailed");
            if (MiscUtils.equal(a, b)) {
                return try SExpr.Nil(at);
            } else {
                return interpreter.nativePrompt(at, "exception", &[1]SExpr{msg});
            }
        }
    } },
    .{ "e-assert-eq-addr", "asserts that the first two values provided are equal, using address equality on objects; if they are not, prompts `exception` with any subsequent values provided, or with the condition if none were", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var buf = [3]SExpr{ undefined, undefined, undefined };
            const len = try interpreter.evalSmallList(args, 2, &buf);
            const a = buf[0];
            const b = buf[1];
            const msg =
                if (len == 3) buf[2] else try SExpr.Symbol(at, "AssertionFailed");
            if (MiscUtils.equalAddress(a, b)) {
                return try SExpr.Nil(at);
            } else {
                return interpreter.nativePrompt(at, "exception", &[1]SExpr{msg});
            }
        }
    } },
    .{ "f-assert", "asserts that a condition is true; if it is not, prompts `fail`", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const cond = (try interpreter.evalN(1, args))[0];
            if (cond.coerceNativeBool()) {
                return try SExpr.Nil(at);
            } else {
                return interpreter.nativePrompt(at, "fail", &[0]SExpr{});
            }
        }
    } },
    .{ "f-assert-eq", "asserts that the two values provided are equal, using structural equality on objects; if they are not, prompts `fail`", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const buf = try interpreter.evalN(2, args);
            const a = buf[0];
            const b = buf[1];
            if (MiscUtils.equal(a, b)) {
                return try SExpr.Nil(at);
            } else {
                return interpreter.nativePrompt(at, "fail", &[0]SExpr{});
            }
        }
    } },
    .{ "f-assert-eq-addr", "asserts that the two values provided are equal, using address equality on objects; if they are not, prompts `fail`", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const buf = try interpreter.evalN(2, args);
            const a = buf[0];
            const b = buf[1];
            if (MiscUtils.equalAddress(a, b)) {
                return try SExpr.Nil(at);
            } else {
                return interpreter.nativePrompt(at, "fail", &[0]SExpr{});
            }
        }
    } },
};
