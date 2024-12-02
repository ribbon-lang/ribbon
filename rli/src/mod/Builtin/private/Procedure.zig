const std = @import("std");

const MiscUtils = @import("Utils").Misc;

const Core = @import("Core");
const Source = Core.Source;
const SExpr = Core.SExpr;
const Interpreter = Core.Interpreter;

pub const Doc =
    \\This module provides the primitive `fun` and `macro` special forms,
    \\which can be used anywhere to create closure-binding procedural abstractions.
    \\
    \\The only difference between `fun` and `macro` is the timing of evaluation:
    \\+ `fun` evaluates its arguments at the time of invocation,
    \\  and evaluates its return value in its own environment.
    \\+ `macro` does not evaluate its arguments,
    \\  and evaluates its return value in the environment of the caller.
    \\
    \\> ##### Example
    \\> ```lisp
    \\> (fun (x y) (+ x y))
    \\> ```
    \\> ```lisp
    \\> (macro (x y) `(+ ,x ,y))
    \\> ```
;

pub const Env = .{
    .{ "fun", "inline function definition", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            return function(interpreter, at, .Lambda, args);
        }
    } },
    .{ "macro", "inline macro definition", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            return function(interpreter, at, .Macro, args);
        }
    } },
    .{ "apply", "apply a function to a list of arguments", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rArgs = try interpreter.eval2(args);
            return try interpreter.nativeInvoke(at, rArgs[0], rArgs[1]);
        }
    } },
};

pub fn function(interpreter: *Interpreter, at: *const Source.Attr, kind: SExpr.Types.Function.Kind, args: SExpr) Interpreter.Result!SExpr {
    const rArgs = try interpreter.expectAtLeast1(args);
    try Interpreter.LambdaListRich.validate(interpreter, rArgs.head);
    return try SExpr.Function(at, kind, rArgs.head, interpreter.env, rArgs.tail);
}
