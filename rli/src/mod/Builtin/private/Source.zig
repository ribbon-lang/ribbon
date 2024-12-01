const std = @import("std");

const Extern = @import("Utils").Extern;
const MiscUtils = @import("Utils").Misc;
const Core = @import("Core");
const Source = Core.Source;
const SExpr = Core.SExpr;
const Interpreter = Core.Interpreter;

pub const Doc =
    \\This module provides functions for the creation, access and transformation
    \\of source-attribution primitives.
    \\
;

pub const Env = .{
    .{ "attr-here", "create a source attribution referencing the call location", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            try interpreter.expect0(args);
            return ExternAttr(at, at);
        }
    } },
    .{ "attr-filename", "get the filename stored in an Attr", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const arg = try interpreter.eval1(args);
            const attr: *const Source.Attr = try interpreter.castExternDataPtr(Source.Attr, at, arg);
            return try SExpr.StringPreallocated(at, attr.filename);
        }
    } },
    .{ "attr-range", "get the range stored in an Attr", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const arg = try interpreter.eval1(args);
            const attr: *const Source.Attr = try interpreter.castExternDataPtr(Source.Attr, at, arg);
            return try convertRangeToSExpr(at, attr.range);
        }
    } },
    .{ "attr-new", "create a new Attr from a filename string and a range object", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rargs = try interpreter.eval2(args);
            const filename = try interpreter.castStringSlice(at, rargs[0]);
            const range = try convertSExprToRange(interpreter, at, rargs[1]);
            const attr = try interpreter.context.new(Source.Attr{
                .context = interpreter.context,
                .filename = filename,
                .range = range,
            });
            return try ExternAttr(at, attr);
        }
    } },
    .{ "attr-of", "extract the Attr from a value", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const arg = try interpreter.eval1(args);
            return try ExternAttr(at, arg.getAttr());
        }
    } },
    .{ "attr-set!", "set the Attr of a value; returns the old Attr", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rargs = try interpreter.eval2(args);
            const attr: *const Source.Attr = try interpreter.castExternDataPtr(Source.Attr, at, rargs[1]);
            const oldAttr = rargs[0].getAttr();
            rargs[0].setAttr(attr);
            return try ExternAttr(at, oldAttr);
        }
    } },
};

pub fn convertRangeToSExpr(at: *const Source.Attr, value: ?Source.Range) !SExpr {
    if (value) |range| {
        const start = try convertPosToSExpr(at, range.start);
        const end = try convertPosToSExpr(at, range.end);
        return try SExpr.Cons(at, start, end);
    } else {
        return try SExpr.Nil(at);
    }
}

pub fn convertPosToSExpr(at: *const Source.Attr, value: ?Source.Pos) !SExpr {
    if (value) |pos| {
        return try SExpr.Cons(
            at,
            try SExpr.Cons(
                at,
                try SExpr.Int(at, pos.line),
                try SExpr.Int(at, pos.column),
            ),
            try SExpr.Int(at, pos.offset),
        );
    } else {
        return try SExpr.Nil(at);
    }
}

pub fn convertSExprToRange(interpreter: *Interpreter, at: *const Source.Attr, value: SExpr) !?Source.Range {
    const xp1 = value.castCons() orelse {
        if (value.isNil()) {
            return null;
        } else {
            return interpreter.abort(Interpreter.Error.TypeError, at, "expected a source range of the form `(start . end)`, got {}", .{value.getTag()});
        }
    };

    const start = try convertSExprToPos(interpreter, at, xp1.car);
    const end = try convertSExprToPos(interpreter, at, xp1.cdr);

    return Source.Range{
        .start = start,
        .end = end,
    };
}

pub fn convertSExprToPos(interpreter: *Interpreter, at: *const Source.Attr, value: SExpr) !?Source.Pos {
    const xp1 = value.castCons() orelse {
        if (value.isNil()) {
            return null;
        } else {
            return interpreter.abort(Interpreter.Error.TypeError, at, "expected a source position of the form `((line . column) . offset)`, got {}", .{value.getTag()});
        }
    };

    const xp2 = xp1.car.castCons() orelse {
        return interpreter.abort(Interpreter.Error.TypeError, at, "expected a source position line and column pair of the form `(line . column)`, got {}: `{}`", .{ xp1.car.getTag(), xp1.car });
    };

    const line = try interpreter.castInt(at, xp2.car);

    const column = try interpreter.castInt(at, xp2.cdr);

    const offset = try interpreter.castInt(at, xp1.cdr);

    if (line < 0) {
        return interpreter.abort(Interpreter.Error.RangeError, at, "line must be non-negative, got {}", .{line});
    }

    if (column < 0) {
        return interpreter.abort(Interpreter.Error.RangeError, at, "column must be non-negative, got {}", .{column});
    }

    if (offset < 0) {
        return interpreter.abort(Interpreter.Error.RangeError, at, "offset must be non-negative, got {}", .{offset});
    }

    return Source.Pos{
        .line = @intCast(line),
        .column = @intCast(column),
        .offset = @intCast(offset),
    };
}

pub fn ExternAttr(at: *const Source.Attr, value: *const Source.Attr) !SExpr {
    const ParserVTable = SExpr.Types.ExternData.VTable(Source.Attr){
        .compare = struct {
            fn fun(self: *const Source.Attr, other: *const Source.Attr) callconv(.C) MiscUtils.Ordering {
                return MiscUtils.compare(self.*, other.*);
            }
        }.fun,
        .format = struct {
            fn fun(self: *const Source.Attr, f: Extern.Writer) callconv(.C) bool {
                return f.print("{}", .{self.*});
            }
        }.fun,
        .hashWith = struct {
            fn fun(self: *const Source.Attr, hasher: *Extern.Hasher) callconv(.C) void {
                MiscUtils.hashWith(hasher, self.*);
            }
        }.fun,
    };

    return try SExpr.ExternData(Source.Attr, at, @constCast(value), &ParserVTable);
}
