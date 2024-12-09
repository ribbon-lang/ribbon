const std = @import("std");

const Rml = @import("root.zig");
const ptr = Rml.ptr;
const Obj = Rml.Obj;
const Result = Rml.Result;
const Object = Rml.Object;
const Origin = Rml.Origin;
const Nil = Rml.Nil;
const Bool = Rml.Bool;
const Int = Rml.Int;
const Float = Rml.Float;
const Char = Rml.Char;
const Writer = Rml.Writer;
const Interpreter = Rml.Interpreter;
const TypeId = Rml.TypeId;
const getRml = Rml.getRml;
const castObj = Rml.castObj;
const forceObj = Rml.forceObj;
const isType = Rml.isType;
const coerceBool = Rml.coerceBool;


pub const nil = Nil{};

/// Print any number of arguments followed by a new line
pub fn @"print-ln"(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    const rml = getRml(interpreter);

    const stdout = std.io.getStdOut();
    const nativeWriter = stdout.writer();

    const writer: Obj(Writer) = try .init(rml, origin, .{nativeWriter.any()});
    defer writer.deinit();

    try writer.data.print("{}: ", .{origin});

    for (args) |arg| try arg.getHeader().onFormat(writer);

    try writer.data.writeAll("\n");

    return (try Obj(Nil).init(rml, origin)).typeEraseLeak();
}



/// Print any number of arguments
pub fn print(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    const rml = getRml(interpreter);

    const stdout = std.io.getStdOut();
    const nativeWriter = stdout.writer();

    const writer: Obj(Writer) = try .init(rml, origin, .{nativeWriter.any()});
    defer writer.deinit();

    for (args) |arg| try arg.getHeader().onFormat(writer);

    return (try Obj(Nil).init(rml, origin)).typeEraseLeak();
}



/// Alias for `+`
pub const add = @"+";
/// Sum any number of arguments of type `int | float | char`;
/// if only one argument is provided, return the argument's absolute value
pub fn @"+"(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len == 0) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 1 argument, found 0", .{});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    if (args.len == 1) {
        if (castObj(Int, sum)) |int| {
            defer int.deinit();

            return (try Obj(Int).wrap(int.getRml(), origin, @intCast(@abs(int.data.*)))).typeEraseLeak();
        } else if (castObj(Float, sum)) |float| {
            defer float.deinit();

            return (try Obj(Float).wrap(float.getRml(), origin, @abs(float.data.*))).typeEraseLeak();
        } if (castObj(Char, sum)) |char| {
            defer char.deinit();

            return (try Obj(Char).wrap(char.getRml(), origin, char.data.*)).typeEraseLeak();
        } else {
            try interpreter.abort(origin, error.TypeError, "expected int | float | char, found {s}", .{TypeId.name(sum.getTypeId())});
        }
    }

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return a + b; }
        pub fn float(a: Float, b: Float) Float { return a + b; }
        pub fn char(a: Char, b: Char) Char { return a + b; }
    });
}



/// Alias for `-`
pub const sub = @"-";
/// Subtract any number of arguments of type `int | float | char`;
/// if only one argument is provided, return the argument's negative value
pub fn @"-"(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len == 0) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 1 argument, found 0", .{});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    if (args.len == 1) {
        if (castObj(Int, sum)) |int| {
            defer int.deinit();

            return (try Obj(Int).wrap(int.getRml(), origin, -int.data.*)).typeEraseLeak();
        } else if (castObj(Float, sum)) |float| {
            defer float.deinit();

            return (try Obj(Float).wrap(float.getRml(), origin, -float.data.*)).typeEraseLeak();
        } if (castObj(Char, sum)) |char| { // TODO: ???
            defer char.deinit();

            return (try Obj(Char).wrap(char.getRml(), origin, char.data.*)).typeEraseLeak();
        } else {
            try interpreter.abort(origin, error.TypeError, "expected int | float | char, found {s}", .{TypeId.name(sum.getTypeId())});
        }
    }

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return a - b; }
        pub fn float(a: Float, b: Float) Float { return a - b; }
        pub fn char(a: Char, b: Char) Char { return a - b; }
    });
}


/// Alias for `/`
pub const div = @"/";
/// Divide any number of arguments of type `int | float | char`;
/// it is an error to provide less than two arguments
pub fn @"/"(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len < 2) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 2 arguments, found {}", .{args.len});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return @divFloor(a, b); }
        pub fn float(a: Float, b: Float) Float { return a / b; }
        pub fn char(a: Char, b: Char) Char { return @divFloor(a, b); }
    });
}


/// Alias for `*`
pub const mul = @"*";
/// Multiply any number of arguments of type `int | float | char`;
/// it is an error to provide less than two arguments
pub fn @"*"(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len < 2) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 2 arguments, found {}", .{args.len});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return a * b; }
        pub fn float(a: Float, b: Float) Float { return a * b; }
        pub fn char(a: Char, b: Char) Char { return a * b; }
    });
}


/// Perform remainder division on any number of arguments of type `int | float | char`;
/// it is an error to provide less than two arguments
pub fn @"rem"(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len < 2) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 2 arguments, found {}", .{args.len});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return @rem(a, b); }
        pub fn float(a: Float, b: Float) Float { return @rem(a, b); }
        pub fn char(a: Char, b: Char) Char { return @rem(a, b); }
    });
}


/// Perform exponentiation on any number of arguments of type `int | float | char`;
/// it is an error to provide less than two arguments
pub fn pow(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len < 2) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 2 arguments, found {}", .{args.len});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return std.math.pow(Int, a, b); }
        pub fn float(a: Float, b: Float) Float { return std.math.pow(Float, a, b); }
        pub fn char(a: Char, b: Char) Char { return std.math.pow(Char, a, b); }
    });
}


/// Perform bitwise NOT on an argument of type `int | char`
pub fn bnot(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len != 1) try interpreter.abort(origin, error.InvalidArgumentCount, "expected 1 argument, found {}", .{args.len});

    if (castObj(Int, args[0])) |i| {
        return (try Obj(Int).wrap(i.getRml(), origin, ~i.data.*)).typeErase();
    } else if (castObj(Char, args[0])) |c| {
        return (try Obj(Char).wrap(c.getRml(), origin, ~c.data.*)).typeEraseLeak();
    } else {
        try interpreter.abort(origin, error.TypeError, "expected int | char, found {s}", .{TypeId.name(args[0].getTypeId())});
    }
}


/// Perform bitwise AND on any number of arguments of type `int | char`;
/// it is an error to provide less than two arguments
pub fn band(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len < 2) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 2 arguments, found {}", .{args.len});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return a & b; }
        pub fn char(a: Char, b: Char) Char { return a & b; }
    });
}

/// Perform bitwise OR on any number of arguments of type `int | char`;
/// it is an error to provide less than two arguments
pub fn bor(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len < 2) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 2 arguments, found {}", .{args.len});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return a | b; }
        pub fn char(a: Char, b: Char) Char { return a | b; }
    });
}

/// Perform bitwise XOR on any number of arguments of type `int | char`;
/// it is an error to provide less than two arguments
pub fn bxor(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
    if (args.len < 2) try interpreter.abort(origin, error.InvalidArgumentCount, "expected at least 2 arguments, found {}", .{args.len});

    var sum: Object = args[0].clone();
    defer sum.deinit();

    return arithCastReduce(interpreter, origin, &sum, args[1..], struct {
        pub fn int(a: Int, b: Int) Int { return a ^ b; }
        pub fn char(a: Char, b: Char) Char { return a ^ b; }
    });
}

/// logical not on an argument of type `bool`
pub fn not(b: Bool) Bool {
    return !b;
}

/// Short-circuiting logical AND on any number of arguments of any type;
/// returns the last succeeding argument or nil
pub const @"and" = Rml.Procedure {
    .native_macro = &struct{
        pub fn fun(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
            if (args.len == 0) return (try Obj(Nil).init(getRml(interpreter), origin)).typeEraseLeak();

            var a = try interpreter.eval(args[0]);
            errdefer a.deinit();

            if (!coerceBool(a)) {
                return (try Obj(Nil).init(getRml(interpreter), origin)).typeEraseLeak();
            }

            for (args[1..]) |aN| {
                const b = try interpreter.eval(aN);
                errdefer b.deinit();

                if (!coerceBool(b)) return a;

                a.deinit();
                a = b;
            }

            return a;
        }
    }.fun,
};

/// Short-circuiting logical OR on any number of arguments of any type;
/// returns the first succeeding argument or nil
pub const @"or" = Rml.Procedure {
    .native_macro = &struct{
        pub fn fun(interpreter: ptr(Interpreter), origin: Origin, args: []const Object) Result! Object {
            for (args[0..]) |aN| {
                const a = try interpreter.eval(aN);

                if (coerceBool(a)) return a;

                a.deinit();
            }

            return (try Obj(Nil).init(getRml(interpreter), origin)).typeEraseLeak();
        }
    }.fun,
};


fn arithCastReduce(
    interpreter: ptr(Interpreter),
    origin: Origin, acc: *Object, args: []const Object,
    comptime Ops: type,
) Result! Object {
    const offset = 1;
    comptime var expect: []const u8 = "";
    const decls = comptime std.meta.declarations(Ops);
    inline for (decls, 0..) |decl, i| comptime {
        expect = expect ++ decl.name;
        if (i < decls.len - 1) expect = expect ++ " | ";
    };
    for (args, 0..) |arg, i| {
        if (@hasDecl(Ops, "int") and isType(Int, acc.*)) {
            const int = forceObj(Int, acc.*);
            defer int.deinit();

            if (castObj(Int, arg)) |int2| {
                defer int2.deinit();

                const int3: Obj(Int) = try .wrap(int2.getRml(), origin, @field(Ops, "int")(int.data.*, int2.data.*));
                defer int3.deinit();

                acc.deinit();
                acc.* = int3.typeErase();
            } else if (@hasDecl(Ops, "float") and isType(Float, arg)) {
                const float = forceObj(Float, arg);
                defer float.deinit();

                const float2: Obj(Float) = try .wrap(float.getRml(), origin, @field(Ops, "float")(@as(Float, @floatFromInt(int.data.*)), float.data.*));
                defer float2.deinit();

                acc.deinit();
                acc.* = float2.typeErase();
            } else if (castObj(Char, arg)) |char| {
                defer char.deinit();

                const int2: Obj(Int) = try .wrap(char.getRml(), origin, @field(Ops, "int")(int.data.*, @as(Int, @intCast(char.data.*))));
                defer int2.deinit();

                acc.deinit();
                acc.* = int2.typeErase();
            } else {
                try interpreter.abort(origin, error.TypeError, "expected " ++ expect ++ " for argument {}, found {s}", .{i + offset, TypeId.name(arg.getTypeId())});
            }
        } else if (@hasDecl(Ops, "float") and isType(Float, acc.*)) {
            const float = forceObj(Float, acc.*);
            defer float.deinit();

            if (castObj(Int, arg)) |int| {
                defer int.deinit();

                const float2: Obj(Float) = try .wrap(int.getRml(), origin, @field(Ops, "float")(float.data.*, @as(Float, @floatFromInt(int.data.*))));
                defer float2.deinit();

                acc.deinit();
                acc.* = float2.typeErase();
            } else if (castObj(Float, arg)) |float2| {
                defer float2.deinit();

                const float3: Obj(Float) = try .wrap(float2.getRml(), origin, @field(Ops, "float")(float.data.*, float2.data.*));
                defer float3.deinit();

                acc.deinit();
                acc.* = float3.typeErase();
            } else if (castObj(Char, arg)) |char| {
                defer char.deinit();

                const float2: Obj(Float) = try .wrap(char.getRml(), origin, @field(Ops, "float")(float.data.*, @as(Float, @floatFromInt(char.data.*))));
                defer float2.deinit();

                acc.deinit();
                acc.* = float2.typeErase();
            } else {
                try interpreter.abort(origin, error.TypeError, "expected " ++ expect ++ " for argument {}, found {s}", .{i + offset, TypeId.name(arg.getTypeId())});
            }
        } else if (@hasDecl(Ops, "char") and isType(Char, acc.*)) {
            const char = forceObj(Char, acc.*);
            defer char.deinit();

            if (@hasDecl(Ops, "int") and isType(Int, arg)) {
                const int = forceObj(Int, arg);
                defer int.deinit();

                const int2: Obj(Int) = try .wrap(char.getRml(), origin, @field(Ops, "int")(@as(Int, @intCast(char.data.*)), int.data.*));
                defer int2.deinit();

                acc.deinit();
                acc.* = int2.typeErase();
            } else if (@hasDecl(Ops, "float") and isType(Float, arg)) {
                const float = forceObj(Float, arg);
                defer float.deinit();

                const float2: Obj(Float) = try .wrap(float.getRml(), origin, @field(Ops, "float")(@as(Float, @floatFromInt(char.data.*)), float.data.*));
                defer float2.deinit();

                acc.deinit();
                acc.* = float2.typeErase();
            } else if (castObj(Char, arg)) |char2| {
                defer char2.deinit();

                const char3: Obj(Char) = try .wrap(char2.getRml(), origin, @field(Ops, "char")(char.data.*, char2.data.*));
                defer char3.deinit();

                acc.deinit();
                acc.* = char3.typeErase();
            } else {
                try interpreter.abort(origin, error.TypeError, "expected " ++ expect ++ " for argument {}, found {s}", .{i + offset, TypeId.name(arg.getTypeId())});
            }
        } else {
            try interpreter.abort(origin, error.TypeError, "expected " ++ expect ++ " for argument {}, found {s}", .{i, TypeId.name(acc.getTypeId())});
        }
    }

    return acc.clone();
}

