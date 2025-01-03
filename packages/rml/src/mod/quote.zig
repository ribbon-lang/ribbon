const std = @import("std");
const MiscUtils = @import("Utils").Misc;


const Rml = @import("root.zig");
const Ordering = Rml.Ordering;
const Error = Rml.Error;
const OOM = Rml.OOM;
const ptr = Rml.ptr;
const Obj = Rml.Obj;
const ObjData = Rml.ObjData;
const Object = Rml.Object;
const Writer = Rml.Writer;
const Interpreter = Rml.Interpreter;
const getObj = Rml.getObj;
const getTypeId = Rml.getTypeId;
const forceObj = Rml.forceObj;
const getRml = Rml.getRml;
const isAtom = Rml.isAtom;


pub const QuoteKind = enum {
    // these need to be ordered length-wise if they use the same prefix
    // (e.g. unquote_splice must come before unquote)
    basic,
    quasi,
    to_quote,
    to_quasi,
    unquote_splice,
    unquote,

    pub fn toStr(self: QuoteKind) []const u8 {
        return switch (self) {
            .basic => "'",
            .quasi => "`",
            .to_quote => "~'",
            .to_quasi => "~`",
            .unquote_splice => ",@",
            .unquote => ",",
        };
    }

    pub fn fromStr(str: []const u8) ?QuoteKind {
        return if (std.mem.eql(u8, str, "'")) .basic
          else if (std.mem.eql(u8, str, "`")) .quasi
          else if (std.mem.eql(u8, str, "~'")) .to_quote
          else if (std.mem.eql(u8, str, "~`")) .to_quasi
          else if (std.mem.eql(u8, str, ",@")) .unquote_splice
          else if (std.mem.eql(u8, str, ",")) .unquote
          else null;
    }
};

pub const Quote = struct {
    kind: QuoteKind,
    body: Object,

    pub fn onInit(self: ptr(Quote), kind: QuoteKind, body: Object) void {
        self.kind = kind;
        self.body = body;
    }

    pub fn onCompare(self: ptr(Quote), other: Object) Ordering {
        var ord = Rml.compare(getTypeId(self), other.getTypeId());

        if (ord == .Equal) {
            const other_quote = forceObj(Quote, other);
            defer other_quote.deinit();

            ord = Rml.compare(self.kind, other_quote.data.kind);

            if (ord == .Equal) {
                ord = self.body.compare(other_quote.data.body);
            }
        }

        return ord;
    }

    pub fn onFormat(self: ptr(Quote), writer: Obj(Writer)) Error! void {
        try writer.data.writeAll(self.kind.toStr());
        try self.body.onFormat(writer);
    }

    pub fn onDeinit(self: ptr(Quote)) void {
        self.body.deinit();
    }

    pub fn run(self: ptr(Quote), interpreter: ptr(Interpreter)) Rml.Result! Object {
        switch (self.kind) {
            .basic => {
                Rml.interpreter.evaluation.debug("evaluating basic quote {}", .{self});
                return self.body.clone();
            },
            .quasi => {
                Rml.interpreter.evaluation.debug("evaluating quasi quote {}", .{self});
                return runQuasi(interpreter, self.body, null);
            },
            .to_quote => {
                Rml.interpreter.evaluation.debug("evaluating to_quote quote {}", .{self});
                const val = try interpreter.eval(self.body);
                errdefer val.deinit();

                return Rml.wrapObject(getRml(self), self.body.getOrigin(), Quote {.kind = .basic, .body = val});
            },
            .to_quasi => {
                Rml.interpreter.evaluation.debug("evaluating to_quasi quote {}", .{self});
                const val = try interpreter.eval(self.body);
                errdefer val.deinit();

                return Rml.wrapObject(getRml(self), self.body.getOrigin(), Quote {.kind = .quasi, .body = val});
            },
            else => {
                try interpreter.abort(Rml.getOrigin(self), error.TypeError, "unexpected {s}", .{@tagName(self.kind)});
            },
        }
    }
};


pub fn runQuasi(interpreter: ptr(Interpreter), body: Object, out: ?*Rml.array.ArrayUnmanaged) Rml.Result! Object {
    const rml = getRml(interpreter);

    if (Rml.castObj(Quote, body)) |quote| quote: {
        defer quote.deinit();

        const origin = quote.getOrigin();

        switch (quote.data.kind) {
            .basic => break :quote,
            .quasi => break :quote,
            .to_quote => {
                const ranBody = try runQuasi(interpreter, quote.data.body, null);
                errdefer ranBody.deinit();

                return Rml.wrapObject(rml, origin, Rml.Quote {.kind = .basic, .body = ranBody});
            },
            .to_quasi => {
                const ranBody = try runQuasi(interpreter, quote.data.body, null);
                errdefer ranBody.deinit();

                return Rml.wrapObject(rml, origin, Rml.Quote {.kind = .quasi, .body = ranBody});
            },
            .unquote => {
                return interpreter.eval(quote.data.body);
            },
            .unquote_splice => {
                const outArr = out
                    orelse try interpreter.abort(body.getOrigin(), error.SyntaxError,
                        "unquote-splice is not allowed here", .{});

                const ranBody = try interpreter.eval(quote.data.body);
                defer ranBody.deinit();

                const arrBody = try Rml.coerceArray(ranBody)
                    orelse try interpreter.abort(quote.data.body.getOrigin(), error.TypeError,
                        "unquote-splice expects an array-like, got {s}: {}", .{Rml.TypeId.name(ranBody.getTypeId()), ranBody});
                defer arrBody.deinit();

                for (arrBody.data.items()) |item| {
                    const ref = item.clone();
                    errdefer ref.deinit();

                    try outArr.append(rml, ref);
                }

                return Rml.newObject(Rml.Nil, rml, origin);
            }
        }
    } else if (Rml.castObj(Rml.Block, body)) |block| {
        defer block.deinit();

        var subOut: Rml.array.ArrayUnmanaged = .{};
        errdefer subOut.deinit(rml);

        for (block.data.array.items()) |item| {
            const len = subOut.length();

            const ranItem = try runQuasi(interpreter, item, &subOut);
            errdefer ranItem.deinit();

            // don't append if its the nil from unquote-splice
            if (len == subOut.length()) try subOut.append(rml, ranItem)
            else {
                std.debug.assert(Rml.isType(Rml.Nil, ranItem));
                ranItem.deinit();
            }
        }

        return (try Rml.wrap(rml, block.getOrigin(), Rml.Block {.kind = block.data.kind, .array = subOut})).typeEraseLeak();
    }

    return body.clone();
}
