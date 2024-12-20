const std = @import("std");

const TextUtils = @import("Utils").Text;

const Rli = @import("../root.zig");
const Source = Rli.Source;
const SExpr = Rli.SExpr;
const Interpreter = Rli.Interpreter;

pub const Doc =
    \\This module provides functions for working with strings.
    \\
    \\The functions in this module are designed to be utf8-safe, and will
    \\generally cause a compilation error if used improperly.
    \\
    \\Most functions come in a codepoint-indexed and byte-index variant.
    \\
    \\> [!Caution]
    \\> Special care must be take in particular with the byte-indexed
    \\> functions to avoid causing errors, as they validate that their operation is
    \\> boundary-aligned.
    \\
;

pub const Decls = .{
    .{ "string/empty?", "check if a value is the empty string", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const arg = (try interpreter.evalN(1, args))[0];
            return try SExpr.Bool(at, if (arg.castStringSlice()) |str| str.len == 0 else false);
        }
    } },
    .{ "string/length", "get the number of characters in a string", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const arg = (try interpreter.evalN(1, args))[0];
            const str = try interpreter.castStringSlice(at, arg);
            const len = TextUtils.codepointCount(str) catch {
                return interpreter.abort(Interpreter.Error.BadEncoding, at, "bad utf8 string", .{});
            };
            if (len > std.math.maxInt(i64)) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "string is too long to take its length", .{});
            }
            return try SExpr.Int(at, @intCast(len));
        }
    } },
    .{ "string/find", "within a given string, find the character index of another string, or a character; returns nil if not found", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rargs = try interpreter.evalN(2, args);
            const haystack = try interpreter.castStringSlice(at, rargs[0]);
            var needleBuf = [4]u8{ 0, 0, 0, 0 };
            const needle =
                if (rargs[1].castStringSlice()) |s| s
                else if (rargs[1].coerceNativeChar()) |c| needleBuf[0..(TextUtils.encode(c, &needleBuf)
                    catch return interpreter.abort(Interpreter.Error.TypeError, at, "bad char {}", .{c}))]
                else {
                    return interpreter.abort(Interpreter.Error.TypeError, at, "expected a string or char for string/find needle, got {}: `{}`", .{ rargs[1].getTag(), rargs[1] });
                };
            const pos = TextUtils.findStrCodepointIndex(haystack, needle) catch {
                return interpreter.abort(Interpreter.Error.BadEncoding, at, "bad utf8 string", .{});
            } orelse {
                return try SExpr.Nil(at);
            };
            if (pos > std.math.maxInt(i64)) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "string/find result is too large to fit in an integer", .{});
            }
            return try SExpr.Int(at, @intCast(pos));
        }
    } },
    .{ "string/find-byte-offset", "within a given string, find the byte index of another string; returns nil if not found", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rargs = try interpreter.evalN(2, args);
            const haystack = try interpreter.castStringSlice(at, rargs[0]);
            var needleBuf = [4]u8{ 0, 0, 0, 0 };
            const needle =
                if (rargs[1].castStringSlice()) |s| s
                else if (rargs[1].coerceNativeChar()) |c| needleBuf[0..(TextUtils.encode(c, &needleBuf)
                    catch return interpreter.abort(Interpreter.Error.TypeError, at, "bad char {}", .{c}))]
                else {
                    return interpreter.abort(Interpreter.Error.TypeError, at, "expected a string or char for string/intercalate separator, got {}: `{}`", .{ rargs[1].getTag(), rargs[1] });
                };
            const pos = TextUtils.findStr(haystack, needle) orelse {
                return try SExpr.Nil(at);
            };
            if (pos > std.math.maxInt(i64)) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "string/find-byte-offset result is too large to fit in an integer", .{});
            }
            return try SExpr.Int(at, @intCast(pos));
        }
    } },
    .{ "string/nth-char", "get the character at the given character index; returns nil if out of range", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rargs = try interpreter.evalN(2, args);
            const n = try interpreter.coerceNativeInt(at, rargs[0]);
            if (n < 0) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "expected a non-negative integer, got {}", .{n});
            }
            const str = try interpreter.castStringSlice(at, rargs[1]);
            const char = TextUtils.nthCodepoint(@intCast(n), str) catch {
                return interpreter.abort(Interpreter.Error.BadEncoding, at, "bad utf8 string", .{});
            } orelse {
                return try SExpr.Nil(at);
            };
            return try SExpr.Char(at, char);
        }
    } },
    .{ "string/index<-byte-offset", "given a string, convert a byte index within it to a character index; returns nil if out of range", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rargs = try interpreter.evalN(2, args);
            const str = try interpreter.castStringSlice(at, rargs[0]);
            const offset = try interpreter.coerceNativeInt(at, rargs[1]);
            if (offset < 0) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "expected a non-negative integer, got {}", .{offset});
            }
            const index = TextUtils.offsetToCodepointIndex(str, @intCast(offset)) catch {
                return try SExpr.Nil(at);
            };
            if (index > std.math.maxInt(i64)) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "index<-byte-offset result is too large to fit in an integer", .{});
            }
            return try SExpr.Int(at, @intCast(index));
        }
    } },
    .{ "string/byte-offset<-index", "given a string, convert a character index within it to a byte index; returns nil if out of range or mis-aligned ", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rargs = try interpreter.evalN(2, args);
            const str = try interpreter.castStringSlice(at, rargs[0]);
            const n = try interpreter.coerceNativeInt(at, rargs[1]);
            if (n < 0) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "expected a non-negative integer, got {}", .{n});
            }
            const index = TextUtils.nthCodepointOffset(@intCast(n), str) catch {
                return try SExpr.Nil(at);
            } orelse {
                return try SExpr.Nil(at);
            };
            if (index > std.math.maxInt(i64)) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "nth-char-offset result is too large to fit in an integer", .{});
            }
            return try SExpr.Int(at, @intCast(index));
        }
    } },
    .{ "string/concat", "given any number of strings or characters, returns a new string with all of them concatenated in order", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var rargs = try interpreter.argIterator(true, args);
            var newStr = std.ArrayList(u8).init(interpreter.context.allocator);
            while (try rargs.next()) |arg| {
                if (arg.castStringSlice()) |str| {
                    try newStr.appendSlice(str);
                } else if (arg.coerceNativeChar()) |char| {
                    var charBuf = [1]u8{0} ** 4;
                    const charSize = TextUtils.encode(char, &charBuf) catch {
                        return interpreter.abort(Interpreter.Error.TypeError, at, "bad char {}", .{char});
                    };
                    try newStr.appendSlice(charBuf[0..charSize]);
                } else {
                    return interpreter.abort(Interpreter.Error.TypeError, at, "expected a string or char, got {}", .{arg.getTag()});
                }
            }
            return try SExpr.StringPreallocatedUnchecked(at, try newStr.toOwnedSlice());
        }
    } },
    .{ "string/intercalate", "given a string or a char, and any number of subsequent strings or chars, returns a new string with all of the subsequent values concatenated in order with the first value in between concatenations", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var rargs = try interpreter.argIterator(true, args);
            var newStr = std.ArrayList(u8).init(interpreter.context.allocator);
            var sepBuf = [4]u8{ 0, 0, 0, 0 };
            const sep = try rargs.atLeast();
            const sepStr =
                if (sep.castStringSlice()) |s| s
                else if (sep.coerceNativeChar()) |c| sepBuf[0..(TextUtils.encode(c, &sepBuf)
                    catch return interpreter.abort(Interpreter.Error.TypeError, at, "bad char {}", .{c}))]
                else {
                    return interpreter.abort(Interpreter.Error.TypeError, at, "expected a string or char for string/intercalate separator, got {}: `{}`", .{ sep.getTag(), sep });
                };
            if (!rargs.hasNext()) {
                try rargs.assertDone();
                return try SExpr.String(at, "");
            }
            var charBuf = [4]u8{ 0, 0, 0, 0 };
            const fst = try rargs.atLeast();
            const fstStr =
                if (fst.castStringSlice()) |s| s
                else if (fst.coerceNativeChar()) |c| charBuf[0..(TextUtils.encode(c, &charBuf)
                    catch return interpreter.abort(Interpreter.Error.TypeError, at, "bad char {}", .{c}))]
                else {
                    return interpreter.abort(Interpreter.Error.TypeError, at, "expected a string or char for string/intercalate argument, got {}: `{}`", .{ fst.getTag(), fst });
                };
            try newStr.appendSlice(fstStr);
            while (try rargs.next()) |arg| {
                const str =
                    if (arg.castStringSlice()) |s| s
                    else if (arg.coerceNativeChar()) |c| charBuf[0..(TextUtils.encode(c, &charBuf)
                        catch return interpreter.abort(Interpreter.Error.TypeError, at, "bad char {}", .{c}))]
                    else {
                        return interpreter.abort(Interpreter.Error.TypeError, at, "expected a string or char for string/intercalate argument, got {}: `{}`", .{ arg.getTag(), fst });
                    };
                try newStr.appendSlice(sepStr);
                try newStr.appendSlice(str);
            }
            return try SExpr.StringPreallocatedUnchecked(at, try newStr.toOwnedSlice());
        }
    } },
    .{ "string/sub", "given a string and two character indices, returns a new string containing the designated section; returns nil if out of range", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var rargs = [3]SExpr{ undefined, undefined, undefined };
            const len = try interpreter.evalSmallList(args, 2, &rargs);
            const str = try interpreter.castStringSlice(at, rargs[0]);
            const start = try interpreter.coerceNativeInt(at, rargs[1]);
            if (start < 0) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "expected a non-negative integer, got {}", .{start});
            }
            const end: i64 =
                if (len == 3) try interpreter.coerceNativeInt(at, rargs[2])
                else if (str.len < std.math.maxInt(i64)) @intCast(str.len)
                else return interpreter.abort(Interpreter.Error.RangeError, at, "substring is too long to take its length", .{});
            if (end < 0) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "expected a non-negative integer, got {}", .{end});
            }
            if (end < start) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "substring end index is less than start index", .{});
            }
            const startOffset = TextUtils.nthCodepointOffset(@intCast(start), str) catch {
                return interpreter.abort(Interpreter.Error.BadEncoding, at, "bad utf8 string", .{});
            } orelse {
                return try SExpr.Nil(at);
            };
            const endOffset = TextUtils.nthCodepointOffset(@intCast(end), str) catch {
                return interpreter.abort(Interpreter.Error.BadEncoding, at, "bad utf8 string", .{});
            } orelse {
                return try SExpr.Nil(at);
            };
            const newStr = str[startOffset..endOffset];
            return SExpr.StringPreallocatedUnchecked(at, newStr);
        }
    } },
    .{ "string/byte-offset-sub", "given a string and two byte indices, returns a new string containing the designated section; ; returns nil if out of range or mis-aligned", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            const rargs = try interpreter.evalListInRange(args, 2, 3);
            const str = try interpreter.castStringSlice(at, rargs[0]);
            const start = try interpreter.coerceNativeInt(at, rargs[1]);
            if (start < 0) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "expected a non-negative integer, got {}", .{start});
            }
            if (start > str.len) {
                return SExpr.Nil(at);
            }
            const end: i64 = if (rargs.len == 3)
                try interpreter.coerceNativeInt(at, rargs[2])
            else if (str.len < std.math.maxInt(i64))
                @intCast(str.len)
            else
                return interpreter.abort(Interpreter.Error.RangeError, at, "string is too long to take its length", .{});
            if (end < 0) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "expected a non-negative integer, got {}", .{end});
            }
            if (end < start) {
                return interpreter.abort(Interpreter.Error.RangeError, at, "substring end index is less than start index", .{});
            }
            if (end > str.len) {
                return SExpr.Nil(at);
            }
            const newStr = str[@intCast(start)..@intCast(end)];
            if (!TextUtils.isValidStr(newStr)) {
                return interpreter.abort(Interpreter.Error.BadEncoding, at, "bad utf8 substring", .{});
            }
            return SExpr.StringPreallocatedUnchecked(at, newStr);
        }
    } },
    .{ "format", "stringify all arguments with `'Display`, then concatenate", struct {
        pub fn fun(interpreter: *Interpreter, at: *const Source.Attr, args: SExpr) Interpreter.Result!SExpr {
            var rargs = try interpreter.argIterator(true, args);
            var out = std.ArrayList(u8).init(interpreter.context.allocator);
            defer out.deinit();
            const writer = out.writer();
            while (try rargs.next()) |next| {
                try writer.print("{display}", .{next});
            }
            return SExpr.StringPreallocatedUnchecked(at, try out.toOwnedSlice());
        }
    } },
};
