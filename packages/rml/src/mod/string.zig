const std = @import("std");
const MiscUtils = @import("Utils").Misc;
const TextUtils = @import("Utils").Text;

const Rml = @import("root.zig");
const Char = Rml.Char;
const OOM = Rml.OOM;
const Error = Rml.Error;
const Obj = Rml.Obj;
const Object = Rml.Object;
const Writer = Rml.Writer;
const getObj = Rml.getObj;
const getRml = Rml.getRml;



pub const NativeString = std.ArrayListUnmanaged(u8);
pub const NativeWriter = NativeString.Writer;
pub const String = struct {
    allocator: std.mem.Allocator,
    native_string: NativeString = .{},

    pub fn create(rml: *Rml, str: []const u8) OOM! String {
        var self = String {.allocator = rml.blobAllocator()};
        try self.appendSlice(str);
        return self;
    }

    pub fn onCompare(self: *String, other: Object) MiscUtils.Ordering {
        var ord = Rml.compare(Rml.TypeId.of(String), other.getTypeId());

        if (ord == .Equal) {
            const otherStr = Rml.forceObj(String, other);
            ord = Rml.compare(self.text(), otherStr.data.text());
        }

        return ord;
    }

    pub fn compare(self: *String, other: String) MiscUtils.Ordering {
        return Rml.compare(self.native_string.items, other.native_string.items);
    }

    pub fn onFormat(self: *String, w: std.io.AnyWriter) anyerror! void {
        try w.print("{}", .{self});
    }

    pub fn format(self: *const String, comptime _: []const u8, _: std.fmt.FormatOptions, w: anytype) Error! void {
        // TODO: escape non-ascii & control etc Chars
        w.print("\"{s}\"", .{self.native_string.items}) catch |err| return Rml.errorCast(err);
    }

    pub fn text(self: *String) []const u8 {
        return self.native_string.items;
    }

    pub fn length(self: *String) usize {
        return self.native_string.items.len;
    }

    pub fn append(self: *String, ch: Char) OOM! void {
        var buf = [1]u8{0} ** 4;
        const len = TextUtils.encode(ch, &buf) catch @panic("invalid ch");
        return self.native_string.appendSlice(self.allocator, buf[0..len]);
    }

    pub fn appendSlice(self: *String, str: []const u8) OOM! void {
        return self.native_string.appendSlice(self.allocator, str);
    }

    pub fn makeInternedSlice(self: *String, rml: *Rml) OOM! []const u8 {
        return try rml.storage.intern(self.native_string.items);
    }

    pub fn writer(self: *String) NativeWriter {
        return self.native_string.writer(self.allocator);
    }
};

