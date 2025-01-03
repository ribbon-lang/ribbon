const std = @import("std");
const MiscUtils = @import("Utils").Misc;
const TypeUtils = @import("Utils").Type;

const dispatch = std.log.scoped(.@"object-dispatch");

const Rml = @import("root.zig");
const Nil = Rml.Nil;
const Bool = Rml.Bool;
const bindgen = Rml.bindgen;
const Error = Rml.Error;
const Ordering = Rml.Ordering;
const OOM = Rml.OOM;
const log = Rml.log;
const TypeId = Rml.TypeId;
const map = Rml.map;
const Writer = Rml.Writer;
const Symbol = Rml.Symbol;
const Origin = Rml.Origin;


pub const refcount = std.log.scoped(.refcount);

pub const OBJ_ALIGN = 16;

pub const ObjData = extern struct { data: u8 align(OBJ_ALIGN) };
pub fn ptr(comptime T: type) type { return *align(OBJ_ALIGN) T; }
pub fn const_ptr(comptime T: type) type { return *const align(OBJ_ALIGN) T; }

pub const PropertySet = map.MapUnmanaged;

pub const Header = struct {
    rml: *Rml,
    type_id: TypeId,
    vtable: *const VTable,
    origin: Origin,
    ref_count: usize,
    weak_ref_count: usize,
    properties: PropertySet,

    pub fn onInit(self: ptr(Header), comptime T: type, rml: *Rml, origin: Origin) void {
        refcount.debug("Header/onInit {} {} {s} @ {} : #{x}", .{1, 1, @typeName(T), origin, @intFromPtr(self.getObjMemory())});
        self.* = Header {
            .rml = rml,
            .type_id = TypeId.of(T),
            .vtable = VTable.of(T),
            .origin = origin,
            .ref_count = 1,
            .weak_ref_count = 1,
            .properties = .{},
        };
    }

    pub fn onDeinit(self: ptr(Header)) void {
        refcount.debug("Header/onDeinit {} {} {s} @ {} : #{x}", .{self.ref_count, self.weak_ref_count, TypeId.name(self.type_id), self.origin, @intFromPtr(self.getObjMemory())});
        std.debug.assert(self.ref_count == 0);

        self.vtable.onDeinit(self);

        self.properties.deinit(self.rml);

        self.decrWeakRefCount();
    }

    pub fn onDestroy(self: ptr(Header)) void {
        refcount.debug("Header/onDestroy {} {} {s} @ {} : #{x}", .{self.ref_count, self.weak_ref_count, TypeId.name(self.type_id), self.origin, @intFromPtr(self.getObjMemory())});
        std.debug.assert(self.weak_ref_count == 0);
        self.vtable.onDestroy(self);
    }

    pub fn onCompare(self: ptr(Header), other: ptr(Header)) Ordering {
        const obj = other.getObject();
        defer obj.deinit();

        return self.vtable.onCompare(self, obj);
    }

    pub fn onFormat(self: ptr(Header), writer: Obj(Writer)) Error! void {
        return self.vtable.onFormat(self, writer);
    }

    pub fn getObject(self: ptr(Header)) Object {
        return getObj(self.getData());
    }

    pub fn getObjMemory(self: ptr(Header)) *ObjMemory(ObjData) {
        return @fieldParentPtr("header", @as(ptr(TypeUtils.ToBytes(Header)), @ptrCast(self)));
    }

    pub fn getData(self: ptr(Header)) ptr(ObjData) {
        return self.getObjMemory().getData();
    }

    pub fn incrRefCount(self: ptr(Header)) void {
        std.debug.assert(self.ref_count > 0);

        self.ref_count += 1;

        refcount.debug("incr {} {} {s} @ {} : #{x}", .{self.ref_count, self.weak_ref_count, TypeId.name(self.type_id), self.origin, @intFromPtr(self.getObjMemory())});
    }

    pub fn decrRefCount(self: ptr(Header)) void {
        std.debug.assert(self.ref_count > 0);

        self.ref_count -= 1;

        refcount.debug("decr {} {} {s} @ {} : #{x}", .{self.ref_count, self.weak_ref_count, TypeId.name(self.type_id), self.origin, @intFromPtr(self.getObjMemory())});

        if (self.ref_count == 0) self.onDeinit();
    }

    pub fn incrWeakRefCount(self: ptr(Header)) void {
        std.debug.assert(self.weak_ref_count > 0);

        self.weak_ref_count += 1;

        refcount.debug("incr weak {} {} {s} @ {} : #{x}", .{self.ref_count, self.weak_ref_count, TypeId.name(self.type_id), self.origin, @intFromPtr(self.getObjMemory())});
    }

    pub fn decrWeakRefCount(self: ptr(Header)) void {
        std.debug.assert(self.weak_ref_count > 0);

        self.weak_ref_count -= 1;

        refcount.debug("decr weak {} {} {s} @ {} : #{x}", .{self.ref_count, self.weak_ref_count, TypeId.name(self.type_id), self.origin, @intFromPtr(self.getObjMemory())});

        if (self.weak_ref_count == 0) self.onDestroy();
    }
};


pub const VTable = struct {
    obj_memory: ObjMemoryFunctions,
    obj_data: ObjDataFunctions,

    pub const ObjMemoryFunctions = struct {
        onDestroy: ?*const fn (*anyopaque) void = null,
    };

    pub const ObjDataFunctions = struct {
        onCompare: ?*const fn (const_ptr(ObjData), Rml.Object) Ordering = null,
        onFormat: ?*const fn (const_ptr(ObjData), Obj(Writer)) Error! void = null,
        onDeinit: ?*const fn (const_ptr(ObjData)) void = null,
    };

    pub fn of(comptime T: type) *const VTable {
        if (comptime T == ObjData) return undefined;

        const x = struct {
            const vtable = VTable {
                .obj_memory = obj_memory: {
                    var functionSet: ObjMemoryFunctions = .{};

                    for (std.meta.fields(ObjMemoryFunctions)) |field| {
                        const funcName = field.name;

                        const G = @typeInfo(@typeInfo(field.type).optional.child).pointer.child;
                        const gInfo = @typeInfo(G).@"fn";

                        const F = @TypeOf(@field(ObjMemory(T), funcName));
                        const fInfo = @typeInfo(F).@"fn";

                        std.debug.assert(!fInfo.is_generic);
                        std.debug.assert(!fInfo.is_var_args);
                        std.debug.assert(fInfo.return_type.? == gInfo.return_type.?);
                        std.debug.assert(fInfo.params.len == gInfo.params.len);

                        @field(functionSet, funcName) = @ptrCast(&@field(ObjMemory(T), funcName));
                    }

                    break :obj_memory functionSet;
                },
                .obj_data = obj_data: {
                    var functionSet: ObjDataFunctions = .{};

                    const support = bindgen.Support(T);
                    for (std.meta.fields(ObjDataFunctions)) |field| {
                        const funcName = field.name;

                        const def =
                            if (TypeUtils.supportsDecls(T) and @hasDecl(T, funcName)) &@field(T, funcName)
                            else if (@hasDecl(support, funcName)) &@field(support, funcName)
                            else @compileError("no " ++ @typeName(T) ++ "." ++ funcName ++ " found");

                        const G = @typeInfo(@typeInfo(field.type).optional.child).pointer.child;
                        const gInfo = @typeInfo(G).@"fn";

                        const F = @typeInfo(@TypeOf(def)).pointer.child;
                        if (@typeInfo(F) != .@"fn") {
                            @compileError("expected fn: " ++ @typeName(T) ++ "." ++ @typeName(@TypeOf(def)));
                        }
                        const fInfo = @typeInfo(F).@"fn";

                        std.debug.assert(!fInfo.is_generic);
                        std.debug.assert(!fInfo.is_var_args);
                        std.debug.assert(fInfo.return_type.? == gInfo.return_type.?);
                        std.debug.assert(fInfo.params.len == gInfo.params.len);

                        @field(functionSet, funcName) = @ptrCast(def);
                    }

                    break :obj_data functionSet;
                },
            };
        };

        return &x.vtable;
    }

    pub fn onCompare(self: *const VTable, header: ptr(Header), other: Object) Ordering {
        const data = header.getData();
        dispatch.debug("VTable/onCompare {s}", .{TypeId.name(header.type_id)});
        return self.obj_data.onCompare.?(data, other);
    }

    pub fn onFormat(self: *const VTable, header: ptr(Header), writer: Obj(Writer)) Error! void {
        const data = header.getData();
        // too noisy
        // dispatch.debug("VTable/onFormat {s}", .{TypeId.name(header.type_id)});
        return self.obj_data.onFormat.?(data, writer);
    }

    pub fn onDeinit(self: *const VTable, header: ptr(Header)) void {
        const data = header.getData();
        dispatch.debug("VTable/onDeinit {s}", .{TypeId.name(header.type_id)});
        return self.obj_data.onDeinit.?(data);
    }

    pub fn onDestroy(self: *const VTable, header: ptr(Header)) void {
        const data = header.getObjMemory();
        dispatch.debug("VTable/onDestroy {s}", .{TypeId.name(header.type_id)});
        return self.obj_memory.onDestroy.?(data);
    }
};

pub const ObjectMemory = ObjMemory(ObjData);
pub fn ObjMemory (comptime T: type) type {
    return extern struct {
        const Self = @This();

        // this sucks but we need extern to guarantee layout here & don't want it on Header / T
        header: TypeUtils.ToBytes(Header) align(OBJ_ALIGN),
        data: TypeUtils.ToBytes(T) align(OBJ_ALIGN),

        pub fn onInit(self: *Self, rml: *Rml, origin: Origin, data: T) void {
            Header.onInit(@ptrCast(&self.header), T, rml, origin);
            self.data = std.mem.toBytes(data);
            rml.storage.object_count += 1;
        }

        pub fn getHeader(self: *Self) ptr(Header) {
            return @ptrCast(&self.header);
        }

        pub fn getTypeId(self: *Self) TypeId {
            return self.getHeader().type_id;
        }

        pub fn getData(self: ptr(Self)) ptr(T) {
            return @ptrCast(&self.data);
        }

        pub fn onDestroy(self: ptr(Self)) void {
            refcount.debug("(ObjMemory {s})/onDestroy", .{@typeName(T)});
            const rml = self.getHeader().rml;
            rml.storage.object.destroy(self);
            rml.storage.object_count -= 1;
        }
    };
}

pub const Weak = Wk(ObjData);
pub fn Wk(comptime T: type) type {
    return struct {
        const Self = @This();

        memory: ?ptr(ObjMemory(T)),

        pub const Null = Self { .memory = null };

        pub fn upgradeUnchecked(self: Self) Obj(T) {
            const m = self.memory.?;
            m.getHeader().incrRefCount();
            return .{.data = @ptrCast(&m.data)};
        }

        pub fn upgrade(self: Self) ?Obj(T) {
            return if (self.memory) |m| (
                if (m.getHeader().ref_count > 0) self.upgradeUnchecked()
                else null
            ) else null;
        }

        pub fn deinit(self: Self) void {
            if (self.memory) |m| {
                refcount.debug("Wk({s})/deinit", .{TypeId.name(m.getTypeId())});
                m.getHeader().decrWeakRefCount();
            }
        }
    };
}

pub fn ref (comptime T: type) type {
    return struct {
        obj: Object,
        data: if (@typeInfo(T) == .pointer) T else *T,
    };
}

pub fn new(comptime T: type, rml: *Rml, origin: Origin) OOM! Obj(T) {
    comptime if (@typeInfo(@TypeOf(Obj(T).new)).@"fn".params.len != 2) {
        @compileError("new for " ++ @typeName(T) ++ " requires parameters, use newWith instead");
    };
    return Obj(T).new(rml, origin);
}

pub fn newObject(comptime T: type, rml: *Rml, origin: Origin) OOM! Object {
    return (try new(T, rml, origin)).typeEraseLeak();
}

pub fn newWith(comptime T: type, rml: *Rml, origin: Origin, args: anytype) OOM! Obj(T) {
    return Obj(T).new(rml, origin, args);
}

pub fn newObjectWith(comptime T: type, rml: *Rml, origin: Origin, args: anytype) OOM! Object {
    return (try newWith(T, rml, origin, args)).typeEraseLeak();
}

pub fn wrap(rml: *Rml, origin: Origin, value: anytype) OOM! Obj(@TypeOf(value)) {
    return Obj(@TypeOf(value)).wrap(rml, origin, value);
}

pub fn wrapObject (rml: *Rml, origin: Origin, value: anytype) OOM! Object {
    return (try wrap(rml, origin, value)).typeEraseLeak();
}

pub const Object = Obj(ObjData);
pub fn Obj(comptime T: type) type {
    std.debug.assert(@alignOf(T) <= OBJ_ALIGN);

    return struct {
        const Self = @This();

        data: ptr(T),

        pub const new = if (T == ObjData) null else if (std.meta.hasMethod(T, "onInit")) struct {
            const OnInit: type = @TypeOf(T.onInit);
            const Args = TypeUtils.DropSelf(T, std.meta.ArgsTuple(OnInit));

            pub fn init(rml: *Rml, origin: Origin, args: Args) OOM! Self {
                const memory = try rml.storage.object.create(ObjMemory(T));
                errdefer rml.storage.object.destroy(memory);

                const causesErrors = comptime TypeUtils.causesErrors(OnInit);

                if (comptime TypeUtils.hasSelf(T, std.meta.ArgsTuple(OnInit))) {
                    memory.onInit(rml, origin, undefined);
                    const r = @call(.auto, T.onInit, .{@as(ptr(T), @ptrCast(&memory.data))} ++ args);
                    if (causesErrors) try r;
                } else {
                    const r = @call(.auto, T.onInit, args);
                    memory.onInit(rml, origin, if (causesErrors) try r else r);
                }

                return Self {.data = @ptrCast(&memory.data) };
            }
        }.init else struct {
            pub fn init(rml: *Rml, origin: Origin) OOM! Self {
                const memory = try rml.storage.object.create(ObjMemory(T));
                errdefer rml.storage.object.destroy(memory);

                memory.onInit(rml, origin, TypeUtils.zero(T));

                return Self { .data = @ptrCast(&memory.data) };
            }
        }.init;

        pub fn clone(self: Self) Self {
            self.getHeader().incrRefCount();
            return Self { .data = self.data };
        }

        pub fn downgrade(self: Self) Wk(T) {
            self.getHeader().incrWeakRefCount();
            return .{ .memory = self.getMemory() };
        }

        pub fn typeErase(self: Self) Object {
            self.getHeader().incrRefCount();
            return self.typeEraseLeak();
        }

        pub fn typeEraseLeak(self: Self) Object {
            return .{ .data = @alignCast(@ptrCast(self.data)) };
        }

        pub fn wrap(rml: *Rml, origin: Origin, val: T) OOM! Self {
            const memory = try rml.storage.object.create(ObjMemory(T));
            errdefer rml.storage.object.destroy(memory);

            memory.onInit(rml, origin, val);

            return Self { .data = memory.getData() };
        }

        pub fn compare(self: Self, other: Obj(T)) Ordering {
            return self.getHeader().onCompare(other.getHeader());
        }

        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) Error! void {
            const w: Rml.writer.Native = if (@TypeOf(writer) == Rml.writer.Native) writer else writer.any();

            const wObj: Obj(Writer) = try .new(self.getRml(), self.getRml().storage.origin, .{w});
            defer wObj.deinit();

            try self.getHeader().onFormat(wObj);
        }

        pub fn deinit(self: Self) void {
            //refcount.debug("deinit Obj({s})", .{TypeId.name(self.getTypeId())});
            self.getHeader().decrRefCount();
        }

        pub fn getMemory(self: Self) *ObjMemory(T) {
            return @fieldParentPtr("data", @as(ptr(TypeUtils.ToBytes(T)), @ptrCast(self.data)));
        }

        pub fn getHeader(self: Self) ptr(Header) {
            return @ptrCast(&getMemory(self).header);
        }

        pub fn getTypeId(self: Self) TypeId {
            return self.getHeader().type_id;
        }

        pub fn getOrigin(self: Self) Origin {
            return self.getHeader().origin;
        }

        pub fn getRml(self: Self) *Rml {
            return self.getHeader().rml;
        }

        pub fn onCompare(self: Self, other: Object) Ordering {
            return self.getHeader().onCompare(other.getHeader());
        }

        pub fn onFormat(self: Self, writer: Obj(Writer)) Error! void {
            return self.getHeader().onFormat(writer);
        }
    };
}

pub fn tempObj(p: anytype) Obj(@typeInfo(@TypeOf(p)).pointer.child) {
    refcount.debug("tempObj", .{});
    const out = Obj(@typeInfo(@TypeOf(p)).pointer.child) { .data = p };
    return out;
}

pub fn getObj(p: anytype) Obj(@typeInfo(@TypeOf(p)).pointer.child) {
    refcount.debug("getObj", .{});
    const out = tempObj(p);
    out.getHeader().incrRefCount();
    return out;
}

pub fn getHeader(p: anytype) ptr(Header) {
    const obj = Obj(@typeInfo(@TypeOf(p)).pointer.child) { .data = p };
    return obj.getHeader();
}

pub fn getOrigin(p: anytype) Origin {
    const obj = Obj(@typeInfo(@TypeOf(p)).pointer.child) { .data = p };
    return obj.getOrigin();
}

pub fn getTypeId(p: anytype) TypeId {
    const obj = Obj(@typeInfo(@TypeOf(p)).pointer.child) { .data = p };
    return obj.getTypeId();
}

pub fn getRml(p: anytype) *Rml {
    const obj = Obj(@typeInfo(@TypeOf(p)).pointer.child) { .data = p };
    return obj.getRml();
}

pub fn castObj(comptime T: type, obj: Object) ?Obj(T) {
    if (isType(T, obj)) return forceObj(T, obj)
    else return null;
}

pub fn castObjLeak(comptime T: type, obj: Object) ?Obj(T) {
    if (isType(T, obj)) return forceObjLeak(T, obj)
    else return null;
}

pub fn isType(comptime T: type, obj: Object) bool {
    return MiscUtils.equal(obj.getTypeId(), TypeId.of(T));
}

pub fn isUserdata(obj: Object) bool {
    return !isBuiltin(obj);
}

pub fn isBuiltinType(comptime T: type) bool {
    return comptime {
        const typeId = TypeId.of(T);

        for (std.meta.fields(@TypeOf(Rml.BUILTIN_TYPES))) |builtin| {
            if (Rml.equal(typeId, TypeId.of(@field(Rml.BUILTIN_TYPES, builtin.name)))) return true;
        }

        return false;
    };
}

pub fn isBuiltin(obj: Object) bool {
    const typeId = obj.getTypeId();

    inline for (comptime std.meta.fields(@TypeOf(Rml.BUILTIN_TYPES))) |builtin| {
        if (Rml.equal(typeId, TypeId.of(@field(Rml.BUILTIN_TYPES, builtin.name)))) return true;
    }

    return false;
}

pub fn isValue(obj: Object) bool {
    const typeId = obj.getTypeId();

    inline for (comptime std.meta.fields(@TypeOf(Rml.VALUE_TYPES))) |value| {
        if (Rml.equal(typeId, TypeId.of(@field(Rml.VALUE_TYPES, value.name)))) return true;
    }

    return false;
}

pub fn isAtom(obj: Object) bool {
    const typeId = obj.getTypeId();

    inline for (comptime std.meta.fields(@TypeOf(Rml.ATOM_TYPES))) |atom| {
        if (Rml.equal(typeId, TypeId.of(@field(Rml.ATOM_TYPES, atom.name)))) return true;
    }

    return false;
}

pub fn isData(obj: Object) bool {
    const typeId = obj.getTypeId();

    inline for (comptime std.meta.fields(@TypeOf(Rml.DATA_TYPES))) |data| {
        if (Rml.equal(typeId, TypeId.of(@field(Rml.DATA_TYPES, data.name)))) return true;
    }

    return false;
}

pub fn isObject(obj: Object) bool {
    const typeId = obj.getTypeId();

    inline for (comptime std.meta.fields(@TypeOf(Rml.OBJECT_TYPES))) |object| {
        if (Rml.equal(typeId, TypeId.of(@field(Rml.OBJECT_TYPES, object.name)))) return true;
    }

    return false;
}

pub fn isSource(obj: Object) bool {
    const typeId = obj.getTypeId();

    inline for (comptime std.meta.fields(@TypeOf(Rml.SOURCE_TYPES))) |source| {
        if (Rml.equal(typeId, TypeId.of(@field(Rml.SOURCE_TYPES, source.name)))) return true;
    }

    return false;
}

pub fn isCollection(obj: Object) bool {
    const typeId = obj.getTypeId();

    inline for (comptime std.meta.fields(@TypeOf(Rml.COLLECTION_TYPES))) |collection| {
        if (Rml.equal(typeId, TypeId.of(@field(Rml.COLLECTION_TYPES, collection.name)))) return true;
    }

    return false;
}

pub fn isObjectType(comptime T: type) bool {
    const typeId = TypeId.of(T);

    inline for (comptime std.meta.fields(Rml.OBJECT_TYPES)) |field| {
        if (Rml.equal(typeId, TypeId.of(@field(Rml.COLLECTION_TYPES, field.name)))) return true;
    }

    return false;
}

pub fn forceObj(comptime T: type, obj: Object) Obj(T) {
    obj.getHeader().incrRefCount();
    return forceObjLeak(T, obj);
}

pub fn forceObjLeak(comptime T: type, obj: Object) Obj(T) {
    return .{.data = @ptrCast(obj.data)};
}

pub fn upgradeCast(comptime T: type, weak: Weak) ?Obj(T) {
    return if (weak.upgrade()) |u| {
        defer u.deinit();
        return castObj(T, u);
    } else null;
}

pub fn downgradeCast(obj: anytype) Weak {
    const e: Object = obj.typeErase();
    defer e.deinit();
    return e.downgrade();
}

pub fn coerceBool(obj: Object) Bool {
    if (castObj(Bool, obj)) |b| {
        defer b.deinit();

        return b.data.*;
    } else if (isType(Nil, obj)) {
        return false;
    } else {
        return true;
    }
}

pub fn coerceArray(obj: Object) OOM! ?Obj(Rml.Array) {
    if (castObj(Rml.Array, obj)) |x| return x
    else if (castObj(Rml.Map, obj)) |x| {
        defer x.deinit();
        return try x.data.toArray();
    } else if (castObj(Rml.Set, obj)) |x| {
        defer x.deinit();
        return try x.data.toArray();
    } else if (castObj(Rml.Block, obj)) |x| {
        defer x.deinit();
        return try x.data.toArray();
    } else return null;
}

pub fn isArrayLike(obj: Object) bool {
    return isType(Rml.Array, obj)
        or isType(Rml.Map, obj)
        or isType(Rml.Set, obj)
        or isType(Rml.Block, obj)
        ;
}


pub fn isExactString(name: []const u8, obj: Object) bool {
    if (castObj(Rml.String, obj)) |sym| {
        defer sym.deinit();
        return std.mem.eql(u8, sym.data.text(), name);
    } else {
        return false;
    }
}

pub fn isExactSymbol(name: []const u8, obj: Object) bool {
    if (castObj(Symbol, obj)) |sym| {
        defer sym.deinit();
        return std.mem.eql(u8, sym.data.text(), name);
    } else {
        return false;
    }
}
