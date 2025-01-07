const std = @import("std");
const MiscUtils = @import("Utils").Misc;
const TextUtils = @import("Utils").Text;

const Rml = @import("root.zig");
const Ordering = Rml.Ordering;
const Error = Rml.Error;
const OOM = Rml.OOM;
const log = Rml.log;
const Weak = Rml.Weak;
const Wk = Rml.Wk;
const Object = Rml.Object;
const Origin = Rml.Origin;
const Obj = Rml.Obj;
const ptr = Rml.ptr;
const Symbol = Rml.Symbol;
const Writer = Rml.Writer;
const getObj = Rml.getObj;
const getTypeId = Rml.getTypeId;
const getRml = Rml.getRml;
const castObj = Rml.castObj;
const forceObj = Rml.forceObj;
const upgradeCast = Rml.upgradeCast;

pub const SymbolError  = UnboundSymbol || SymbolAlreadyBound;
pub const UnboundSymbol = error {UnboundSymbol};
pub const SymbolAlreadyBound = error {SymbolAlreadyBound};

pub const Domain = std.ArrayHashMapUnmanaged(Obj(Symbol), void, MiscUtils.SimpleHashContext, true);

pub const CellTable = std.ArrayHashMapUnmanaged(Rml.Obj(Rml.Symbol), Rml.Obj(Rml.Cell), MiscUtils.SimpleHashContext, true);
pub const Table = std.ArrayHashMapUnmanaged(Rml.Obj(Rml.Symbol), Rml.Obj(Rml.ObjData), MiscUtils.SimpleHashContext, true);

pub const Env = struct {
    allocator: std.mem.Allocator,
    table: CellTable = .{},

    pub fn onCompare(a: *Env, other: Object) Ordering {
        var ord = Rml.compare(getTypeId(a), other.getTypeId());

        if (ord == .Equal) {
            const b = forceObj(Env, other);
            ord = a.compare(b.data.*);
        }

        return ord;
    }

    pub fn compare(self: Env, other: Env) Ordering {
        var ord = Rml.compare(self.table.count(), other.table.count());

        if (ord == .Equal) {
            var it = self.table.iterator();
            while (it.next()) |entry| {
                if (other.table.getEntry(entry.key_ptr.*)) |other_entry| {
                    ord = entry.value_ptr.compare(other_entry.value_ptr.*);
                } else {
                    return .Greater;
                }
            }
        }

        return ord;
    }

    pub fn onFormat(self: *Env, writer: std.io.AnyWriter) anyerror! void {
        return writer.print("{}", .{self});
    }

    pub fn format(self: *Env, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) Error! void {
        writer.writeAll("env{") catch |err| return Rml.errorCast(err);

        var it = self.table.iterator();
        while (it.next()) |entry| {
            writer.print("({} {})", .{entry.key_ptr.*, entry.value_ptr.*}) catch |err| return Rml.errorCast(err);
        }

        return writer.writeAll("}") catch |err| Rml.errorCast(err);
    }

    pub fn clone(self: *Env, origin: ?Origin) OOM! Obj(Env) {
        const table = try self.table.clone(self.allocator);

        return try .wrap(getRml(self), origin orelse Rml.getOrigin(self), .{.allocator = self.allocator, .table = table});
    }

    /// Set a value associated with a key
    ///
    /// If the key is already bound, a new cell is created, overwriting the old one
    ///
    /// Returns an error if:
    /// * Rml is out of memory
    pub fn rebind(self: *Env, key: Obj(Symbol), val: Object) OOM! void {
        const cell = try Obj(Rml.Cell).wrap(getRml(self), key.getOrigin(), .{.value = val});

        try self.table.put(self.allocator, key, cell);
    }

    /// Bind a value to a new key
    ///
    /// Returns an error if:
    /// * a value with the same name was already declared in this scope
    /// * Rml is out of memory
    pub fn bind(self: *Env, key: Obj(Symbol), val: Object) (OOM || SymbolAlreadyBound)! void {
        if (self.contains(key)) return error.SymbolAlreadyBound;

        return self.rebind(key, val);
    }

    /// Bind a value to an existing key
    ///
    /// Returns an error if:
    /// * binding does not exist in this env
    pub fn set(self: *Env, key: Obj(Symbol), val: Object) UnboundSymbol! void {
        return if (self.table.getEntry(key)) |entry| {
            entry.value_ptr.data.set(val);
        } else error.UnboundSymbol;
    }

    /// Find the value bound to a symbol in the env
    pub fn get(self: *Env, key: Obj(Symbol)) ?Object {
        if (self.table.getEntry(key)) |entry| {
            return entry.value_ptr.data.get();
        }

        return null;
    }

    /// Returns the number of bindings in the env
    pub fn length(self: *Env) usize {
        return self.table.count();
    }

    /// Check whether a key is bound in the env
    pub fn contains(self: *Env, key: Obj(Symbol)) bool {
        return self.table.contains(key);
    }

    /// Get a slice of the local keys of this Env
    pub fn keys(self: *Env) []Obj(Symbol) {
        return self.table.keys();
    }


    pub fn copyFromEnv(self: *Env, other: *Env) (OOM || SymbolAlreadyBound)! void {
        var it = other.table.iterator();
        while (it.next()) |entry| {
            try self.rebindCell(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    pub fn copyFromTable(self: *Env, table: *const Table) (OOM || SymbolAlreadyBound)! void {
        var it = table.iterator();
        while (it.next()) |entry| {
            try self.rebind(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    /// Set a cell associated with a key
    ///
    /// If the key is already bound, overwrites the old one
    ///
    /// Returns an error if:
    /// * Rml is out of memory
    pub fn rebindCell(self: *Env, key: Obj(Symbol), cell: Obj(Rml.Cell)) OOM! void {
        try self.table.put(self.allocator, key, cell);
    }

    /// Bind a cell to a new key
    ///
    /// Returns an error if:
    /// * a value with the same name was already declared in this scope
    /// * Rml is out of memory
    pub fn bindCell(self: *Env, key: Obj(Symbol), cell: Obj(Rml.Cell)) (OOM || SymbolAlreadyBound)! void {
        if (self.contains(key)) return error.SymbolAlreadyBound;

        try self.table.put(self.allocator, key, cell);
    }

    pub fn bindNamespace(self: *Env, namespace: anytype) OOM! void {
        const T = @TypeOf(namespace);
        const rml = getRml(self);
        const origin = Origin.fromComptimeStr("builtin-" ++ @typeName(T));
        inline for (comptime std.meta.fields(T)) |field| {
            const sym: Obj(Symbol) = try .wrap(rml, origin, try .create(rml, field.name));

            if (comptime std.mem.startsWith(u8, @typeName(field.type), "object.Obj")) {
                self.bind(sym, @field(namespace, field.name).typeErase()) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory
                    else @panic(@errorName(err));
                };
            } else {
                const val: Obj(field.type) = try .wrap(rml, origin, @field(namespace, field.name));

                self.bind(sym, val.typeErase()) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory
                    else @panic(@errorName(err));
                };
            }
        }
    }
};
