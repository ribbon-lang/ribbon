print-ln "hello world"
local foo = 1
local var = fun() nil
local jazz = "test"
local (x y) = '(1 2)

local check = fun{* args} print-ln args
check 1 2 3 4 5
check 1 2
check 1
(check)

local check2 = fun
    (1 2)
        print-ln "let me see u one, two step"
    {+ args}
        print-ln args
    else
        print-ln "no args"
check2 1 2 3 4 5
check2 1 2
check2 1
(check2)

local foo = fun x
    print-ln x
    + x 1

print-ln "woo " (foo 1)
print-ln (not true)
print-ln 'foo

print-ln `(1 2 3)
print-ln `(1 2 ,(foo 2))
print-ln `(1 2 ,@'(3 4))


local incrBy = fun x
    fun y
        + x
          y
local incr = incrBy 2

print-ln (incr 1)
print-ln (incr 2)


local mac = macro (x) `(print-ln ,x)
mac 1



local closure = fun x
    (local a = fun y
        + x y)
    (local b = fun y
        set! x y)
    `(,a ,b)

local (a b) = closure 1

a 1

b 2

a 1



; global one-hundred = 100
; print-ln one-hundred



; import type

; print-ln (type/nil? nil)
; print-ln (type/nil? 1)

; print-ln (type/string? "foo")
; print-ln (type/string? 1)

; import String

; print-ln (String/length "test")
