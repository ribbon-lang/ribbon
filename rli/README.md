<!-- File generated from README.template.md -->



<div align="center">
  <img style="height: 18em"
       alt="Ribbon Language Logo"
       src="https://ribbon-lang.github.io/images/logo_full.svg"
       />
</div>

<div align="right">
  <h1>rli</h1>
  <h3>The Ribbon Lisp Interpreter</h3>
  <sup>v0.0.0</sup>
</div>

---

This is the intermediate representation for the
[Ribbon](https://ribbon-lang.github.io) programming language.

## Contents

+ [Usage](#usage)
    - [Building from source](#building-from-source)
        * [Zig Build Commands](#zig-build-commands)
        * [Zig Build Options](#zig-build-options)
    - [CLI](#cli)
        * [CLI Usage](#cli-usage)
        * [CLI Options](#cli-options)
    - [REPL](#repl)
        * [REPL Commands](#repl-commands)
    - [Inclusion as a library](#inclusion-as-a-library)
        * [From Zig](#from-zig)
        * [From C](#from-c)
        * [From other languages](#from-other-languages)
+ [Lisp dialect](#lisp-dialect)
    - [Syntax](#syntax)
    - [Environment](#environment)
        * [alist](#alist)
        * [arithmetic](#arithmetic)
        * [attr](#attr)
        * [binding](#binding)
        * [control](#control)
        * [conversion](#conversion)
        * [effect](#effect)
        * [env](#env)
        * [io](#io)
        * [list](#list)
        * [logical](#logical)
        * [meta](#meta)
        * [pair](#pair)
        * [parser](#parser)
        * [pattern](#pattern)
        * [procedure](#procedure)
        * [string](#string)
        * [symbol](#symbol)
        * [text](#text)
        * [type](#type)


## Usage

### Building from source
You will need [`zig`](https://ziglang.org/); likely, the nightly build.
The latest version known to work is `0.14.0-dev.2293+6d781e095`.

You can either:
+ Get it through [ZVM](https://www.zvm.app/) or [Zigup](https://marler8997.github.io/zigup/) (Recommended)
+ [Download it directly](https://ziglang.org/download)
+ Get the nightly build through a script like [night.zig](https://github.com/jsomedon/night.zig/)

#### Zig Build Commands
There are several commands available for `zig build` that can be run in usual fashion (i.e. `zig build run`):
| Command | Description |
|-|-|
|`run`| Build and run a quick debug test version of rli only (No headers, readme, lib ...) |
|`quick`| Build a quick debug test version of rli only (No headers, readme, lib ...) |
|`full`| Runs the following commands: test, readme, header |
|`verify`| Runs the following commands: verify-readme, verify-header, verify-tests |
|`release`| Build the release versions of rli for all targets |
|`unit-tests`| Run unit tests |
|`cli-tests`| Run cli tests |
|`c-tests`| Run C tests |
|`test`| Runs the following commands: unit-tests, cli-tests, c-tests |
|`readme`| Generate `./README.md` |
|`header`| Generate `./include/rli.h` |
|`verify-readme`| Verify that `./README.md` is up to date |
|`verify-header`| Verify that `./include/rli.h` is up to date |
|`verify-tests`| Verify that all tests pass (this is an alias for `test`) |


Running `zig build` alone will build with the designated or default target and optimization levels.

See `zig build --help` for more information.

#### Zig Build Options
In addition to typical zig build options, the build script supports the following options (though not all apply to every step):
| Option | Description | Default |
|-|-|-|
|`-DlogLevel=<log.Level>`| Logging output level to display |`.err`|
|`-DlogScopes=<string>`| Logging scopes to display |`rli,repl`|
|`-DuseEmoji=<bool>`| Use emoji in the output |`true`|
|`-DuseAnsiStyles=<bool>`| Use ANSI styles in the output |`true`|
|`-DreplDumpStdIn=<bool>`| (REPL) Default setting for dumping stdin to a file |`false`|
|`-DreplHistoryPath=<string>`| (REPL) Default path to the history file |`.rli-repl-history`|
|`-DmaxComptimeDepth=<usize>`| (Compiler Eval) Default maximum call depth |`1024`|
|`-DforceNewSnapshot=<bool>`| (Tests) Force a new snapshot to be created instead of referring to an existing one |`false`|
|`-DstripDebugInfo=<?bool>`| Override for optimization-specific settings for stripping debug info from the binary |`{ 110, 117, 108, 108 }`|


See `zig build --help` for more information.


### CLI

The `rli` executable is a work in progress, but offers a functional command line interface for Ribbon.

#### CLI Usage
```
rli [--interactive] [--dump-stdin <bool>] [--history <path>] [--disable-raw-mode] [--use-emoji <bool>] [--use-ansi-styles <bool>] [--max-comptime-depth <uint>] <path>...
```
```
rli --help
```
```
rli --version
```

#### CLI Options
| Option | Description |
|-|-|
|`--help`| Display options help message, and exit |
|`--version`| Display SemVer2 version number for rli, and exit |
|`--interactive`| Run the interpreter in REPL mode |
|`--dump-stdin <bool>`| (REPL) Dump stdin to a file [Default: false] |
|`--history <path>`| (REPL) Path to the REPL history file [Default: .rli-repl-history] |
|`--disable-raw-mode`| (REPL) Disable raw line editing mode |
|`--use-emoji <bool>`| Use emoji in the output [Default: true] |
|`--use-ansi-styles <bool>`| Use ANSI styles in the output [Default: true] |
|`--max-comptime-depth <uint>`| Maximum call stack depth for the compile time interpreter [Default: 1024; Note: going higher may cause segfaults due to native stack overflow; Minimum: 8] |
|`<path>...`| Root files to include in the compilation |


### REPL

The `rli` executable is a work in progress, but offers a functional REPL interface for Ribbon.

See [CLI](#cli) for information on how to access the REPL mode.

#### REPL Commands
| Command | Description |
|-|-|
|`:help`| Display a help message |
|`:quit`| Exit the REPL |
|`:clear-screen`| Clear the screen |
|`:clear-history`| Clear the history |
|`Ctrl`+`D`| Exit the REPL |
|`Ctrl`+`C`| Cancel current line input |


### Inclusion as a library

#### From Zig

1. Include ribbon in your `build.zig.zon` in the `.dependencies` section,
   either by linking the tar, `zig fetch`, or provide a local path to the source.
2. Add ribbon to your module imports like this:
```zig
const ribbon_c = b.dependency("ribbon-c", .{
    // these should always be passed to ensure ribbon is built correctly
    .target = target,
    .optimize = optimize,

    // additional options can be passed here, these are the same as the build options
    // i.e.
    // .logLevel = .info,
});
module.addImport("rli", ribbon_c.module("Core"));
```
3. See [`src/bin/rli.zig`](src/bin/rli.zig) for usage

#### From C

Should be straight forward, though the API is limited as of now.
Use the included header file, then link your program with the `.lib`/`.a` file.

Example of binding from C can be found at [`tests/test.c`](tests/test.c),
and at [`tests/test.sh`](tests/test.sh)

#### From other languages

If your host language has C FFI, it should be fairly straight forward.
If you make a binding for another language,
please [let me know](#discussion) and I will link it here.


## Lisp dialect

Mostly the same as other lisps, major differences as of now include:
+ No comments yet
+ Only decimal integer literals are supported as of now
+ Character literals are c-style (i.e. `'c'`, `'\x00'` etc)
+ Quasiquotes do not traverse through regular quotes; this is used to allow nested quasi logic
+ Some naming convention differences (e.g. `out<-in` conversion function names)
+ Minimal environment

### Syntax

- Nil `()`
- Symbols `foo`, `foo'`, `/`, `+inf`
- Integers `1001`, `+9`, `-32`
- Characters `'x'`, `'\x00'`, `'\esc'`, `'\t'`, `'\''`
- Floats `1.0`, `1.`, `.0`, `+1.0e-3`
- Strings `"foo"`, `"\tfoo\x00"`, `"\""`
- Pairs `(1 . 2)`, `(1 2 3 . 4)`
- Lists `(1 2 3)`, `(+ 1 2 3)`
- Quotes `'foo`, `'(1 2 3)`
- Quasiquotes
    ```
    `foo
    `(1 2 3)
    ```
- Unquote
    ```
    `(1 ,foo 3)
    ```
- Unquote splicing
    ```
    `(1 2 ,@foo)
    ```

### Environment

#### alist

This module contains functions for creating and manipulating association lists.

| Symbol | Description |
|-|-|
|`alist/pair`| lookup a key symbol in an association list, returning the pair it binds; prompts `fail` if the key is not found |
|`alist/lookup-f`| lookup a key symbol in an association list, returning its associated value; prompts `fail` if the key is not found |
|`alist/lookup`| lookup a key symbol in an association list, returning its associated value; returns `nil` if the key is not found |
|`alist/member?`| check if a key symbol is present in an association list |
|`alist/append`| append a key-value pair to an association list |
|`alist/set!`| set the value of an existing key-value pair in an association list, returning the old value; prompts `fail` if the key is not found |
|`alist/each`| calls a function with each key-value pair in an association list |
|`alist/keys`| get the keys of a given association list |

#### arithmetic

This module provides basic arithmetic functions, constants, and predicates.

| Symbol | Description |
|-|-|
|`add`, `+`| integer/floating point addition on any number of values |
|`sub`, `-`| integer/floating point subtraction on any number of values |
|`mul`, `*`| integer/floating point multiplication on any number of values |
|`div`, `/`| integer/floating point division on any number of values |
|`mod`, `%`| integer/floating point remainder division on any number of values |
|`pow`, `^`| integer/floating point exponentiation on any number of values |
|`nan?`| check if input is not a number |
|`inf?`| check if input is a floating point infinity |
|`-inf?`| check if input is a negative floating point infinity |
|`+inf?`| check if input is a positive floating point infinity |
|`inf`| floating point infinity constant |
|`nan`| floating point not a number constant |
|`max-int`| the maximum possible integer constant |
|`min-int`| the minimum possible integer constant |
|`epsilon`| the minimum difference between two floating point numbers constant |
|`floor`| round a floating point number down |
|`ceil`| round a floating point number up |
|`round`| round a floating point number |
|`frac`| take the fractional part of a floating point number |

#### attr

This module provides functions for the creation, access and transformation
of source-attribution primitives.

| Symbol | Description |
|-|-|
|`attr/here`| create a source attribution referencing the call location |
|`attr/filename`| get the filename stored in an Attr |
|`attr/range`| get the range stored in an Attr |
|`attr/new`| create a new Attr from a filename string and a range object |
|`attr/of`| extract the Attr from a value |
|`attr/set!`| set the Attr of a value; returns the old Attr |

#### binding

This module provides special forms for defining and manipulating
bindings in the current environment.

`let` creates a new environment frame with the given bindings,
and evaluates the body in that frame.
> ##### Example
> ```lisp
> (let ((x (+ 1 1))
>       (fun f (x) (+ x 1))
>       (macro m (x) `(f ,x)))
>   (action1 x)
>   (action2 (f x))
>   (action3 (m x)))
> ```

`def`, `def fun`, and `def macro` forms mirror the syntax of `let`,
but bind individual symbols in the current environment.
> ##### Example
> ```lisp
> (def x (+ 1 1))
> (def fun f (x) (+ x 1))
> (action1 x)
> (action2 (f x))
> ```

`bound?` and `set!` can be used to query and manipulate
bindings created with any of the above forms.

| Symbol | Description |
|-|-|
|`def`| define a new variable |
|`let`| create local value bindings |
|`bound?`| check if a given symbol is bound in the current env |
|`set!`| set the value of a symbol in the current env. symbol must already be bound. returns old value |

#### control

This module provides special forms for controlling the flow of execution.

`if` is a one or two option conditional branch.
> ##### Example
> ```lisp
> (if x (conditional-action))
> (if y (conditional-action) (else-action))
> ```

`cond` is a multi-option conditional branch.
> ##### Example
> ```lisp
> (cond
>   (x (conditional-action1))
>   (y (conditional-action2))
>   (else (default-action)))
> ```

`match` uses lambda lists to perform structural pattern matching on an input.
> ##### Example
> ```lisp
> (match x
>   ((0) (conditional-action0))
>   ((x) (conditional-action1 x))
>   ((x y) (conditional-action2 x y))
>   ((x y . z) (conditional-action3 x y z))
>   (else (default-action)))
> ```
For more information on the syntax of lambda lists, see the [`Pattern` module](#pattern).

`begin` allows for sequencing expressions.
> ##### Example
> ```lisp
> (begin
>   (action1)
>   (action2))
> ```
| Symbol | Description |
|-|-|
|`if`| two-option conditional branch |
|`when`| single-option conditional branch, taken if the condition is true |
|`unless`| single-option conditional branch, taken if the condition is false |
|`cond`| multi-option conditional branch |
|`match`| pattern based matching on any inputt |
|`begin`| allows sequencing expressions |
|`panic`| runs `format` on the values provided and then triggers a panic with the resulting string |
|`panic-at`| uses the first argument as the source attribution for the panic; runs `format` on subsequent values provided and then triggers a panic with the resulting string |
|`throw`| prompts `exception` with the value provided; this is a shortcut for `(prompt exception arg)` |
|`stop`| prompts `fail`; this is a shortcut for `(prompt fail)` |
|`assert`| asserts that a condition is true; if it is not, triggers a panic with the subsequent arguments, or with the condition itself if none were provided |
|`assert-eq`| asserts that the first two values provided are equal, using structural equality on objects; if they are not, triggers a panic with any subsequent values provided, or with the condition if none were |
|`assert-eq-addr`| asserts that the first two values provided are equal, using address equality on objects; if they are not, triggers a panic with any subsequent values provided, or with the condition if none were |
|`assert-at`| asserts that a condition is true; if it is not, triggers a panic with the subsequent arguments, or with the condition itself if none were provided |
|`assert-eq-at`| asserts that the first two values provided are equal, using structural equality on objects; if they are not, triggers a panic with any subsequent values provided, or with the equality inputs if none were |
|`assert-eq-addr-at`| asserts, using the location provided as the first argument, that the next two values provided are equal, using address equality on objects; if they are not, triggers a panic with any subsequent values provided, or with the equality inputs if none were |
|`e-assert`| asserts that a condition is true; if it is not, prompts `exception` with the second value provided or with the symbol `AssertionFailed` if one is not |
|`e-assert-eq`| asserts that the first two values provided are equal, using structural equality on objects; if they are not, prompts `exception` with any subsequent values provided, or with the condition if none were |
|`e-assert-eq-addr`| asserts that the first two values provided are equal, using address equality on objects; if they are not, prompts `exception` with any subsequent values provided, or with the condition if none were |
|`f-assert`| asserts that a condition is true; if it is not, prompts `fail` |
|`f-assert-eq`| asserts that the two values provided are equal, using structural equality on objects; if they are not, prompts `fail` |
|`f-assert-eq-addr`| asserts that the two values provided are equal, using address equality on objects; if they are not, prompts `fail` |

#### conversion

This module provides functions for converting between specific types,
as well as converting between arbitrary values and strings.

| Symbol | Description |
|-|-|
|`bool<-int`| convert an integer to a boolean |
|`int<-bool`| convert a boolean to an integer |
|`int<-char`| convert a character to an integer |
|`char<-int`| convert an integer to a character |
|`int<-float`| convert a float to an integer |
|`float<-int`| convert an integer to a float |
|`string<-symbol`| convert a symbol to a string |
|`symbol<-string`| convert a string to a symbol |
|`list<-string`| convert a string to a list of characters |
|`string<-list`| convert a list of characters to a string |
|`stringify`| convert any value to a string representation; optionally accepts two parameters where the first may be a symbol of the set `Display`, `Attr`, `Dotted`, or `Source`, indicating the way in which to format the second value |
|`unstringify`| convert a string representation to a value |

#### effect

This module provides an api to trigger and handle
arbitrary user-defined side effects at compile time.
The special forms `with` and `with-global` provide a `let`-like syntax for binding
functions, macros, and variables to symbols in a special dynamic environment,
which can be accessed with the `fetch` and `prompt` special forms.

The three kinds of bindings are discriminated
by a keyword at the head of the binding:
> ```lisp
> (with ((kind name def)...) body...)
> (with-global (kind name def)...)
> ```
> Where `kind` is one of:
> + `fun` for lambda-like effect handlers
> + `macro` for macro-like effect handlers
> + [none] simple variable bindings

Values created via `with` and `with-global` are provided a special binding, `terminate`,
which can be called to cancel the inner computation of
the `with` they are bound to, and return a value in its place.
> [!Caution]
> In the case of terminate being called from a `with-global` binding,
> the computation being terminated is the entire compilation.

> [!Caution]
> Macros calling `terminate` will need to manually evaluate
> their termination value if it requires it;
> all termination values are passed as-is

> ##### Example
> ```lisp
> (with ((fun abort (x) (terminate x))
>        (macro error (x) (prompt abort (interpreter x)))
>        (abort2 terminate))
>   (action1)
>   (action2))
> ```

Some builtin effects can also be handled via `with`/`with-global`;
for example `exception` and `fail`, which are triggered by some builtins.

Items bound this way can be accessed with `prompt` and `fetch`:
+ `fetch` simply retrieves the value
+ `prompt` retrieves and then invokes the value with a given list of arguments

| Symbol | Description |
|-|-|
|`with-global`| provide one or more named *top-level* effect handlers to serve as a last resort; note that the `terminate` which is provided to handlers bound this way will terminate the interpreter |
|`with`| provide one or more named effect handlers, and an expression to execute under them |
|`fetch`| get a dynamically bound variable or effect handler from its binding symbol |
|`prompt`| defer execution to a named effect handler; `(prompt sym args...)` is equivalent to `((fetch sym) args...)` |

#### env

This module contains functions manipulation of environments.

| Symbol | Description |
|-|-|
|`env/keys`| get the names of all bindings in the given env |
|`env/lookup-f`| lookup a key symbol in an environment, returning the value it binds; prompts `fail` if the key is not found |
|`env/lookup`| lookup a key symbol in an environment, returning the value it binds; returns `nil` if the key is not found |
|`env/pair`| lookup a key symbol in an environment, returning the pair it binds; prompts `fail` if the key is not found |
|`env/set!`| set the value associated with a name in an environment, returning the old value; prompts `fail` if the name is not bound |
|`env/put!`| append a key-value pair to the top frame of an environment |
|`env/copy`| copy a given environment |
|`env/new`| make a new environment from a simple a-list |
|`env/get-frame`| get the environment frame at the given offset depth; prompts `fail` if the depth is out of bounds |
|`env/push`| push a given environment frame into the current environment, returning the modified enviroment |
|`env/pop`| pop an environment frame off the current environment, returning it and the modified environment as a pair `(frame . env)`; prompts `fail` if the environment is empty |

#### io

This module provides functions for interacting with the file system.
Many of these will likely be converted to prompts in the future.

Also available here are the std-io constants `std-in`, `std-out`, and `std-err`,
which refer to file descriptors usable by `read-file`, `write-file` and their related functions.

| Symbol | Description |
|-|-|
|`io/open-file`| open a file at the provided path; accepts mode symbol `'r`, `'w`, or `'rw`; prompts an exception if it fails |
|`io/read-file`| read the content of a text file to a string; if a second parameter is given it is expected to be the length in bytes to read, otherwise reads the whole file; prompts an exception if it fails |
|`io/read-ln`| read a single line of a text file to a string; prompts an exception if it fails |
|`io/write-file`| write a string to a file; prompts an exception if it fails |
|`io/write-ln`| write an optional string to a file, then write a new line; prompts an exception if it fails |
|`print`| stringify all* arguments with `'Display`, concatenate, then `write-file` with the resulting string; if the first parameter is a file, prints to that file instead of std-out; prompts an exception if it fails |
|`print-ln`| stringify all* arguments with `'Display`, concatenate, then `write-ln` with the resulting string; if the first parameter is a file, prints to that file instead of std-out; prompts an exception if it fails |
|`io/file-end`| get the cursor position that marks the end of a file; prompts an exception if it fails |
|`io/file-cursor`| get the current cursor position in a file; prompts an exception if it fails |
|`io/file-cursor!`| set the current cursor position in a file; prompts an exception if it fails |
|`io/std-in`| the input file constant |
|`io/std-out`| the output file constant |
|`io/std-err`| the error file constant |

#### list

This module contains functions for creating and manipulating lists.

| Symbol | Description |
|-|-|
|`nil`| the empty list constant |
|`list`| create a new list, with any number of values |
|`list/length`| get the length of a list |
|`list/map`| apply a function to each element of a list, returning a new list of the results |
|`list/each`| apply a function to each element of a list |
|`list/member?`| determine if a given value is contained in a list |

#### logical

This module contains functions and primitives for logical operations,
such as comparison and boolean algebra.

Additionally, there is the `truthy?` function, which converts
any value into a boolean, as well as the constants `true` and `false.`

| Symbol | Description |
|-|-|
|`eq?`, `==`| determine if any number of values are equal; uses structural comparison |
|`not-eq?`, `/=`| determine if any number of values are not equal; uses structural comparison |
|`less?`, `<`| determine if any number of values are in order of least to greatest; uses structural comparison |
|`greater?`, `>`| determine if any number of values are in order of greatest to least; uses structural comparison |
|`less-or-equal?`, `<=`| determine if any number of values are in order from least to greatest, allowing adjacent values to be equal; uses structural comparison |
|`greater-or-equal?`, `>=`| determine if any number of values are in order from greatest to least, allowing adjacent values to be equal; uses structural comparison |
|`eq-addr?`, `==*`| determine if any number of values are equal; uses address comparisons for object types |
|`not-eq-addr?`, `/=*`| determine if any number of values are not equal; uses address comparisons for object types |
|`less-addr?`, `<*`| determine if any number of values are in order of least to greatest; uses address comparisons for object types |
|`greater-addr?`, `>*`| determine if any number of values are in order of greatest to least; uses address comparisons for object types |
|`less-or-equal-addr?`, `<=*`| determine if any number of values are in order from least to greatest, allowing adjacent values to be equal; uses address comparisons for object types |
|`greater-or-equal-addr?`, `>=*`| determine if any number of values are in order from greatest to least, allowing adjacent values to be equal; uses address comparisons for object types |
|`not`, `!`| logical not, performs truthy conversion |
|`and`, `&&`| logical and accepting any number of values, short circuiting. performs truthy conversion for tests and returns the first failing value |
|`or`, `\|\|`| logical or accepting any number of values, short circuiting. performs truthy conversion for tests and returns the first succeeding value |
|`truthy?`| performs truthy conversion |
|`true`| boolean constant |
|`false`| boolean constant |

#### meta

This module contains functions for converting data to syntax,
and for direct access and manipulation of the execution environments.

See [Syntax](#syntax) for more information on the syntax of `quote` and `quasiquote`.

| Symbol | Description |
|-|-|
|`quasiquote`| a quote accepting `unquote` and `unquote-splicing` in its body |
|`quote`| makes a given input into its literal equivalent by skipping an evaluation step |
|`meta/eval`| evaluate a given expression in the current env or an optional provided env |
|`meta/gensym`| generate a unique symbol |
|`meta/swap-env`| replace the current environment with the given one, returning the old one; optionally accepts `'self` `'caller` or `'evidence` symbols indicating which environment to effect |
|`meta/take-env`| take the current environment, leaving it empty; optionally accepts `'self` `'caller` or `'evidence` symbols indicating which environment to effect |
|`meta/get-env`| take a copy of the current environment, leaving it in place; optionally accepts `'self` `'caller` or `'evidence` symbols indicating which environment to effect |
|`meta/replace-env`| replace the current environment with the given one; optionally accepts `'self` `'caller` or `'evidence` symbols indicating which environment to effect |
|`meta/get-global-evidence`| get the global evidence environment frame |
|`meta/set-global-evidence`| set the global evidence environment frame |
|`ls`| shortcut for `(each (env/keys (meta/get-env)) (key . val) (print-ln key " : " (type/of val)))`; optionally accepts `'self` `'caller` or `'evidence` symbols indicating which environment to list |

#### pair

This module contains functions for creating and manipulating pairs.

| Symbol | Description |
|-|-|
|`pair/cons`| join a head and tail into a pair |
|`pair/car`| get the head of a pair |
|`pair/set-car!`| set the head of a pair; returns the old value |
|`pair/cdr`| get the tail of a pair |
|`pair/set-cdr!`| set the tail of a pair; returns the old value |

#### parser

This module provides access to Ribbon's parser from within the language.

> ##### Example
> ```lisp
> (def p (parser/new))
> (def first-ln "(print-ln \"hello world\")")
> (def line-len (string-length first-ln))
> (parser/filename! p "foo")
> (parser/input! p
>     (string-intercalate "\n"
>         first-ln
>         "(print-ln \"goodbye world\")"
>         "(+ 1 2)")
>     '((2 . 1) . 0))
> (def res1 (parser/parse-sexpr! p))
> (assert-eq
>     (cdr (attr-range (attr-of res1)))
>     (cons (cons 2 (+ 1 line-len)) line-len))
> (interpreter res1)
> (interpreter (parse-sexpr! p))
> (assert-eq (interpreter (parse-sexpr! p)) 3)
> (assert (parser/eof? p))
> ```
| Symbol | Description |
|-|-|
|`parser/new`| create a parser object |
|`parser/filename!`| set the file name of the given parser; returns old value |
|`parser/filename`| get the file name of the given parser |
|`parser/input!`| set the input of the given parser, optionally providing a position offset; returns old values as a pair |
|`parser/input`| get the input of the given parser |
|`parser/parse-sexpr!`| parse an S-expression from the given parser's input; prompts `exception` with an error symbol if an error is encountered; prompts `fail` if there was nothing to parse |
|`parser/eof?`| determine whether a parser is at the end of its input |

#### pattern

##### Supported pattern syntax
- `optional` = `(? var)`
    > if there are arguments remaining, apply `var` to the next argument; otherwise any bindings within `var` are `nil`
- `rest` = `(... symbol)`
    > if there are arguments remaining, bind the rest of the arguments to `symbol`; otherwise bind `nil`
- `cons` = `. var`
    > if there are arguments remaining, bind the rest of the arguments to `var`; otherwise bind `nil`
- `var` =
    + `(var* optional* rest? cons?)`
        > expect a list of `var`s, or the empty list
    + `,expr`
        > same as quasiquote's unquote, evaluate `expr` and apply it to the next argument
    + `(@ symbol var)`
        > match the given `var`, then bind it to the given `symbol` (ie `(@ foo 1)` matches the number `1` and binds it to `foo`)
    + `(: predicate)`
        > expect a value that satisfies the given `predicate`
    + `(-> translator-function var*)`
        > apply the given `translator-function` to the argument, and bind the results to the given `var`s if any are present;
        > translator function can `(prompt fail)` to reject the match
    + `symbol`
        > bind any value to the given `symbol`
    + `'symbol`
        > expect a literal `symbol`
    + expect an exact match to the given atom:
        * `int` (ie `1`, `9900`, etc)
        * `float` (ie `1.`, `3.14e-2`, etc)
        * `char` (ie `'a'`, `'\n'`, etc)
        * `string` (ie `"hello"`, `"\x00\""`, etc)
        * `bool` (ie `true`, `false`)

Additionally, repeated binding symbols (ie `(a a)`) are allowed, and will have their bound values checked for equality with `eq?`

> ##### Example
> ```lisp
> (assert-eq
>     (pattern/run (a b) '(1 2))
>     '((b . 2) (a . 1)))
>
> (assert-eq
>     (with ((fun fail () (terminate ())))
>         (pattern/run-f (a b) '(1)))
>     ())
>
> (assert-eq
>     (pattern/run (@ a 1) 1)
>     '((a . 1)))
>
> (assert-eq
>     (pattern/run 1 1)
>     ())
>
> (assert-eq '((x . (2 3)))
>     (pattern/run
>         (-> (lambda (x) (f-assert-eq x 2) (list x 3)) . x)
>         2))
>
> (assert-eq 'okay
>     (with ((fun fail () (terminate 'okay)))
>         (pattern/run-f
>             (-> (lambda (x) (f-assert-eq x 1) (list x)) a)
>             2)))
>
> (assert-eq '((x . (1 . 2)))
>     (pattern/run
>         (@ x (: pair?))
>         '(1 . 2)))
>
> (assert-eq 'okay
>     (with ((fun fail () (terminate 'okay)))
>         (pattern/run-f
>             (@ x (: pair?))
>             1)))
> ```
| Symbol | Description |
|-|-|
|`pattern/validate`| given a pattern, returns a boolean indicating whether it is valid |
|`pattern/binders`| given a pattern, returns a list of the symbols that will be bound if it is successfully run on an input |
|`pattern/run-f`| given a pattern and an input, returns an env frame binding the symbols of the list to the values of the input, or prompts fail |
|`pattern/run-e`| given a pattern and an input, returns an env frame binding the symbols of the list to the values of the input, or prompts an exception on failure |
|`pattern/run`| given a pattern and an input, returns an env frame binding the symbols of the list to the values of the input, or causes a compile time error on failure |

#### procedure

This module provides the primitive `fun` and `macro` special forms,
which can be used anywhere to create closure-binding procedural abstractions.

The only difference between `fun` and `macro` is the timing of evaluation:
+ `fun` evaluates its arguments at the time of invocation,
  and evaluates its return value in its own environment.
+ `macro` does not evaluate its arguments,
  and evaluates its return value in the environment of the caller.

> ##### Example
> ```lisp
> (fun (x y) (+ x y))
> ```
> ```lisp
> (macro (x y) `(+ ,x ,y))
> ```
| Symbol | Description |
|-|-|
|`fun`| inline function definition |
|`macro`| inline macro definition |
|`apply`| apply a function to a list of arguments |

#### string

This module provides functions for working with strings.

The functions in this module are designed to be utf8-safe, and will
generally cause a compilation error if used improperly.

Most functions come in a codepoint-indexed and byte-index variant.

> [!Caution]
> Special care must be take in particular with the byte-indexed
> functions to avoid causing errors, as they validate that their operation is
> boundary-aligned.

| Symbol | Description |
|-|-|
|`string/empty?`| check if a value is the empty string |
|`string/length`| get the number of characters in a string |
|`string/find`| within a given string, find the character index of another string, or a character; returns nil if not found |
|`string/find-byte-offset`| within a given string, find the byte index of another string; returns nil if not found |
|`string/nth-char`| get the character at the given character index; returns nil if out of range |
|`string/index<-byte-offset`| given a string, convert a byte index within it to a character index; returns nil if out of range |
|`string/byte-offset<-index`| given a string, convert a character index within it to a byte index; returns nil if out of range or mis-aligned  |
|`string/concat`| given any number of strings or characters, returns a new string with all of them concatenated in order |
|`string/intercalate`| given a string or a char, and any number of subsequent strings or chars, returns a new string with all of the subsequent values concatenated in order with the first value in between concatenations |
|`string/sub`| given a string and two character indices, returns a new string containing the designated section; returns nil if out of range |
|`string/byte-offset-sub`| given a string and two byte indices, returns a new string containing the designated section; ; returns nil if out of range or mis-aligned |
|`format`| stringify all arguments with `'Display`, then concatenate |

#### symbol

This module provides functions for working with symbols, paralleling the [`String` module](#string).

| Symbol | Description |
|-|-|
|`symbol/empty?`| check if a value is the empty symbol |
|`symbol/length`| get the number of characters in a symbol |
|`symbol/find`| within a given symbol, find the character index of another symbol, or a character; returns nil if not found |
|`symbol/concat`| given any number of symbols or characters, returns a new symbol with all of them concatenated in order |
|`symbol/intercalate`| given a symbol or a char, and any number of subsequent symbols or chars, returns a new symbol with all of the subsequent values concatenated in order with the first value in between concatenations |
|`symbol/sub`| given a symbol and two character indices, returns a new symbol containing the designated section; returns nil if out of range |

#### text

This module provides predicate and conversion functions,
to enable working with utf8 text and utf32 codepoints.

All functions here are overloaded to work both with
single characters, as well as strings.

| Symbol | Description |
|-|-|
|`text/category`| given a char, gives a symbol representing the unicode general category |
|`text/describe-category`| given a unicode character category symbol, returns a string explaining the value |
|`text/control?`| given a string or char, checks if all characters are control characters |
|`text/letter?`| given a string or char, checks if all characters are letter characters |
|`text/mark?`| given a string or char, checks if all characters are mark characters |
|`text/number?`| given a string or char, checks if all characters are number characters |
|`text/punctuation?`| given a string or char, checks if all characters are punctuation characters |
|`text/separator?`| given a string or char, checks if all characters are separator characters |
|`text/symbol?`| given a string or char, checks if all characters are symbol characters |
|`text/math?`| given a string or char, checks if all characters are math characters |
|`text/alphabetic?`| given a string or char, checks if all characters are alphabetic characters |
|`text/id-start?`| given a string or char, checks if all characters are id-start characters char |
|`text/id-continue?`| given a string or char, checks if all characters are id-continue characters char |
|`text/xid-start?`| given a string or char, checks if all characters are xid-start characters char |
|`text/xid-continue?`| given a string or char, checks if all characters are xid-continue characters char |
|`text/space?`| given a string or char, checks if all characters are space characters |
|`text/hex-digit?`| given a string or char, checks if all characters are hexadecimal digit characters char |
|`text/diacritic?`| given a string or char, checks if all characters are diacritic characters |
|`text/numeric?`| given a string or char, checks if all characters are numeric characters |
|`text/digit?`| given a string or char, checks if all characters are digit characters |
|`text/decimal?`| given a string or char, checks if all characters are decimal digit characters char |
|`text/hex?`| given a string or char, checks if all characters are hexadecimal digit characters char |
|`text/lowercase?`| given a string or char, checks if all characters are lowercase |
|`text/uppercase?`| given a string or char, checks if all characters are uppercase |
|`text/lowercase`| given a string or char, returns a new copy with all of the characters converted to lowercase |
|`text/uppercase`| given a string or char, returns a new copy with all of the characters converted to uppercase |
|`text/casefold`| given a string or a char, returns a new copy with all characters converted with unicode case folding; note that is may require converting chars to strings |
|`text/byte-count`| given a string or a char, returns the number of bytes required to represent it as text/8 |
|`text/display-width`| given a string or a char, returns the width of the value in visual columns (approximate) |
|`text/case-insensitive-eq?`| compare two strings or chars using unicode case folding to ignore case |

#### type

This module provides facilities for the inspection of value types.

| Symbol | Description |
|-|-|
|`type/of`| get a symbol representing the type of a value |
|`type/nil?`| determine if a value is the empty list |
|`type/pair?`| determine if a value is a cons pair |
|`type/bool?`| determine if a value is a boolean |
|`type/int?`| determine if a value is an integer |
|`type/char?`| determine if a value is a character |
|`type/float?`| determine if a value is a floating point number |
|`type/string?`| determine if a value is a string |
|`type/symbol?`| determine if a value is a symbol |
|`type/function?`| determine if a value is a function |
|`type/lambda?`| determine if a value is a lambda |
|`type/macro?`| determine if a value is a macro |
|`type/extern-data?`| determine if a value is external data such as a file |
|`type/extern-function?`| determine if a value is an external function |
|`type/builtin?`| determine if a value is a builtin function |
|`type/callable?`| determine if a value is callable |
