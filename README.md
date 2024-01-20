# hashcat rule minimizer

### About

This is a semi-practical toy project that implements a subset of the [Hashcat rule language](https://hashcat.net/wiki/doku.php?id=rule_based_attack).

Currently there's:
- [x] a parser
- [x] an evaluator
- [x] a very bare-bones rule minimizer
- [x] a terminal REPL
- [ ] Eventually it would be nice to make it analyze rulesets and minimize/deduplicate them (more effectively than `sort -u`)
- [ ] Filtering/mangling rules to ensure they stick to specific masks/character sets would also be nice


It looks like this:
```
=====================
\-- rulemin repl --/
 ==================
#init# eval
#dict# testWord123
#dict# MyoTHERward
#dict#
#eval# { { $A $B$C D0D0D0 K
│                                              { { $A $B$C D0D0D0 K                                              │
├────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ [RotateLeft, RotateLeft, Append(65), Append(66), Append(67), Omit(0, 1), Omit(0, 1), Omit(0, 1), SwapBack]     │
├────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ [RotateLeft, RotateLeft, Append(65), Append(66), Append(67), Omit(0, 3), SwapBack]                             │
│ testWord123                                           │                                            ord123teACB │
│ MyoTHERward                                           │                                            ERwardMyACB │
#eval# l $A } $B$C D0D0 K
│                                         l $A } $B$C D0D0 K                                         │
├────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ [Lowercase, Append(65), RotateRight, Append(66), Append(67), Omit(0, 1), Omit(0, 1), SwapBack]     │
├────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ [Lowercase, Append(65), RotateRight, Append(66), Append(67), Omit(0, 2), SwapBack]                 │
│ testWord123                                     │                                     estword123CB │
│ MyoTHERward                                     │                                     yotherwardCB │
```

### Implemented operations:

```
# 0 operands:
:
l
u
r
d
{
}
[
]
k
K

# 1 operand:
D
p
.
,
@
$
^

# two operands:
*
O
x
o
i
s
```

**Not** implemented:
- `%1s` `/` and `p` positions
```
# 0 operands:
c
C
t
f
q
4
6
M
Q
E

# 1 operand:
L
R
+
-
y
Y
e

T
'
z
Z
<
>
_
!
/
(
)

# 2 operands:
=
%

# 3 operands:
X
3
```

### Fuzzing

```shell
# may need: cargo install cargo-fuzz
cd rulelib
cargo fuzz build
cargo fuzz run fuzz_target_1 -- -max_len=200
```
