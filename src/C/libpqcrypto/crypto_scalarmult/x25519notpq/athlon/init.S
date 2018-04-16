.text
.p2align 5
.globl _initrounding
.globl initrounding
_initrounding:
initrounding:
mov %esp,%eax
and $31,%eax
add $0,%eax
sub %eax,%esp
fldcw rounding
add %eax,%esp
ret
