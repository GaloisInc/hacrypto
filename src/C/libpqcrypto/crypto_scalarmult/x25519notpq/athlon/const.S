.data
.section .rodata
.p2align 5

.globl scale
.globl _121665
.globl alpha26
.globl alpha51
.globl alpha77
.globl alpha102
.globl alpha128
.globl alpha153
.globl alpha179
.globl alpha204
.globl alpha230
.globl alpha255
.globl in0offset
.globl in1offset
.globl in2offset
.globl in3offset
.globl in4offset
.globl in5offset
.globl in6offset
.globl in7offset
.globl in8offset
.globl in9offset
.globl out0offset
.globl out1offset
.globl out2offset
.globl out3offset
.globl out4offset
.globl out5offset
.globl out6offset
.globl out7offset
.globl out8offset
.globl out9offset
.globl two0
.globl two1
.globl zero
.globl rounding

.hidden scale
.hidden _121665
.hidden alpha26
.hidden alpha51
.hidden alpha77
.hidden alpha102
.hidden alpha128
.hidden alpha153
.hidden alpha179
.hidden alpha204
.hidden alpha230
.hidden alpha255
.hidden in0offset
.hidden in1offset
.hidden in2offset
.hidden in3offset
.hidden in4offset
.hidden in5offset
.hidden in6offset
.hidden in7offset
.hidden in8offset
.hidden in9offset
.hidden out0offset
.hidden out1offset
.hidden out2offset
.hidden out3offset
.hidden out4offset
.hidden out5offset
.hidden out6offset
.hidden out7offset
.hidden out8offset
.hidden out9offset
.hidden two0
.hidden two1
.hidden zero
.hidden rounding

scale:
	.long 0x0,0x30430000
_121665:
	.long 0x0,0x40fdb410
in0offset:
	.long 0x0,0x43300000
in1offset:
	.long 0x0,0x45300000
in2offset:
	.long 0x0,0x46b00000
in3offset:
	.long 0x0,0x48300000
in4offset:
	.long 0x0,0x49b00000
in5offset:
	.long 0x0,0x4b300000
in6offset:
	.long 0x0,0x4d300000
in7offset:
	.long 0x0,0x4eb00000
in8offset:
	.long 0x0,0x50300000
in9offset:
	.long 0x0,0x51b00000
alpha26:
	.long 0x0,0x45880000
alpha51:
	.long 0x0,0x47180000
alpha77:
	.long 0x0,0x48b80000
alpha102:
	.long 0x0,0x4a480000
alpha128:
	.long 0x0,0x4be80000
alpha153:
	.long 0x0,0x4d780000
alpha179:
	.long 0x0,0x4f180000
alpha204:
	.long 0x0,0x50a80000
alpha230:
	.long 0x0,0x52480000
alpha255:
	.long 0x0,0x53d80000
two0:
	.long 0x0,0x3ff00000
two1:
	.long 0x0,0x40000000
zero:
	.long 0x0,0x0
out0offset:
	.long 0x1fffffed,0x43380000
out1offset:
	.long 0xffffff8,0x44d80000
out2offset:
	.long 0x1ffffff8,0x46680000
out3offset:
	.long 0xffffff8,0x48080000
out4offset:
	.long 0x1ffffff8,0x49980000
out5offset:
	.long 0xffffff8,0x4b380000
out6offset:
	.long 0x1ffffff8,0x4cc80000
out7offset:
	.long 0xffffff8,0x4e680000
out8offset:
	.long 0x1ffffff8,0x4ff80000
out9offset:
	.long 0x1fffff8,0x51980000
rounding:
	.byte 0x7f
	.byte 0x13
