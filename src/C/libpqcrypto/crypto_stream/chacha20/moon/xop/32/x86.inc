.macro SECTION_TEXT
	.text
.endm

.macro SECTION_RODATA
	.text
.endm

.macro FN name
	\name:
.endm

.macro FN_END name
	.size \name, .-\name
	.type \name, @function
.endm

.macro GLOBAL name
	.globl \name
.endm

.macro HIDDEN name
	.hidden \name
.endm

.macro GLOBAL_HIDDEN_FN name
	GLOBAL \name
	HIDDEN \name
	FN \name
.endm

.macro GLOBAL_HIDDEN_FN_EXT name, args, xmmused
	GLOBAL \name
	HIDDEN \name
	FN \name
.endm

.macro LOAD_VAR_PIC var, reg
#if defined(__i386__)
	call 1f
	1:
	popl \reg
	leal \var - 1b(\reg), \reg
#else
	leaq \var(%rip), \reg
#endif
.endm
