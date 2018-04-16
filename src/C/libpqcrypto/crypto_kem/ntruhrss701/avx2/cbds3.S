.data
.section .rodata
.align 32
lookup_L:
.word 0x2118
.word 0x0006
.word 0x2118
.word 0x0006
.word 0x2118
.word 0x0006
.word 0x2118
.word 0x0006
.word 0x2118
.word 0x0006
.word 0x2118
.word 0x0006
.word 0x2118
.word 0x0006
.word 0x2118
.word 0x0006
fives:
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
.word 0x5555
threes_32:
.word 0x3
.word 0x0
.word 0x3
.word 0x0
.word 0x3
.word 0x0
.word 0x3
.word 0x0
.word 0x3
.word 0x0
.word 0x3
.word 0x0
.word 0x3
.word 0x0
.word 0x3
.word 0x0
threes_32_b:
.word 0x6
.word 0x0
.word 0x6
.word 0x0
.word 0x6
.word 0x0
.word 0x6
.word 0x0
.word 0x6
.word 0x0
.word 0x6
.word 0x0
.word 0x6
.word 0x0
.word 0x6
.word 0x0
a_shifts:
.word 0
.word 0x0
.word 4
.word 0x0
.word 8
.word 0x0
.word 12
.word 0x0
.word 16
.word 0x0
.word 20
.word 0x0
.word 24
.word 0x0
.word 28
.word 0x0
b_shifts:
.word 1
.word 0x0
.word 5
.word 0x0
.word 9
.word 0x0
.word 13
.word 0x0
.word 17
.word 0x0
.word 21
.word 0x0
.word 25
.word 0x0
.word 29
.word 0x0
.text
.hidden cbdS3
.global cbdS3
.att_syntax prefix
cbdS3:
vmovdqa a_shifts(%rip), %ymm11
vmovdqa b_shifts(%rip), %ymm12
vmovdqa lookup_L(%rip), %ymm4
vmovdqa threes_32(%rip), %ymm8
vmovdqa threes_32_b(%rip), %ymm9
vmovdqa fives(%rip), %ymm10
vmovdqa 0(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 0(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 16(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 32(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 48(%rdi)
vmovdqa 16(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 64(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 80(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 96(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 112(%rdi)
vmovdqa 32(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 128(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 144(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 160(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 176(%rdi)
vmovdqa 48(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 192(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 208(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 224(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 240(%rdi)
vmovdqa 64(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 256(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 272(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 288(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 304(%rdi)
vmovdqa 80(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 320(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 336(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 352(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 368(%rdi)
vmovdqa 96(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 384(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 400(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 416(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 432(%rdi)
vmovdqa 112(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 448(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 464(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 480(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 496(%rdi)
vmovdqa 128(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 512(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 528(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 544(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 560(%rdi)
vmovdqa 144(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 576(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 592(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 608(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 624(%rdi)
vmovdqa 160(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 640(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 656(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 672(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 688(%rdi)
vmovdqa 176(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 704(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 720(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 736(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 752(%rdi)
vmovdqa 192(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 768(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 784(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 800(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 816(%rdi)
vmovdqa 208(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 832(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 848(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 864(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 880(%rdi)
vmovdqa 224(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 896(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 912(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 928(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 944(%rdi)
vmovdqa 240(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 960(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 976(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 992(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1008(%rdi)
vmovdqa 256(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1024(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1040(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1056(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1072(%rdi)
vmovdqa 272(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1088(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1104(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1120(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1136(%rdi)
vmovdqa 288(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1152(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1168(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1184(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1200(%rdi)
vmovdqa 304(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1216(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1232(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1248(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1264(%rdi)
vmovdqa 320(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1280(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1296(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1312(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1328(%rdi)
vmovdqa 336(%rsi), %xmm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1344(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1360(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovdqu %ymm6, 1376(%rdi)
vpshufd $57, %ymm7, %ymm7
vbroadcastss %xmm7, %ymm0
vpand %ymm10, %ymm0, %ymm1
vpsrld $1, %ymm0, %ymm0
vpand %ymm10, %ymm0, %ymm0
vpaddd %ymm0, %ymm1, %ymm1
vpsrlvd %ymm11, %ymm1, %ymm2
vpsrlvd %ymm12, %ymm1, %ymm3
vpand %ymm8, %ymm2, %ymm2
vpand %ymm9, %ymm3, %ymm3
vpslld $3, %ymm2, %ymm2
vpsrlvd %ymm2, %ymm4, %ymm5
vpsrlvd %ymm3, %ymm5, %ymm5
vpand %ymm8, %ymm5, %ymm5
vpackusdw %ymm5, %ymm5, %ymm5
vpermq $216, %ymm5, %ymm6
vmovq %xmm6, 1392(%rdi)
movq $0, 1400(%rdi)
ret
