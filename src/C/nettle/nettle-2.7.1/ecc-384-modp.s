



































	.file "ecc-384-modp.asm"
















	
	
	

.globl _nettle_ecc_384_modp
_nettle_ecc_384_modp:
	
    
  
  

	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	
	
	
	
	
	
	
	
	
	
	
	
	
	

	mov	80(%rsi), %rax
	mov	88(%rsi), %r9
	mov	%rax, %r13
	mov	%r9, %r14
	sub	%r9, %rax
	sbb	$0, %r9

	mov	%rax, %rdx
	mov	%r9, %r10
	shl	$32, %r9
	shr	$32, %rdx
	shr	$32, %r10
	or	%rdx, %r9

	xor	%r15, %r15
	add	%r13, %r9
	adc	%r14, %r10
	adc	$0, %r15

	
	add	48(%rsi), %r9
	adc	56(%rsi), %r10
	adc	$0, %r15		

	
	mov	(%rsi), %rbx
	add	%r9, %rbx
	mov	8(%rsi), %rcx
	adc	%r10, %rcx
	mov	16(%rsi), %rdx
	mov	64(%rsi), %r11
	adc	%r11, %rdx
	mov	24(%rsi), %rbp
	mov	72(%rsi), %r12
	adc	%r12, %rbp
	mov	32(%rsi), %rdi
	adc	%r13, %rdi
	mov	40(%rsi), %r8
	adc	%r14, %r8
	sbb	%r14, %r14
	neg	%r14		

	push	%rsi

	
	add	%r9, %rdx
	adc	%r10, %rbp
	adc	%r11, %rdi
	adc	%r12, %r8
	adc	$0, %r14

	
	
	
	

	mov	%eax, %eax
	mov	%r9, %rsi
	neg	%rsi
	sbb	%r10, %r9
	sbb	%r11, %r10
	sbb	%r12, %r11
	sbb	%r13, %r12
	sbb	$0, %rax

	
	mov	%rax, %r13
	sar	$32, %r13
	shl	$32, %rax
	add	%r13, %r14

	mov	%r12, %r13
	shr	$32, %r13
	shl	$32, %r12
	or	%r13, %rax

	mov	%r11, %r13
	shr	$32, %r13
	shl	$32, %r11
	or	%r13, %r12

	mov	%r10, %r13
	shr	$32, %r13
	shl	$32, %r10
	or	%r13, %r11

	mov	%r9, %r13
	shr	$32, %r13
	shl	$32, %r9
	or	%r13, %r10

	mov	%rsi, %r13
	shr	$32, %r13
	shl	$32, %rsi
	or	%r13, %r9

	add	%rsi, %rbx
	adc	%r9, %rcx
	adc	%r10, %rdx
	adc	%r11, %rbp
	adc	%r12, %rdi
	adc	%rax, %r8
	adc	$0, %r14

	
	
	
	
	mov	%r14, %r9
	mov	%r14, %r10
	mov	%r14, %r11
	sar	$63, %r14		
	shl	$32, %r10
	sub	%r10, %r9		
	sbb	$0, %r10
	add	%r14, %r11

	add	%r9, %rbx
	adc	%r10, %rcx
	adc	$0, %r11
	adc	$0, %r14

	
	mov	%r15, %r9
	mov	%r15, %r10
	shl	$32, %r10
	sub	%r10, %r9
	sbb	$0, %r10

	add	%r11, %r9
	adc	%r14, %r10
	adc	%r15, %r14
	mov	%r14, %r11
	sar	$63, %r14
	add	%r9, %rdx
	adc	%r10, %rbp
	adc	%r11, %rdi
	adc	%r14, %r8
	sbb	%r14, %r14

	
	mov	%r14, %r9
	mov	%r14, %r10
	mov	%r14, %r11
	sar	$63, %r14
	shl	$32, %r10
	sub	%r10, %r9
	sbb	$0, %r10
	add	%r14, %r11

	pop	%rsi

	sub	%r9, %rbx
	mov	%rbx, (%rsi)
	sbb	%r10, %rcx
	mov	%rcx, 8(%rsi)
	sbb	%r11, %rdx
	mov	%rdx, 16(%rsi)
	sbb	%r14, %rbp
	mov	%rbp, 24(%rsi)
	sbb	%r14, %rdi
	mov	%rdi, 32(%rsi)
	sbb	%r14, %r8
	mov	%r8, 40(%rsi)

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx

	
    
  
  
	ret



