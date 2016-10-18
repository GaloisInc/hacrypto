; --------------------------------------------------------------------
;
; sbox_canright_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains the implementation of the subBytes
; step of the AES. subBytes does the transformation on the
; AES state in R15 to R8. subBytes_rk expects an array of
; 8 variables to be passed in RCX and transforms these
; variables.
; This implementation of the S-Box transformation is based on:
; 'A Very Compact Rijndael S-box' by D. Canright. His ideas
; aiming on hardware implementations were taken as base to
; form a bitslice implementation of the sbox transformation.
;
; @author Robert Könighofer <robert.koenighofer@student.tugraz.at>
;
; This code is hereby placed in the public domain.
;
; THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
; BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
; OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
; EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
; --------------------------------------------------------------------

PUBLIC	subBytes
PUBLIC	subBytesRk

; --------------------------------------------------------------------
; The following macro transposes the state into a special domain X
; The calculation of the inverse is
; then done in this special domain, to reduce the workload. In
; addition to that, the transformation does a permutation of the
; variables in the following way:
; in:  n7 n6 n5 n4 n3 n2 n1 n0
; out: n2 n4 n1 n7 n3 n0 n5 n6
G256_newbasisA2X MACRO n7, n6, n5, n4, n3, n2, n1, n0, n1_n7 

; the following transformation has to be implemented (refer to the
; documentation for details, '+' means an exor interconnection 
; with the input)
; input:     | n0   n1   n2   n3   n4   n5   n6   n7
; ------------------------------------------------------
; output n0  | +
; output n1  | +    +                   +    +
; output n2  | +    +    +              +    +    +
; output n3  | +    +         +    +              +
; output n4  | +                   +    +    +
; output n5  | +                        +    +
; output n6  | +    +    +    +              +
; output n7  | +                        +    +    +

                    ;n0 = n0                -> OK
    MOV n1_n7,n1 
    XOR n1_n7,n7
    XOR n5, n6      ;n5 = n5^n6
    XOR n5, n0      ;n5 = n5^n6^n0          -> OK
    XOR n6, n0      ;n6 = n6^n0
    XOR n6, n1      ;n6 = n6^n0^n1
    XOR n6, n2      ;n6 = n6^n0^n1^n2
    XOR n6, n3      ;n6 = n6^n0^n1^n2^n3    -> OK  
    XOR n7, n5      ;n7 = n7^n5^n6^n0       -> OK
    XOR n1, n5      ;n1 = n1^n5^n6^n0       -> OK
    XOR n3, n4      ;n3 = n3^n4
    XOR n4, n5      ;n4 = n4^n5^n6^n0       -> OK
    XOR n2, n1_n7   ;n2 = n2^n1^n7
    XOR n2, n5      ;n2 = n2^n1^n7^n5^n6^n0 -> OK
    XOR n3, n1_n7   ;n3 = n3^n1^n7
    XOR n3, n0      ;n3 = n3^n1^n7^n0       -> OK
ENDM

; --------------------------------------------------------------------
;
; The following macro transposes the result of the inverting operation
; back from the special domain X into the normal domain A.
; In addition to that, the affine 
; transformation of the Sbox transformation is done. 
; This transformation also does a special permutation of the variables:
; in:  n7 n6 n5 n4 n3 n2 n1 n0
; out: n0 n4 n5 n2 n7 n3 n1 n6
; This permutation is designed in a way, that it removes all permutations
; previously done during the calculation of the sbox transformation.
G256_newbasisX2S MACRO n7, n6, n5, n4, n3, n2, n1, n0, n6_c, n2_c, n1_c, n0_c

; the following transformation has to be implemented (refer to the 
; documentation for details, '+' means an exor interconnection 
; with the input)
; input:     | n0   n1   n2   n3   n4   n5   n6   n7
; ------------------------------------------------------
; output n0  |                +         +
; output n1  |      +              +    +
; output n2  |                +         +         +
; output n3  | +         +    +         +    +
; output n4  |                +                   +
; output n5  | +                             +
; output n6  |      +              +         +
; output n7  |                +    +    +    +    +
    MOV n6_c, n6
    XOR n6, n4      ;n6 = n4^n6
    MOV n1_c, n1
    XOR n1, n4      ;n1 = n1^n4
    MOV n2_c, n2
    XOR n1, n5      ;n1 = n1^n4^n5       -> OK
    MOV n4, n3      ;n4 = n3
    XOR n4, n7      ;n4 = n3^n7          -> OK
    MOV n2, n4      ;n2 = n3^n7
    XOR n2, n5      ;n2 = n3^n5^n7       -> OK
    MOV n7, n2      ;n7 = n3^n5^n7
    XOR n7, n6      ;n7 = n3^n4^n5^n6^n7 -> OK
    MOV n0_c, n0
    XOR n6, n1_c    ;n6 = n1^n4^n6       -> OK
    MOV n0, n3      ;n0 = n3
    XOR n0, n5      ;n0 = n3^n5          -> OK
    MOV n5, n6_c    ;n5 = n6
    XOR n5, n0_c    ;n5 = n0^n6          -> OK
    MOV n3, n0      ;n3 = n3^n5
    XOR n3, n5      ;n3 = n0^n3^n5^n6    -> OK
    XOR n3, n2_c    ;n3 = n0^n2^n3^n5^n6 -> OK
ENDM

; --------------------------------------------------------------------
;
; This macro does a mutliplication of the value {a1,a0} with the value
; {b1,b0} in GF4 and stores the result in {a1,a0} again.
; in:  a1 a0 b1 b0
; out: a1 a0
; a1^a0 is not calculated but read from [rsp-64]
; b1^b0 is not calculated but read from [rsp-32]
; as these values occur more often and therefor can be reused.
; Refer to the documentation for more details.
G4_mul21 MACRO a1, a0, b1, b0, e 
    MOV e, [rsp-64]
    AND e, [rsp-32]
    AND a1, b1
    AND a0, b0
    XOR a1, e
    XOR a0, e
ENDM

; --------------------------------------------------------------------
;
; This macro does a mutliplication of the value {a1,a0} with the value
; {b1,b0} in GF4 and stores the result in {a1,a0} again.
; in:  a1 a0 b1 b0
; out: a1 a0
; a1^a0 is not calculated but read from [rsp-80]
; b1^b0 is not calculated but read from [rsp-48]
; as these values occur more often and therefor can be reused.
; Refer to the documentation for more details.
G4_mul22 MACRO a1, a0, b1, b0, e 
    MOV e, [rsp-80]
    AND e, [rsp-48]
    AND a1, b1
    AND a0, b0
    XOR a1, e
    XOR a0, e
ENDM

; --------------------------------------------------------------------
;
; This macro does a mutliplication of the value {a1,a0} with the value
; {b1,b0} in GF4 and stores the result in {a1,a0} again.
; in:  a1 a0 b1 b0
; out: a1 a0
; a1^a0 is not calculated but read from [rsp-72]
; b1^b0 is stored onto [rsp-32] as it is used later again
; Refer to the documentation for more details.
G4_mul11 MACRO a1, a0, b1, b0, e 
    MOV e, b1;
    XOR e, b0;
    MOV [rsp-32],e 
    AND e,[rsp-72]
    AND a1,b1
    AND a0,b0
    XOR a1,e
    XOR a0,e
ENDM

; --------------------------------------------------------------------
;
; This macro does a mutliplication of the value {a1,a0} with the value
; {b1,b0} in GF4 and stores the result in {a1,a0} again.
; in:  a1 a0 b1 b0
; out: a1 a0
; a1^a0 is not calculated but read from [rsp-88]
; b1^b0 is stored onto [rsp-48] as it is used later again
; Refer to the documentation for more details.
G4_mul12 MACRO a1, a0, b1, b0, e 
    MOV e, b1;
    XOR e, b0;
    MOV [rsp-48],e 
    AND e,[rsp-88]
    AND a1,b1
    AND a0,b0
    XOR a1,e
    XOR a0,e
ENDM


; --------------------------------------------------------------------
;
; This macro does a mutliplication of the value {a1,a0} with the value
; {b1,b0} in GF4 and stores the result in {a1,a0} again.
; in:  a1 a0 b1 b0
; out: a1 a0
; a1^a0 is stored onto [rsp-64] as it is used later again
; b1^b0 is stored onto [rsp-72] as it is used later again
; Refer to the documentation for more details.
G4_mul_store_x7x6_x3x2 MACRO a1, a0, b1, b0, e, e1 
    MOV e,a1
    XOR e,a0
    MOV [rsp-64],e
    MOV e1,b1
    XOR e1,b0
    MOV [rsp-72],e1
    AND e, e1
    AND a1, b1
    AND a0, b0
    XOR a1, e
    XOR a0, e
ENDM

; --------------------------------------------------------------------
;
; This macro does a mutliplication of the value {a1,a0} with the value
; {b1,b0} in GF4 and stores the result in {a1,a0} again.
; in:  a1 a0 b1 b0
; out: a1 a0
; a1^a0 is stored onto [rsp-80] as it is used later again
; b1^b0 is stored onto [rsp-88] as it is used later again
; Refer to the documentation for more details.
G4_mul_store_x5x4_x1x0 MACRO a1, a0, b1, b0, e, e1 
    MOV e,a1
    XOR e,a0
    MOV [rsp-80],e
    MOV e1,b1
    XOR e1,b0
    MOV [rsp-88],e1
    AND e, e1
    AND a1, b1
    AND a0, b0
    XOR a1, e
    XOR a0, e
ENDM

; --------------------------------------------------------------------
;
; This macro does a mutliplication of the value {r3,r2,r1,r0} with 
; the value {s3,s2,s1,s0} in GF16 and stores the result in 
; {r3,r2,r1,r0} again.
; in:  r3 r2 r1 r0 s3 s2 s1 s0
; out: r3 r2 r1 r0
; This is done by applying a multiplication in GF4 twice. Some
; immediate values are stored to and loaded from the memory, since
; they are needed often. Refer to the documentation for more details.
G16_mul1 MACRO r3, r2, r1, r0, s3, s2, s1, s0, t3, t2, t1 
    MOV t3, [rsp-24]
    MOV t2, s3
    XOR t2, s1;     
    MOV [rsp-24],t2
    AND t3, t2
    MOV t1, s0
    XOR t1, s2       
    MOV [rsp-56],t1
    XOR t2, t1       
    MOV [rsp-96],t2 
    AND t1,[rsp-32]
    XOR t3, t1      
    AND t2, [rsp-48]
    XOR t2, t1       
    G4_mul11 r3, r2, s3, s2, t1
    XOR r3, t2
    XOR r2, t3
    G4_mul12 r1, r0, s1, s0, t1
    XOR r1, t2
    XOR r0, t3
ENDM

; --------------------------------------------------------------------
;
; This macro does a mutliplication of the value {r3,r2,r1,r0} with 
; the value {s3,s2,s1,s0} in GF16 and stores the result in 
; {r3,r2,r1,r0} again.
; in:  r3 r2 r1 r0 s3 s2 s1 s0
; out: r3 r2 r1 r0
; This is done by applying a multiplication in GF4 twice. Some
; immediate values are stored to and loaded from the memory, since
; they are needed often. Refer to the documentation for more details.
G16_mul2 MACRO r3, r2, r1, r0, s3, s2, s1, s0, t3, t2, t1 
    MOV t3, [rsp-8]
    AND t3, [rsp-24]
    MOV t2, [rsp-16]
    AND t2, [rsp-56]
    XOR t3, t2
    MOV t1,[rsp-40]
    AND t1,[rsp-96]
    XOR t2, t1
    G4_mul21 r3, r2, s3, s2, t1
    XOR r3, t2
    XOR r2, t3
    G4_mul22 r1, r0, s1, s0, t1
    XOR r1, t2
    XOR r0, t3
ENDM

; --------------------------------------------------------------------
;
; This macro computes the inverse of {r3,r2,r1,r0} in GF16 and stores 
; the result in {r3,r2,r1,r0} again, but with the following 
; permutation:
; in:  r3, r2, r1, r0
; out: r1, r0, r3, r2
; Refer to the documentation for more details.
G16_inv MACRO r3, r2, r1, r0, e, r3_r2, r1_r0, d1, d0
    MOV r3_r2, r3
    XOR r3_r2, r2
    MOV r1_r0, r1
    XOR r1_r0, r0
    MOV e, r3_r2       
    AND e, r1_r0
    XOR e, r3
    XOR e, r1
    MOV d1, r3
    AND d1, r1
    XOR d1, e
    MOV d0, r2
    AND d0, r0
    XOR d0, e
    XOR d0, r2
    XOR d0, r0
    AND r3, d0
    AND r2, d1
    AND r1, d0
    AND r0, d1
    XOR d0, d1       
    AND r3_r2, d0    
    XOR r3, r3_r2
    XOR r2, r3_r2
    AND r1_r0, d0  
    XOR r1, r1_r0 
    XOR r0, r1_r0 
ENDM


; --------------------------------------------------------------------
;
; This macro computes the inverse of {x7-x0} in GF16 and stores 
; the result in {x7-x0} again, but with the following 
; permutation:
; in:  x7,x6,x5,x4,x3,x2,x1,x0
; out: x3,x2,x1,x0,x7,x6,x5,x4
; Refer to the documentation for more details.
G256_inv MACRO x7, x6, x5, x4, x3, x2, x1, x0, d3, d2, d1, d0, a3, a2, a1 
    MOV a3, x7
    XOR a3, x5          
    MOV [rsp-8],a3
    MOV a2, x6
    XOR a2, x4          
    MOV [rsp-16],a2 
    MOV d3, x3
    XOR d3, x1          
    MOV [rsp-24],d3 
    MOV d2, x2
    XOR d2, x0          
    MOV [rsp-32],d2 
    MOV d1, a3;
    XOR d1, a2          
    MOV [rsp-40],d1 
    AND a2, d2          
    XOR d2, d3          
    MOV [rsp-48],d2
    AND d1, d2          
    AND a3, d3          
    XOR a3, a2          
    XOR a2, d1       

    MOV d3, x7
    MOV d2, x6
    MOV d1, x5
    MOV d0, x4
    
    MOV [rsp-56],a2
    G4_mul_store_x7x6_x3x2 d3, d2, x3, x2, a2, a1
    G4_mul_store_x5x4_x1x0 d1,d0,x1,x0, a2, a1
    MOV a2,[rsp-56]

    MOV a1, x0
    XOR a1, x4
    XOR a2, a1
    XOR d1, a2
    XOR d0, a3
    XOR d3, a2
    XOR d2, a3

    XOR d0, a1
    MOV a1, x1
    XOR a1, x5
    XOR d1, a1
    XOR d2, a1
    XOR d3, x6
    XOR d3, x2
    XOR d2, x7
    XOR d2, x3
    MOV [rsp-56],x1
    MOV [rsp-96],x0
    G16_inv d3, d2, d1, d0, x1, x0, a3, a2, a1
    MOV x1,[rsp-56]
    MOV x0,[rsp-96]
    G16_mul1 x3, x2, x1, x0, d1, d0, d3, d2, a3, a2, a1
    G16_mul2 x7, x6, x5, x4, d1, d0, d3, d2, a3, a2, a1
ENDM


; --------------------------------------------------------------------
;
; This macro computes the Sbox tranformation of {i7-i0} and stores 
; the result in {i7-i0} again, but with the following 
; permutation:
; in:   i7 i6 i5 i4 i3 i2 i1 i0
; out:  i7 i6 i5 i4 i3 i2 i1 i0
; The Sbox transformation is defined as multiplicative inverse in
; GF256 followed by an affine transformation. The input values are
; transformed into a special domain X first. The inverse is then
; calculated in this domain X. After that, the affine transformation
; and the transformation back into the normal domain is done. The
; bits 0, 1, 5 and 6 would have to be inverted at the end. However this
; step is skipped to increase the performance. Instead of inverting the
; bits, the round key is modified accordingly.
SBOX MACRO i7, i6, i5, i4, i3, i2, i1, i0, t6, t5, t4, t3, t2, t1, t0 

; in:  i7 i6 i5 i4 i3 i2 i1 i0
    G256_newbasisA2X i7, i6, i5, i4, i3, i2, i1, i0, t0
; out: i2 i4 i1 i7 i3 i0 i5 i6

; in:  i2 i4 i1 i7 i3 i0 i5 i6
    G256_inv i2, i4, i1, i7, i3, i0, i5, i6, t6, t5, t4, t3, t2, t1, t0
; out: i3 i0 i5 i6 i2 i4 i1 i7

; in:  i3 i0 i5 i6 i2 i4 i1 i7
    G256_newbasisX2S i3, i0, i5, i6, i2, i4, i1, i7, t3, t2, t1, t0
; out: i7 i6 i5 i4 i3 i2 i1 i0
	
; the last step is:
    ;not i6
    ;not i5
    ;not i1
    ;not i0
; but this step can be skipped if the round key is modified 
; accordingly
ENDM


_TEXT	SEGMENT

; --------------------------------------------------------------------
;
; This method implements the SubBytes step of the AES in a bitsliced 
; way. The method updates the state, which has to be in bitslice 
; representation in the registers R8 to R15. The implementation is
; based on:
; 'A Very Compact Rijndael S-box' by D. Canright.
; The final inversion of the bits 0, 1, 5 and 6 is skipped
; to make the implementation faster. This is undone by inverting 
; the according bits of the round keys.
subBytes	PROC
; SBOX needs 96 bytes of RAM on the stack:	
; in:   R15 R14 R13 R12 R11 R10 R9 R8
    SBOX R15, R14, R13, R12, R11, R10, R9, R8, RAX, RBX, RCX, RDX, RBP, RSI, RDI
; out:  R15 R14 R13 R12 R11 R10 R9 R8   
RET
subBytes	ENDP

; --------------------------------------------------------------------
;
; This method implements the SubBytes step  of the AES in a bitsliced 
; way. The method transforms the 8 64-bit values passed in 
; RCX, which have to be in
; bitslice representation. It is used for the calculation of the
; round keys only and uses the subBytes method.
subBytesRk	PROC
    PUSH RBP
    PUSH RBX
    PUSH R12
    PUSH R13
    PUSH R14
    PUSH R15
    PUSH RSI
    PUSH RDI
    PUSH RCX
    MOV R15, [RCX+56]
    MOV R14, [RCX+48]
    MOV R13, [RCX+40]
    MOV R12, [RCX+32]
    MOV R11, [RCX+24]
    MOV R10, [RCX+16]
    MOV R9, [RCX+8]
    MOV R8, [RCX]
    CALL subBytes

; we can not skip the final inversion here:

    NOT R14
    NOT R13
    NOT R9
    NOT R8
    
    POP RCX
    MOV	[RCX+56], R15
    MOV	[RCX+48], R14
    MOV	[RCX+40], R13
    MOV	[RCX+32], R12
    MOV	[RCX+24], R11
    MOV	[RCX+16], R10
    MOV	[RCX+8], R9
    MOV	[RCX], R8
    POP RDI
    POP RSI
    POP R15
    POP R14
    POP R13
    POP R12
    POP RBX
    POP RBP
RET
subBytesRk	ENDP

END