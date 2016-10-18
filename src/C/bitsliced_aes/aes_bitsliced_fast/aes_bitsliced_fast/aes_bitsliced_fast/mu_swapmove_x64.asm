; --------------------------------------------------------------------
;
; mu_swapmove_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains the implementation of the muAddRk method and the
; murk method in x64 assembler. These methods are used to transform
; 4 blocks of data in normal representation into bitslice 
; representation. The muAddRk does an additional key addition. The
; key addition and the transformation are merged for performance 
; reasons.
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

PUBLIC	muAddRk
PUBLIC	murk
; --------------------------------------------------------------------
;
; The swapmove-function replaces the bits in b masked by m with
; the bits in a masked by m<<n. It was taken from
; 'An Implementation of Bitsliced DES on the Pentium MMX Processor'
; by Lauren May, Lyta Penna and Andrew Clark
; This macro applies the swapmove funkctionality twice. The bits 
; in b1 masked by m are swapped with the bits in a1 masked by m<<n
; and the bits in b2 masked by m are swapped with the bits in a2 
; masked by m<<n.
; This merging is done for a higher performance.
; RSI and RDI are used as temporary registers.
doubleSwapmove MACRO a1, b1, a2, b2, n, m
    MOV RSI,a1
    MOV RDI,a2
    SHR RSI,n
    SHR RDI,n
    XOR RSI,b1
    XOR RDI,b2
    AND RSI,m
    AND RDI,m
    XOR b1,RSI
    XOR b2,RDI
    SHL RSI,n
    SHL RDI,n
    XOR a1,RSI
    XOR a2,RDI
ENDM

_TEXT	SEGMENT
; ml64.exe does not allow the use of 64 bit constants as
; immediate values, we therefor define constants:
    mask1	QWORD	5555555555555555h
    mask2	QWORD	3333333333333333h
    mask3	QWORD	0f0f0f0f0f0f0f0fh
    mask4	QWORD	00ff00ff00ff00ffh
    mask5	QWORD	0000ffff0000ffffh
    mask6	QWORD	00000000ffffffffh

; --------------------------------------------------------------------
;
; This method transforms the 4 blocks of 64 byte passed in 
; RCX in the normal representation into bitslice 
; representation and writes the result into the registers R8 to R15.
; Also the round key for the key addition of round 0 is added.  The
; address of the round key is read from the stack.
; Each of the resulting registers contains one bit. 
; The elements of the byte sequence are interpreted as elements of
; a matrix of dimension 4x4, where the elements are bytes, as defined
; in the AES algorithm. The elements of this matrix are mapped
; into the bitslice representation in the following way:
;
; register R[8+i]:
; row   00000000 00000000 11111111 11111111 22222222 22222222 33333333 33333333
; col   00001111 22223333 00001111 22223333 00001111 22223333 00001111 22223333 
; block 01230123 01230123 01230123 01230123 01230123 01230123 01230123 01230123 
; bit   iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii
;
; In this version, some calls of doubleSwapmove are inserted and
; merged with some other code for performance reasons. The code will
; therefor not be very easy to read. Have a look at the project
; 'aes_bitsliced', where the idea is the same, but the code is much
; easier to understand.
muAddRk	PROC

;first doubleSwapmove merged with loading the bytes from the
;memory:
    MOV RSI,[RCX+24]   ;RSI = pointer to block 3
    MOV R12,[RSI+8]    ;R12 = high 64 bytes of block 3
    MOV RAX,R12
    MOV R8,[RSI]       ;R8 = low 64 bytes of block 3    
    SHR RAX,8    
    MOV RDI,[RCX+16]   ;RDI = pointer to block 2
    XOR RAX,R8    
    MOV R13,[RDI+8]    ;R13 = high 64 bytes of block 2
    AND RAX,mask4 
    MOV R9,[RDI]       ;R9 = low 64 bytes of block 2
    MOV RDX,R13   
    MOV RBX,[RCX]      ;RBX = pointer to block 0
    XOR R8,RAX
    MOV RBP,[RCX+8]    ;RBP = pointer to block 1
    SHR RDX,8
    MOV R10,[RBP]      ;R10 = low 64 bytes of block 1
    SHL RAX,8
    XOR RDX,R9 
    MOV R11,[RBX]      ;R11 = low 64 bytes of block 0
    AND RDX,mask4   
    MOV R14,[RBP+8]    ;R14 = high 64 bytes of block 1
    XOR R9,RDX
    XOR R12,RAX   
    SHL RDX,8
    MOV R15,[RBX+8]    ;R15 = high 64 bytes of block 0
    XOR R13,RDX   

    doubleSwapmove R8,R12,R9,R13,16,mask5
    doubleSwapmove R12,R8,R13,R9,32,mask6
    
    doubleSwapmove R14,R10,R15,R11,8,mask4
    doubleSwapmove R10,R14,R11,R15,16,mask5
    doubleSwapmove R14,R10,R15,R11,32,mask6


    doubleSwapmove R14, R15,R12, R13, 1, mask1
    doubleSwapmove R10, R11,R8, R9, 1, mask1

    doubleSwapmove R13, R15,R12, R14, 2, mask2
    doubleSwapmove R9, R11,R8, R10, 2, mask2

    doubleSwapmove R11, R15,R10, R14, 4, mask3
    
;last doubleSwapmove merged with the key addition:
    
    MOV RAX,[RSP+8]     ;RAX contains a pointer to round key 0
    
    XOR R15, [RAX+56]
    MOV RCX,R9
    MOV RDX,R8
    XOR R14, [RAX+48]
    SHR RCX,4
    SHR RDX,4
    XOR R11, [RAX+24]
    XOR RCX,R13
    XOR RDX,R12
    XOR R10, [RAX+16]
    AND RCX,mask3
    AND RDX,mask3
    XOR R13,RCX
    XOR R12,RDX
    XOR R13, [RAX+40]
    SHL RCX,4
    SHL RDX,4
    XOR R12, [RAX+32]
    XOR R9,RCX
    XOR R9, [RAX+8]
    XOR R8,RDX
    XOR R8, [RAX]
RET
muAddRk	ENDP

; --------------------------------------------------------------------
;
; This method transforms the 4 blocks of 64 byte passed in 
; RCX (the first argument as uint8_t**) from the normal representation 
; into bitslice  representation and writes the result into RDX (the 
; second argument as uint64_t*). Each
; element of the resulting array contains one bit. 
; The elements of the byte sequence are interpreted as elements of
; a matrix of dimension 4x4, where the elements are bytes, as defined
; in the AES algorithm. The elements of this matrix are mapped
; into the bitslice representation in the following way:

; target[i]:
; row   00000000 00000000 11111111 11111111 22222222 22222222 33333333 33333333
; col   00001111 22223333 00001111 22223333 00001111 22223333 00001111 22223333 
; block 01230123 01230123 01230123 01230123 01230123 01230123 01230123 01230123 
; bit   iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii
;
; The working principle is the same as within muAddRk, but no xor
; interconnection with the round key is done, and the results are
; written to the address RDX.
murk	PROC
    PUSH R15
    PUSH R14
    PUSH R13
    PUSH R12
    PUSH R11
    PUSH R10
    PUSH R9
    PUSH R8
    PUSH RAX
    PUSH RBX
    PUSH RBP
    PUSH RDI
    PUSH RSI
    PUSH RDX
    
    
    MOV RSI,[RCX+24]   ;RSI = pointer to block 3
    MOV R12,[RSI+8]    ;R12 = high 64 bytes of block 0
    MOV RAX,R12
    MOV R8,[RSI]       ;R8 = low 64 bytes of block 3    
    SHR RAX,8    
    MOV RDI,[RCX+16]   ;RDI = pointer to block 2
    XOR RAX,R8    
    MOV R13,[RDI+8]    ;R13 = high 64 bytes of block 0
    AND RAX,mask4 
    MOV R9,[RDI]       ;R9 = low 64 bytes of block 2
    MOV RDX,R13   
    MOV RBX,[RCX]      ;RBX = pointer to block 0
    XOR R8,RAX
    MOV RBP,[RCX+8]    ;RBP = pointer to block 1
    SHR RDX,8
    MOV R10,[RBP]      ;R10 = low 64 bytes of block 1
    SHL RAX,8
    XOR RDX,R9 
    MOV R11,[RBX]      ;R11 = low 64 bytes of block 0
    AND RDX,mask4   
    MOV R14,[RBP+8]    ;R14 = high 64 bytes of block 0
    XOR R9,RDX
    XOR R12,RAX   
    SHL RDX,8
    MOV R15,[RBX+8]    ;R15 = high 64 bytes of block 0
    XOR R13,RDX   

    doubleSwapmove R8,R12,R9,R13,16,mask5
    doubleSwapmove R12,R8,R13,R9,32,mask6
    
    doubleSwapmove R14,R10,R15,R11,8,mask4
    doubleSwapmove R10,R14,R11,R15,16,mask5
    doubleSwapmove R14,R10,R15,R11,32,mask6


    doubleSwapmove R14, R15,R12, R13, 1, mask1
    doubleSwapmove R10, R11,R8, R9, 1, mask1

    doubleSwapmove R13, R15,R12, R14, 2, mask2
    doubleSwapmove R9, R11,R8, R10, 2, mask2

    doubleSwapmove R11, R15,R10, R14, 4, mask3
    doubleSwapmove R9, R13,R8, R12, 4, mask3
  
    POP RDX
    MOV [RDX+56], R15
    MOV [RDX+48], R14
    MOV [RDX+40], R13
    MOV [RDX+32], R12
    MOV [RDX+24], R11
    MOV [RDX+16], R10
    MOV [RDX+8], R9
    MOV [RDX], R8
    POP RSI
    POP RDI
    POP RBP
    POP RBX
    POP RAX
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15
RET
murk	ENDP

END