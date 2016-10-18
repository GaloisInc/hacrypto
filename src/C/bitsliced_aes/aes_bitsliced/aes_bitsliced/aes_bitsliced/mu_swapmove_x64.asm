; --------------------------------------------------------------------
;
; mu_swapmove_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains the implementation of the mu method and the
; murk method in x64 assembler. These methods are used to transform
; 4 blocks of data in normal representation into bitslice 
; representation.
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

PUBLIC	mu
PUBLIC	murk

; --------------------------------------------------------------------
;
; This macro replaces the bits in b masked by m with
; the bits in a masked by m<<n. It was taken from
; 'An Implementation of Bitsliced DES on the Pentium MMX Processor'
; by Lauren May, Lyta Penna and Andrew Clark
; RCX is used as temporary register
swapmove MACRO a, b, n, m
    MOV RCX,a
    SHR RCX,n
    XOR RCX,b
    AND RCX,m
    XOR b,RCX
    SHL RCX,n
    XOR a,RCX
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
; A detailed description why this sequence of swapmove calls leads
; to the above representation can be found in the documentation.
mu	PROC
; A pointer to an array containing pointers to the four
; message blocks is passed in RCX. First we load these
; poiters:
    MOV RBX,[RCX]      ;RBX = block 0
    MOV RBP,[RCX+8]    ;RBP = block 1
    MOV RDI,[RCX+16]   ;RDI = block 2
    MOV RSI,[RCX+24]   ;RSI = block 3

; Now we load the actual data of the four blocks:
    MOV R8,[RSI]       ;R8 = low 64 bytes of block 3
    MOV R9,[RDI]       ;R9 = low 64 bytes of block 2
    MOV R10,[RBP]      ;R10 = low 64 bytes of block 1
    MOV R11,[RBX]      ;R11 = low 64 bytes of block 0
    MOV R12,[RSI+8]    ;R12 = high 64 bytes of block 3
    MOV R13,[RDI+8]    ;R13 = high 64 bytes of block 2
    MOV R14,[RBP+8]    ;R14 = high 64 bytes of block 1
    MOV R15,[RBX+8]    ;R15 = high 64 bytes of block 0

    swapmove r12,r8,8,mask4
    swapmove r8,r12,16,mask5
    swapmove r12,r8,32,mask6

    swapmove R13,R9,8,mask4
    swapmove R9,R13,16,mask5
    swapmove R13,R9,32,mask6

    swapmove R14,R10,8,mask4
    swapmove R10,R14,16,mask5
    swapmove R14,R10,32,mask6

    swapmove R15,R11,8,mask4
    swapmove R11,R15,16,mask5
    swapmove R15,R11,32,mask6


    swapmove R14, R15, 1, mask1
    swapmove R12, R13, 1, mask1
    swapmove R10, R11, 1, mask1
    swapmove R8, R9, 1, mask1

    swapmove R13, R15, 2, mask2
    swapmove R12, R14, 2, mask2
    swapmove R9, R11, 2, mask2
    swapmove R8, R10, 2, mask2

    swapmove R11, R15, 4, mask3
    swapmove R10, R14, 4, mask3
    swapmove R9, R13, 4, mask3
    swapmove R8, R12, 4, mask3

RET
mu	ENDP

; This method transforms the 4 blocks of 64 byte passed in 
; RCX from the normal representation into bitslice 
; representation and writes the result into the area pointed to by RDX.
; Each of the resulting registers contains one bit. 
; The elements of the byte sequence are interpreted as elements of
; a matrix of dimension 4x4, where the elements are bytes, as defined
; in the AES algorithm. The elements of this matrix are mapped
; into the bitslice representation in the following way:
;
; address RDX+64*i contains:
;row   00000000 00000000 11111111 11111111 22222222 22222222 33333333 33333333
;col   00001111 22223333 00001111 22223333 00001111 22223333 00001111 22223333 
;block 01230123 01230123 01230123 01230123 01230123 01230123 01230123 01230123 
;bit   iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii
;
; This is done by simply calling mu again.
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

    CALL mu

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