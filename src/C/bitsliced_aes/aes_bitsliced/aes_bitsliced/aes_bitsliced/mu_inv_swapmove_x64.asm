; --------------------------------------------------------------------
;
; mu_inv_swapmove_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains the implementation of the muInv method 
; in x64 assembler. This methods is used to transform
; 4 blocks of data in bitslice representation back into the normal 
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


PUBLIC	muInv

; --------------------------------------------------------------------
;
; This macro replaces the bits in b masked by m with
; the bits in a masked by m<<n. It was taken from
; 'An Implementation of Bitsliced DES on the Pentium MMX Processor'
; by Lauren May, Lyta Penna and Andrew Clark
; RCX is used as temporary register
swapmove MACRO a, b, n, m
    MOV RAX,a
    SHR RAX,n
    XOR RAX,b
    AND RAX,m
    XOR b,RAX
    SHL RAX,n
    XOR a,RAX
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
; This method transforms the result in bitslice representation back
; into the normal representation. It expects the result to be available
; in the registers R8 to R15. The corresponding 4 blocks are written
; into the address in RCX (the first passed parameter) in normal 
; representation. This function is the inverse function to mu. It
; therefor does the same operations as mu, but in reverse order.  
; Have a look at mu for more details.
muInv	PROC

    swapmove R8, R12, 4, mask3
    swapmove R9, R13, 4, mask3
    swapmove R10, R14, 4, mask3
    swapmove R11, R15, 4, mask3

    swapmove R8, R10, 2, mask2
    swapmove R9, R11, 2, mask2
    swapmove R12, R14, 2, mask2
    swapmove R13, R15, 2, mask2

    swapmove R8, R9, 1, mask1
    swapmove R10, R11, 1, mask1
    swapmove R12, R13, 1, mask1
    swapmove R14, R15, 1, mask1

    swapmove R15,R11,32,mask6
    swapmove R11,R15,16,mask5
    swapmove R15,R11,8,mask4

    swapmove R14,R10,32,mask6
    swapmove R10,R14,16,mask5
    swapmove R14,R10,8,mask4

    swapmove R13,R9,32,mask6
    swapmove R9,R13,16,mask5
    swapmove R13,R9,8,mask4

    swapmove R12,R8,32,mask6
    swapmove R8,R12,16,mask5
    swapmove R12,R8,8,mask4

; A pointer to an array containing pointers to the four
; result blocks is passed in RCX. First we load these
; poiters:
    MOV RBX,[RCX]      ;RBX = block 0
    MOV RBP,[RCX+8]    ;RBP = block 1
    MOV RDI,[RCX+16]   ;RDI = block 2
    MOV RSI,[RCX+24]   ;RSI = block 3

; Now we store the actual results:
    MOV [RSI],R8       ;R8 = low 64 bytes of block 3
    MOV [RDI],R9       ;R9 = low 64 bytes of block 2
    MOV [RBP],R10      ;R10 = low 64 bytes of block 1
    MOV [RBX],R11      ;R11 = low 64 bytes of block 0
    MOV [RSI+8],R12    ;R12 = high 64 bytes of block 3
    MOV [RDI+8],R13    ;R13 = high 64 bytes of block 2
    MOV [RBP+8],R14    ;R14 = high 64 bytes of block 1
    MOV [RBX+8],R15    ;R15 = high 64 bytes of block 0

RET
muInv	ENDP

END