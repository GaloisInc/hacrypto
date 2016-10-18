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
    MOV RAX,a1
    MOV RDX,a2
    SHR RAX,n
    SHR RDX,n
    XOR RAX,b1
    XOR RDX,b2
    AND RAX,m
    AND RDX,m
    XOR b1,RAX
    XOR b2,RDX
    SHL RAX,n
    SHL RDX,n
    XOR a1,RAX
    XOR a2,RDX
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
; Refer to mu for more details.
muInv	PROC

    doubleSwapmove R8, R12,R9, R13, 4, mask3
    doubleSwapmove R10, R14,R11, R15, 4, mask3

    doubleSwapmove R8, R10,R9, R11, 2, mask2
    doubleSwapmove R12, R14,R13, R15, 2, mask2

    doubleSwapmove R8, R9,R10, R11, 1, mask1
    doubleSwapmove R12, R13,R14, R15, 1, mask1

    doubleSwapmove R15,R11,R14,R10,32,mask6
    doubleSwapmove R11,R15,R10,R14,16,mask5
    doubleSwapmove R15,R11,R14,R10,8,mask4
    doubleSwapmove R13,R9,R12,R8,32,mask6
    doubleSwapmove R9,R13,R8,R12,16,mask5
    
; storing the results is merged with the last call of
; doubleSwapmove for performance reasons:    
    MOV RBX,[RCX]      ;RBX = pointer to block 0   
    MOV RAX,R13
    MOV RBP,[RCX+8]    ;RBP = pointer to block 1
    MOV RDX,R12
    MOV RDI,[RCX+16]   ;RDI = pointer to block 2
    SHR RAX,8
    MOV RSI,[RCX+24]   ;RSI = pointer to block 3 
    SHR RDX,8
    MOV [RBP],R10      ;R10 = low 64 bytes of block 1
    XOR RAX,R9
    XOR RDX,R8
    MOV [RBX+8],R15    ;R15 = high 64 bytes of block 0
    AND RAX,mask4
    AND RDX,mask4
    MOV [RBP+8],R14    ;R14 = high 64 bytes of block 1
    XOR R9,RAX
    XOR R8,RDX
    MOV [RBX],R11      ;R11 = low 64 bytes of block 0
    SHL RAX,8
    MOV [RDI],R9       ;R9 = low 64 bytes of block 2
    SHL RDX,8
    MOV [RSI],R8       ;R8 = low 64 bytes of block 3   
    XOR R13,RAX
    MOV [RDI+8],R13    ;R13 = high 64 bytes of block 2
    XOR R12,RDX
    MOV [RSI+8],R12    ;R12 = high 64 bytes of block 3

RET
muInv	ENDP

END