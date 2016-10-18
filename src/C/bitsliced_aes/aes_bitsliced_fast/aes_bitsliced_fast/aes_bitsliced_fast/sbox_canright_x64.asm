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
;
; This macro does the sbox transformation of the registers x7 to x0.
; The final inversion of the bits 0, 1, 5 and 6 is skipped
; to make the implementation faster. This is undone by inverting 
; the according bits of the round keys.
;
; Don't try to understand this implementation of the SBOX Macro.
; If you intend to do so, refer to the project 'aes_bitsliced'. The
; sbox implementation is done with the same algorithm, but this version
; has some performance optimizations, which make the code unreadable.
; (all macros are inserted, instructions are permutated and temporary
; registers are sometimes renamed to save a few moves which is 
; possible because of the reordering of the instruction) 
SBOX MACRO x7, x6, x5, x4, x3, x2, x1, x0, t6, t5, t4, t3, t2, t1, t0 
    MOV t0,x1
    XOR x5,x6
    XOR t0,x7
    XOR x5,x0
    XOR x6,x1
    XOR x7,x5
    XOR x6,x3
    XOR x1,x5
    XOR x6,x0
    XOR x3,x4
    XOR x6,x2
    XOR x4,x5
    XOR x2,t0
    XOR x3,x0
    XOR x2,x5
    XOR x3,t0
    MOV t1,x4
    MOV t2,x2
    XOR t1,x7
    XOR t2,x1
    MOV [RSP-16],t1
    MOV t4,t1
    MOV t5,x0
    MOV [RSP-8],t2
    MOV t6,x3
    XOR t5,x6
    XOR t6,x5
    MOV [RSP-32],t5
    XOR t4,t2
    AND t1,t5
    MOV [RSP-24],t6 
    AND t2,t6   
    MOV [RSP-40],t4      
    XOR t5,t6        
    XOR t2,t1 
    AND t4,t5       
    MOV [RSP-48],t5  
    MOV t6,x2
    XOR t1,t4 
    AND t6,x3
    MOV [RSP-56],t1
    MOV t0,x3
    MOV t1,x2
    XOR t0,x0
    XOR t1,x4
    MOV t5,x4
    MOV [RSP-64],t1
    MOV t3,x7
    AND t1,t0
    AND t3,x6
    MOV [RSP-72],t0
    AND t5,x0
    XOR t6,t1
    XOR t5,t1
    MOV [RSP-96],x6
    MOV t1,x1
    MOV t0,x5
    XOR t1,x7
    XOR t0,x6
    MOV [RSP-80],t1
    XOR t5,t2
    MOV t4,x1
    MOV [RSP-104],x5
    AND t1,t0
    AND t4,x5
    XOR x6,x7
    MOV [RSP-88],t0
    XOR t4,t1
    XOR t3,t1
    XOR x5,x1
    MOV t1,[RSP-56]
    XOR t3,t2        
    XOR t5,x5
    XOR t3,x6
    XOR t5,x2
    XOR t1,x6
    XOR t6,x0
    XOR t4,t1
    XOR t6,t1
    XOR t4,x5
    XOR t6,x4
    MOV t2,t4
    XOR t5,x3
    XOR t2,t3
    MOV x6,t5
    MOV t0,t5
    XOR x6,t6
    AND t0,t3
    MOV x5,t2
    XOR t0,t3
    AND x5,x6
    XOR t0,t5
    XOR x5,t6
    MOV t1,t6
    XOR x5,t4
    AND t1,t4
    XOR t0,x5
    XOR t1,x5
    AND t6,t0
    AND t4,t0
    MOV x5,[RSP-104] 
    AND t5,t1
    XOR t0,t1
    AND t3,t1
    AND x6,t0 
    AND t2,t0 
    XOR t6,x6
    XOR t4,t2
    XOR t5,x6
    XOR t3,t2 
    MOV t1,t6
    MOV x6,[RSP-96]
    AND x3,t4
    XOR t1,t4
    MOV t2,[RSP-24] 
    AND x2,t4
    AND [RSP-8],t1 
    AND x5,t6
    XOR t4,t3
    AND x1,t6
    AND [RSP-64],t4
    AND x0,t3
    XOR t6,t5
    AND t4,[RSP-72]
    AND x4,t3
    AND [RSP-80],t6
    AND x7,t5   
    XOR t3,t5 
    AND t6,[RSP-88]
    AND x6,t5  
    AND t2,t1
    AND [RSP-16],t3   
    XOR x5,t6 
    MOV t5,[RSP-64]
    XOR x6,t6 
    MOV t6,t1
    XOR x3,t4 
    XOR t1,t3              
    AND t3,[RSP-32]           
    XOR x0,t4
    XOR x2,t5
    AND [RSP-40],t1
    XOR t2,t3 
    AND t1,[RSP-48]
    XOR x0,t2
    MOV t0,[RSP-8]
    XOR t1,t3
    XOR x4,t5
    MOV t3,[RSP-80]
    XOR x6,t2
    XOR x3,t1
    XOR x5,t1
    MOV t6,x0
    MOV t1,[RSP-16]
    XOR x0,x6
    XOR x1,t3
    XOR t0,t1
    XOR x7,t3
    XOR t1,[RSP-40]
    XOR x4,t0
    XOR x7,t0
    XOR x1,t1
    XOR x2,t1
    MOV t2,x1
    MOV t1,x4
    XOR x1,x6
    MOV x4,x5
    MOV x6,x2
    XOR x1,x5
    XOR x6,x3
    MOV t0,x7
    XOR x4,x6
    MOV x3,x0
    MOV x7,x5
    XOR x3,x4
    XOR x7,x2
    MOV x5,t6
    MOV x2,x7
    XOR x5,t0
    XOR x2,t1
    XOR x0,t2
    XOR x2,x5
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
    SBOX R15, R14, R13, R12, R11, R10, R9, R8, RAX, RBX, RCX, RDX, RBP, RSI, RDI
RET
subBytes	ENDP

; --------------------------------------------------------------------
;
; This method implements the SubBytes step  of the AES in a bitsliced 
; way. The method transforms the data passed in RCX (the first argument
; as uint64_t* value) , which has to be in
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
    call subBytes
; we can not skip the final inversion of the bits
; of the bits 0, 1, 5 and 6 here:
    NOT R8
    NOT R9   
    NOT R13
    NOT R14 
    
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