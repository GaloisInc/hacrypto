; --------------------------------------------------------------------
;
; mix_cols_rl16_add_rk_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains the implementation of the mixColumnsRL16AddRk
; method in x64 assembler. This method does the mixColumn step of
; the AES in the bitslice domain, with a rotation of the result
; to the left by 16 positions followed by the AddRoundKey step.
; The two steps are merged for performance reasons.
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

PUBLIC	mixColumnsRL16AddRk

_TEXT	SEGMENT

; --------------------------------------------------------------------
;
; This method implements the MixColumns step with an additinal rotation
; to the left by 16 positions and the AddRoundKey step
; of the AES in a bitsliced way. These two operations are put together
; for performance reasons. The argument passed in RCX is the round key to be
; used for the key addition. It has to be in bitslice representation
; as produced by the initKey method. The method updates the 
; state, which has to be in bitslice representation in the registers
; R8 to R15 as well. The additional rotation to the left by 16
; positions is done to undo the rotation to the right by 16 positions
; done by shiftRowsRR16. The ShiftRows step can be done faster with
; an rotation to the right, and for the MixColumns step, any rotation
; by a multiple of 16 does not make any difference in the performance.

mixColumnsRL16AddRk	PROC

; The following equations calculate the MixColumns step where the
; result is rotated to the left by 16 positions (also 
; see the documentation):
;
;  bit[0] = bit[0] ^ 
;           rotateLeft(bit[7],16) ^ 
;           rotateLeft(bit[0]^bit[7],32) ^ 
;           rotateLeft(bit[0],48);
;  bit[1] = bit[1] ^ 
;           rotateLeft(bit[0]^bit[7],16) ^  
;           rotateLeft(bit[0] ^bit[7]^bit[1],32) ^ 
;           rotateLeft(bit[1],48);
;  bit[2] = bit[2] ^ 
;           rotateLeft(bit[1],16) ^ 
;           rotateLeft(bit[1]^bit[2],32) ^ 
;           rotateLeft(bit[2],32);
;  bit[3] = bit[3] ^ 
;           rotateLeft(bit[2]^bit[7],16) ^ 
;           rotateLeft(bit[2] ^bit[7]^bit[3],32) ^ 
;           rotateLeft(bit[3],48);
;  bit[4] = bit[4] ^ 
;           rotateLeft(bit[3]^bit[7],16) ^ 
;           rotateLeft(bit[3]^bit[7]^bit[4],32) ^ 
;           rotateLeft(bit[4],48);
;  bit[5] = bit[5] ^ 
;           rotateLeft(bit[4],16) ^ 
;           rotateLeft(bit[4]^bit[5],32) ^ 
;           rotateLeft(bit[5],48);
;  bit[6] = bit[6] ^ 
;           rotateLeft(bit[5],16) ^ 
;           rotateLeft(bit[5]^bit[6],32) ^ 
;           rotateLeft(bit[6],48);
;  bit[7] = bit[7] ^ 
;           rotateLeft(bit[6],16) ^ 
;           rotateLeft(bit[6]^bit[7],32) ^ 
;           rotateLeft(bit[7],48);

; to improve the speed, we make some precalculations of values,
; which are used very often:
; t0 = bit[0] ^ rotateLeft(bit[0],16) -> RAX
; t1 = rotateLeft(bit[1],16) ^ rotateLeft(bit[1],32) -> RBX
; t2 = bit[2] ^ rotateLeft(bit[2],16) -> RBP
; t3 = rotateLeft(bit[3],16) ^ rotateLeft(bit[3],32) -> RDX
; t4 = bit[4] ^ rotateLeft(bit[4],16) -> RDI
; t5 = rotateLeft(bit[5],16) ^ rotateLeft(bit[5],32) -> RSI
; t6 = bit[6] ^ rotateLeft(bit[6],16) -> RBX
; t7 = rotateLeft(bit[7],16) ^ rotateLeft(bit[7],32) -> RAX
;
; This leads to a much faster solution than just precomputing
; bit[0]^bit[7] and bit[3]^bit[7]:
; 10 MOV         8  MOV
; 24 ROL   =>   20 ROL
; 34 XOR        27 XOR
;
; The temporary variables t0 to t7 correspond to the 
; following registers:
; t0 = RAX
; t1 = RBX
; t2 = RCX
; t3 = RDX
; t4 = RDI
; t5 = RSI
; t6 = RBP
; t7 = RAX

; The insructions where permutated in oder to achieve higher
; performance. It is thus not easy in this version to understand
; the working principle of this algoritm. If you want to understand
; it please have a look at the 'aes_bitsliced'-project, which is
; based on the same idea but omits the permutation of the
; instructions.

    MOV RBX,R9
    MOV RAX,R8
    ROL RBX,16
    ROL RAX,16
    XOR RBX,R9
    XOR RAX,R8    ; t0 = bit[0]^rl(bit[0],16)
    ROL RBX,16    ; t1 = rl(bit[1],16)^rl(bit[1],32)

    MOV RDX,R11
    MOV RBP,R10
    ROL RDX,16
    ROL RBP,16
    XOR RDX,R11
    XOR RBP,R10   ; t2 = bit[2]^rl(bit[2],16)	
    ROL RDX,16    ; t3 = rl(bit[3],16)^rl(bit[3],32)

    MOV RSI,R13
    MOV RDI,R12
    ROL RSI,16
    ROL RDI,16
    XOR RSI,R13	
    XOR RDI,R12   ;t4 = bit[4]^rl(bit[4],16)
    ROL RSI,16    ;t5 = rl(bit[5],16)^rl(bit[5],32)	
    XOR R12,RDX   ;rbit[4] = bit[4]^rl(bit[3],16)^rl(bit[3],32)
    XOR R10,RBX   ;rbit[2] = bit[2]^rl(bit[1],16)^rl(bit[1],32)
    XOR RDX,RBP   ;t3 = rl(bit[3],16)^rl(bit[3],32)^bit[2]^rl(bit[2],16)
    XOR RBX,RAX   ;t1 = rl(bit[1],16)^rl(bit[1],32)^bit[0]^rl(bit[0],16)
    ROL RDX,16    ;t3 = rl(bit[3],32)^rl(bit[3],48)^rl(bit[2],16)^rl(bit[2],32)
    ROL RBP,32    ;t2 = rl(bit[2],32)^rl(bit[2],48)
    XOR R11,RDX   ;rbit[3] = rl(bit[3],32)^rl(bit[3],48)^rl(bit[2],16)^rl(bit[2],32)
    XOR R10,RBP   ;rbit[2] = bit[2]^rl(bit[1],16)^rl(bit[1],32)^rl(bit[2],32)^rl(bit[2],48)
    ROL RAX,32    ; t0 = rl(bit[0],32)^rl(bit[0],48)
    XOR R10, [RCX+16]   ;key addition
    XOR R8,RAX    ;rbit[0] = bit[0]^rl(bit[0],32)^rl(bit[0],48)
    rol RBX,16    ;t1 = rl(bit[1],32)^rl(bit[1],48)^rl(bit[0],16)^rl(bit[0],32)
    XOR R8, [RCX]       ;key addition
    XOR R9,RBX    ;rbit[1] = bit[1]^rl(bit[1],32)^rl(bit[1],48)^rl(bit[0],16)^rl(bit[0],32)
    MOV RAX,R15
    XOR R9, [RCX+8]     ;key addition
    MOV RBX,R14
    ROL RAX,16
    ROL RBX,16
    XOR RAX,R15	
    XOR RBX,R14	  ;t6 = bit[6]^rl(bit[6],16)
    ROL RAX,16	  ;t7 = rotateLeft(bit[7],16)^rotateLeft(bit[7],32)
    XOR R14,RSI   ;bit[6] = bit[6]^rl(bit[5],16)^rl(bit[5],32)
    XOR R8,RAX
    XOR RSI,RDI   ;t5 = rl(bit[5],16)^rl(bit[5],32)^bit[4]^rl(bit[4],16)
    XOR R12,RAX
    ROL RDI,32    ;t4 = rl(bit[4],32)^rl(bit[4],48)
    XOR R9,RAX
    XOR R11,RAX
    ROL RSI,16    ;t5 = rl(bit[5],32)^rl(bit[5],48)^rl(bit[4],16)^rl(bit[4],32)
    XOR R11, [RCX+24]    ;key addition
    XOR R12,RDI   ;bit[4] = bit[4]^rl(bit[3],16)^rl(bit[3],32)^rl(bit[4],32)^rl(bit[4],48)
    XOR RAX,RBX
    XOR R12, [RCX+32]    ;key addition
    XOR R13,RSI   ;bit[5] = bit[5]^rl(bit[5],32)^rl(bit[5],48)^rl(bit[4],16)^rl(bit[4],32)
    ROL RBX,32
    XOR R13, [RCX+40]    ;key addition
    ROL RAX,16
    XOR RBX, [RCX+48]    ;key addition
    XOR R15,RAX
    XOR R14,RBX
    XOR R15, [RCX+56]    ;key addition
RET
mixColumnsRL16AddRk	ENDP

END





