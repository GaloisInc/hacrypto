; --------------------------------------------------------------------
;
; mix_cols_rl16_add_rk_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains the implementation of the mixColumnsRL16AddRk
; method in x64 assembler. This method does the mixColumn step of
; the AES in the bitslice domain, with a rotation of the result
; to the left by 16 positions.
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

PUBLIC	mixColumnsRL16

_TEXT	SEGMENT

; This method implements the MixColumns step 
; of the AES in a bitsliced way. The method updates the 
; state, which has to be in bitslice representation in the registers
; R8 to R15. The additional rotation to the left by 16
; positions is done to undo the rotation to the right by 16 positions
; done by shiftRowsRR16. The ShiftRows step can be done faster with
; a rotation to the right, and for the MixColumns step, any rotation
; by a multiple of 16 does not make any difference in the performance.
mixColumnsRL16	PROC

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

  MOV RAX,R8
  ROL RAX,16
  XOR RAX,R8	; t0 = bit[0]^rl(bit[0],16)

  MOV RBX,R9
  ROL RBX,16
  XOR RBX,R9
  ROL RBX,16	; t1 = rl(bit[1],16)^rl(bit[1],32)

  MOV RCX,R10
  ROL RCX,16
  XOR RCX,R10	; t2 = bit[2]^rl(bit[2],16)	

  MOV RDX,R11
  ROL RDX,16
  XOR RDX,R11
  ROL RDX,16	; t3 = rl(bit[3],16)^rl(bit[3],32)

  MOV RDI,R12
  ROL RDI,16
  XOR RDI,R12	; t4 = bit[4]^rl(bit[4],16)

  MOV RSI,R13
  ROL RSI,16
  XOR RSI,R13	
  ROL RSI,16	; t5 = rl(bit[5],16)^rl(bit[5],32)	

  MOV RBP,R14
  ROL RBP,16
  XOR RBP,R14	; t6 = bit[6]^rl(bit[6],16)


  XOR R10,RBX   ;  bit[2] = bit[2]^rl(bit[1],16)^rl(bit[1],32)
  XOR RBX,RAX   ;  t1 = rl(bit[1],16)^rl(bit[1],32)^bit[0]^rl(bit[0],16)
  ROL RBX,16    ;  t1 = rl(bit[1],32)^rl(bit[1],48)^rl(bit[0],16)^rl(bit[0],32)
  XOR R9,RBX    ;  bit[1] = bit[1]^rl(bit[1],32)^rl(bit[1],48)^rl(bit[0],16)^rl(bit[0],32)
  ROL RAX,32    ;  t0 = rl(bit[0],32)^rl(bit[0],48)
  XOR R8,RAX    ;  bit[0] = bit[0]^rl(bit[0],32)^rl(bit[0],48)
  XOR R12,RDX   ;  bit[4] = bit[4]^rl(bit[3],16)^rl(bit[3],32)
  XOR RDX,RCX   ;  t3 = rl(bit[3],16)^rl(bit[3],32)^bit[2]^rl(bit[2],16)
  ROL RDX,16    ;  t3 = rl(bit[3],32)^rl(bit[3],48)^rl(bit[2],16)^rl(bit[2],32)
  XOR R11,RDX   ;  bit[3] = rl(bit[3],32)^rl(bit[3],48)^rl(bit[2],16)^rl(bit[2],32)
  ROL RCX,32    ;  t2 = rl(bit[2],32)^rl(bit[2],48)
  XOR R10,RCX   ;  bit[2] = bit[2]^rl(bit[1],16)^rl(bit[1],32)^rl(bit[2],32)^rl(bit[2],48)
  XOR R14,RSI   ;  bit[6] = bit[6]^rl(bit[5],16)^rl(bit[5],32)
  XOR RSI,RDI   ;  t5 = rl(bit[5],16)^rl(bit[5],32)^bit[4]^rl(bit[4],16)
  ROL RSI,16    ;  t5 = rl(bit[5],32)^rl(bit[5],48)^rl(bit[4],16)^rl(bit[4],32)
  XOR R13,RSI   ;  bit[5] = bit[5]^rl(bit[5],32)^rl(bit[5],48)^rl(bit[4],16)^rl(bit[4],32)
  ROL RDI,32    ;  t4 = rl(bit[4],32)^rl(bit[4],48)
  XOR R12,RDI   ;  bit[4] = bit[4]^rl(bit[3],16)^rl(bit[3],32)^rl(bit[4],32)^rl(bit[4],48)

  MOV RAX,R15
  ROL RAX,16
  XOR RAX,R15	
  ROL RAX,16	; t7 = rl(bit[7],16)^rl(bit[7],32)

  XOR R8,RAX    ;  bit[0] = bit[0]^rl(bit[0],32)^rl(bit[0],48)^rl(bit[7],16)^rl(bit[7],32)
  XOR R9,RAX    ;  bit[1] = bit[1]^rl(bit[1],32)^rl(bit[1],48)^rl(bit[0],16)^rl(bit[0],32)^rl(bit[7],16)^rl(bit[7],32)
  XOR R11,RAX   ;  bit[3] = rl(bit[3],32)^rl(bit[3],48)^rl(bit[2],16)^rl(bit[2],32)^rl(bit[7],16)^rl(bit[7],32)
  XOR R12,RAX   ;  bit[4] = bit[4]^rl(bit[3],16)^rl(bit[3],32)^rl(bit[4],32)^rl(bit[4],48)^rl(bit[7],16)^rl(bit[7],32)

  XOR RAX,RBP   ; t7 = rl(bit[7],16)^rl(bit[7],32)^bit[6]^rl(bit[6],16)
  ROL RAX,16    ; t7 = rl(bit[7],32)^rl(bit[7],48)^rl(bit[6],16)^rl(bit[6],32)
  XOR R15,RAX   ; bit[7] = bit[7]^rl(bit[7],32)^rl(bit[7],48)^rl(bit[6],16)^rl(bit[6],32)
  ROL RBP,32    ; t6 = rl(bit[6],32)^rl(bit[6],48)
  XOR R14,RBP   ; bit[6] = bit[6]^rl(bit[5],16)^rl(bit[5],32)^rl(bit[6],32)^rl(bit[6],48)

RET
mixColumnsRL16	ENDP

END






