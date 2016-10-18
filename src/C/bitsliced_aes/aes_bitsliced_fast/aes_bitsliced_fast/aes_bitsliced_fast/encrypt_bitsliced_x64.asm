; --------------------------------------------------------------------
;
; encrypt_bitsliced_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains the implementation of the encryptBitsliced
; method in x64 assembler. This method does the encrytion of 4 blocks 
; of data in a bitsliced manner.
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

PUBLIC	encryptBitsliced
EXTERN	subBytes:PROC
EXTERN	mixColumnsRL16AddRk:PROC
EXTERN	shiftRowsAddRk:PROC
EXTERN	shiftRowsRR16:PROC
EXTERN  muAddRk:PROC
EXTERN  muInv:PROC

_TEXT	SEGMENT

; --------------------------------------------------------------------
;
; This method encrypts 4 blocks of data passed in register RCX 
; (in the first argument as uint8_t**) with the
; round keys in bitslice representation passed in R8 (in the third
; argument as uint64_t[11][8]). The result
; is written into RDX (to the second argument as uint8_t**). 
; The implementation is doen in x64 assembler.
encryptBitsliced	PROC
    PUSH R12
    PUSH R13
    PUSH R14
    PUSH R15
    PUSH RBP
    PUSH RSI
    PUSH RDI
    PUSH RBX
    PUSH RDX    ; the target address passed as second argument
    PUSH R8     ; the round key passed as third argument

; Transformation into the bitslice domain:    
; RCX contains a pointer to the data (the first argument)
; The address to the round key is read from the stack
    CALL muAddRk

; round 1:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key
    ADD RCX,64                ;RCX = round_key[1]
    CALL mixColumnsRL16AddRk

; round 2:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key
    ADD RCX,128               ;RCX = round_key[2]
    CALL mixColumnsRL16AddRk

; round 3:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key
    ADD RCX,192               ;RCX = round_key[3]
    CALL mixColumnsRL16AddRk

; round 4:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key
    ADD RCX,256               ;RCX = round_key[4]
    CALL mixColumnsRL16AddRk

; round 5:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key   
    ADD RCX,320               ;RCX = round_key[5]
    CALL mixColumnsRL16AddRk

; round 6:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key  
    ADD RCX,384               ;RCX = round_key[6]
    CALL mixColumnsRL16AddRk

; round 7:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key  
    ADD RCX,448               ;RCX = round_key[7]
    CALL mixColumnsRL16AddRk

; round 8:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key  
    ADD RCX,512               ;RCX = round_key[8]
    CALL mixColumnsRL16AddRk

; round 9:
    CALL subBytes
    CALL shiftRowsRR16
    MOV RCX,[RSP]             ;RCX = round_key  
    ADD RCX,576               ;RCX = round_key[9]
    CALL mixColumnsRL16AddRk

; round 10:
    CALL subBytes
    POP RCX                   ;RCX = round_key
    CALL shiftRowsAddRk
    
    POP RCX                   ;RCX = target address
    
; The transformation back into the normal domain:
; RCX contains the target address
    CALL muInv
    POP RBX
    POP RDI
    POP RSI
    POP RBP
    POP R15
    POP R14
    POP R13
    POP R12
RET
encryptBitsliced	ENDP

END