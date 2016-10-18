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
EXTERN	addRoundKey:PROC
EXTERN	subBytes:PROC
EXTERN	mixColumnsRL16:PROC
EXTERN	shiftRows:PROC
EXTERN	shiftRowsRR16:PROC
EXTERN  mu:PROC
EXTERN  muInv:PROC

_TEXT	SEGMENT
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
; RCX contains a pointer to the input data (the first argument)
    CALL mu

    MOV RCX,[RSP]       ;RCX = round_key = round_key[0]
    
; doing the key addition of round 0:
    CALL addRoundKey

; doing round 1:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,64          ;RCX = round_key[1]
    CALL addRoundKey

; doing round 2:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,128         ;RCX = round_key[2]
    CALL addRoundKey

; doing round 3:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,192         ;RCX = round_key[3]
    CALL addRoundKey

; doing round 4:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,256         ;RCX = round_key[4]
    CALL addRoundKey

; doing round 5:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,320         ;RCX = round_key[5]
    CALL addRoundKey

; doing round 6:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,384         ;RCX = round_key[6]
    CALL addRoundKey

; doing round 7:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,448         ;RCX = round_key[7]
    CALL addRoundKey

; doing round 8:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,512         ;RCX = round_key[8]
    CALL addRoundKey

; doing round 9:
    CALL subBytes
    CALL shiftRowsRR16
    CALL mixColumnsRL16
    MOV RCX,[RSP]       ;RCX = round_key
    ADD RCX,576         ;RCX = round_key[9]
    CALL addRoundKey

; doing round 10 (without MixColumns):
    CALL subBytes
    CALL shiftRows
    POP RCX             ;RCX = round_key
    ADD RCX,640         ;RCX = round_key[10]
    CALL addRoundKey

    POP RCX             ;RCX = target address
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