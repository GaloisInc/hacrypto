; --------------------------------------------------------------------
;
; shift_rows_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains an implementation of the ShiftRows
; transformation of the bitsliced AES state.
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

PUBLIC	shiftRows
 
; --------------------------------------------------------------------
;
; This macro rotates the lowest 16 bit (they correspond to
; row 3) of reg by 12 positions to the left, which is
; euivalent to rotating row 3 of the matrix by 3 
; elements to the left.
; The bits 16 to 31 correspond to row 2 and they are rotated
; by 8 positions to the left, which is equivalent to rotating
; row 2 of the matrix by 2 elements to the left.
; The bits 32 to 47 correspond to row 1 and they are rotated
; by 4 positions to the left, which is equivalent to rotating
; row 1 of the matrix by 2 elements to the left.
; The bits 48 to 63 stay untouched as they correspond to row 0
; and row 0 is not rotated. On x64 platforms, the lowest 16 bit
; of each 64 bit register is available as own register. This
; is used for the rotations of the subgroups of 16 bytes inside
; the 64 bit registers.
rotate MACRO reg, reg16
    ROL reg16,12
    ROR reg,16
    ROL reg16,8
    ROR reg,16
    ROL reg16,4
    ROL reg,32
ENDM

_TEXT	SEGMENT

; --------------------------------------------------------------------
;  
; This method does the ShiftRows step
; of the AES in a bitsliced way. This is necessary since the
; MixColumns step is not done in the last round. Therefor the 
; mixColumnsRL16 method can not be executed in combination 
; with the shiftRowsRR16 as in all other rounds. The method 
; expects the state to be in the registers R8 
; to R15 in bitslice representation and updates this state.
shiftRows	PROC
    rotate R15, R15W
    rotate R14, R14W
    rotate R13, R13W
    rotate R12, R12W
    rotate R11, R11W
    rotate R10, R10W
    rotate R9, R9W
    rotate R8, R8W
RET
shiftRows	ENDP

END