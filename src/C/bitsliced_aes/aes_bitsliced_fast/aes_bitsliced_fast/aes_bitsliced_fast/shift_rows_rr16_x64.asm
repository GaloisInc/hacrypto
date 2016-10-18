; --------------------------------------------------------------------
;
; shift_rows_rr16_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains an implementation of the ShiftRows
; transformation of the bitsliced AES state, where the
; resulting values are rotated by 16 positions to the
; right. In fact, a rotate left by 16 positions is left
; out to save one instruction per value. This additional 
; rotation is then undone by mixColumsRL16AddRk.
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

PUBLIC	shiftRowsRR16

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
; row 1 of the matrix by 1 element to the left.
; The bits 48 to 63 stay untouched as they correspond to row 0
; and row 0 is not rotated. On x64 platforms, the lowest 16 bit
; of each 64 bit register is available as own register. This
; is used for the rotations of the subgroups of 16 bytes inside
; the 64 bit registers.
; A rotation back is left out, so the result is rotated by 16
; posistions to the right.
rotate MACRO reg, reg16
    rol reg16,12
    ror reg,32
    rol reg16,4
    rol reg,16
    rol reg16,8
ENDM

_TEXT	SEGMENT

; --------------------------------------------------------------------
;
; This method implements the ShiftRows step of the AES in a bitsliced 
; way. The result is rotated by 16 positions to the right. The
; operation can be implemented faster this way. The rotation is
; undone in the MixColuns step by the mixColumnsRL16AddRk method.
; The MixColuns step is not slowed down by this additional rotation.
; The method expects the state to be in the registers R8 to R15 in
; bitslice representation and updates this state.
shiftRowsRR16	PROC
    rotate R15, R15W
    rotate R14, R14W
    rotate R13, R13W
    rotate R12, R12W
    rotate R11, R11W
    rotate R10, R10W
    rotate R9, R9W
    rotate R8, R8W
RET
shiftRowsRR16	ENDP

END