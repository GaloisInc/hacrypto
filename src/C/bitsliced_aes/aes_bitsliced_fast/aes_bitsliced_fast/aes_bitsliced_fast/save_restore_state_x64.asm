; --------------------------------------------------------------------
;
; save_restore_state_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains a procedure to store all registers
; and to restore all registers into some fixed location
; in the memory (reg_save). This is only used as most
; of the assembler routines do not store and restore the
; registers. In order to be able to call the procedures
; from the test program and to measure their number of
; CPU ticks, save() has to be called before and
; restore() has to be called after calling the assembler
; routine to be measured.
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

PUBLIC	save
PUBLIC	restore
EXTERN  reg_save:PTR
		

_TEXT	SEGMENT
; This method saves all registers to the memory into the array 
; reg_save. This is typically
; done before assembler code is executed, which does not restore
; the register values. This assembler code is not inteded to be called
; from outside, but this is done anyway in order to be able to make
; performance measures on these parts. 
save	PROC
    MOV [reg_save],R8
    MOV [reg_save+8],R9
    MOV [reg_save+16],R10
    MOV [reg_save+24],R11
    MOV [reg_save+32],R12
    MOV [reg_save+40],R13
    MOV [reg_save+48],R14
    MOV [reg_save+56],R15
    MOV [reg_save+64],RAX
    MOV [reg_save+72],RBX
    MOV [reg_save+80],RCX
    MOV [reg_save+88],RDX
    MOV [reg_save+96],RDI
    MOV [reg_save+104],RSI
    MOV [reg_save+112],RBP
RET
save	ENDP

; This method recovers all registers from the array 
; reg_save. This can only be done, if they were saved by the
; save method before. 
restore	PROC
    MOV RBP,[reg_save+112]
    MOV RSI,[reg_save+104]
    MOV RDI,[reg_save+96]
    MOV RDX,[reg_save+88]
    MOV RCX,[reg_save+80]
    MOV RBX,[reg_save+72]
    MOV RAX,[reg_save+64]
    MOV R15,[reg_save+56]
    MOV R14,[reg_save+48]
    MOV R13,[reg_save+40]
    MOV R12,[reg_save+32]
    MOV R11,[reg_save+24]
    MOV R10,[reg_save+16]
    MOV R9,[reg_save+8]
    MOV R8,[reg_save]
RET
restore	ENDP

END