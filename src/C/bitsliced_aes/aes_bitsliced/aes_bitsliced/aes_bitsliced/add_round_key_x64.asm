; --------------------------------------------------------------------
;
; add_round_key_x64.asm
;
; @version 1.0 (June 2007)
;
; This file contains the implementation of the addRoundKey
; method in x64 assembler. This method adds the round key (via XOR) 
; to the bitslice state in the registers R8 to R15.
; The round key in the bitslice domain was precalculated 
; by the initKey procedure. A pointer to the round key is passed in
; RCX.
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


PUBLIC	addRoundKey

_TEXT	SEGMENT
; --------------------------------------------------------------------
;
; This method performs the AddRoundKey step of the AES in a bitlsiced
; way. The elements of the state are xored with the round key passed
; in RCX. The round key has to be in bitsliced representation as
; produced by initKey. The AES-state is expected to be in the
; registers R8 to R15, also in the bitslice representation.
addRoundKey	PROC
    XOR R8, QWORD PTR [RCX]
    XOR R9, QWORD PTR [RCX+8]
    XOR R10, QWORD PTR [RCX+16]
    XOR R11, QWORD PTR [RCX+24]
    XOR R12, QWORD PTR [RCX+32]
    XOR R13, QWORD PTR [RCX+40]
    XOR R14, QWORD PTR [RCX+48]
    XOR R15, QWORD PTR [RCX+56]
RET
addRoundKey	ENDP

END