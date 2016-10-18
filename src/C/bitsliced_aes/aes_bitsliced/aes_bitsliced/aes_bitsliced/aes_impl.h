// --------------------------------------------------------------------
//
// aes_impl.h
//
// @version 1.0 (June 2007)
//
// This file contains method declarations for the bitslice
// implementation of the AES. Note, that not all of the methods
// are intended to be called by an external party. However, they
// are listed here too, to allow performance measures one such
// internal methods.
//
// @author Robert Könighofer <robert.koenighofer@student.tugraz.at>
//
// This code is hereby placed in the public domain.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
// OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
// BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// --------------------------------------------------------------------

#include "types.h"

// --------------------------------------------------------------------
/// \brief does the key scheduling for rounds 0 to 10
///
/// This method calculates the round keys for the rounds 0 to 10 for
/// for the encryption of 4 blocks in a bitsliced form. The round keys
/// are derived from the 4 keys (for the 4 blocks) in normal 
/// in the parameter \a keys. Together with the \ref encrypt method,
/// it builds the interface to access AES functionality from the
/// outside.
///
/// \param[in] keys the keys for the 4 blocks in normal representation
/// \param[out] rk the round keys for the rounds 0 to 10 in bitslice
///      representation
void initKey(uint8_t** keys, uint64_t rk[11][8]);

// --------------------------------------------------------------------
/// \brief does encrytion of 4 blocks of data in a bitsliced manner
///
/// This method encrypts 4 blocks of data passed in \a plain with the
/// round keys in bitslice representation passed in \a rk. The result
/// is written into \a cypher. The bitslice representation of the
/// round keys can be calculated by the \ref initKey method. Together 
/// with the \ref initKey method, this method builds the 
/// interface to access AES functionality from the outside.
///
/// \param[in] plain 4 blocks of plaintext to be encrypted
/// \param[out] cypher the resulting 4 blocks of cypher text
/// \param[in] rk the round keys in bitslice representation used for
///      the encryption
///
/// \see initKey
void encrypt(uint8_t** plain, uint8_t** cypher, uint64_t rk[11][8]);

// --------------------------------------------------------------------
/// \brief the implementation of the \ref encrypt method
///
/// This method actually implements the ref encrypt method in x64
/// assembler. The implementation can be found in the file
/// 'encrypt_bitsliced_x64.asm'
///
/// \param[in] plain 4 blocks of plaintext to be encrypted
/// \param[out] cypher the resulting 4 blocks of cypher text
/// \param[in] rk the round keys in bitslice representation used for
///      the encryption
///
/// \see initKey
/// \see encrypt
extern void encryptBitsliced(uint8_t** plain, uint8_t** cypher, uint64_t rk[11][8]);

// --------------------------------------------------------------------
/// \brief transforms 4 blocks of 64 byte from normal 
///      representation into bitslice representation
///
/// This method transforms the 4 blocks of 64 byte passed in 
/// \a byte_seq from the normal representation into bitslice 
/// representation and writes the result into \a target. Each
/// element of the array \a target contains one bit. 
/// The elements of the byte sequence are interpreted as elements of
/// a matrix of dimension 4x4, where the elements are bytes, as defined
/// in the AES algorithm. The elements of this matrix are mapped
/// into the bitslice representation in the following way:

/// target[i]:
///row   00000000 00000000 11111111 11111111 22222222 22222222 33333333 33333333
///col   00001111 22223333 00001111 22223333 00001111 22223333 00001111 22223333 
///block 01230123 01230123 01230123 01230123 01230123 01230123 01230123 01230123 
///bit   iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii
///
/// The method is implemented in x64 assembler in the file 
/// 'mu_swapmove_x64.asm'.
///
/// \param[in] byte_seq the 4 blocks to be transformed
/// \param[out] target the resulting bitslice representation 
///
/// \see initKey
extern void murk(uint8_t** byte_seq, uint64_t* target);

// --------------------------------------------------------------------
/// \brief transforms 4 blocks of 64 byte from normal representation 
/// into bitslice representation
///
/// This method transforms the 4 blocks of 64 byte passed in 
/// \a byte_seq from the normal representation into bitslice 
/// representation and writes the result into the registers R8 to R15.
/// Each of the resulting registers contains one bit. 
/// The elements of the byte sequence are interpreted as elements of
/// a matrix of dimension 4x4, where the elements are bytes, as defined
/// in the AES algorithm. The elements of this matrix are mapped
/// into the bitslice representation in the following way:
///
/// register R[8+i]:
///row   00000000 00000000 11111111 11111111 22222222 22222222 33333333 33333333
///col   00001111 22223333 00001111 22223333 00001111 22223333 00001111 22223333 
///block 01230123 01230123 01230123 01230123 01230123 01230123 01230123 01230123 
///bit   iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii iiiiiiii
///
/// The method is implemented in x64 assembler in the file 
/// 'mu_swapmove_x64.asm'.
///
/// Note: This method is not intended to be called from the outside.
/// Only use \ref initKey and \ref encrypt for your encryption. The
/// method is only specified here, to do some performance measuring from
/// the outside. 
///
/// \param[in] byte_seq the 4 blocks to be transformed
///
/// \see encryptBitsliced
extern void mu(uint8_t** byte_seq);

// --------------------------------------------------------------------
/// \brief transforms 4 blocks of 64 byte from normal 
///      representation into bitslice representation
///
/// This method transforms the result in bitslice representation back
/// into the normal representation. It expects the result to be available
/// in the registers R8 to R15. The corresponding 4 blocks are written
/// into \byte_seq in normal representation. This function is the inverse
/// function to \ref mu.
///
/// The method is implemented in x64 assembler in the file 
/// 'mu_inv_swapmove_x64.asm'.
///
/// Note: This method is not intended to be called from the outside.
/// Only use \ref initKey and \ref encrypt for your encryption. The
/// method is only specified here, to do some performance measuring from
/// the outside. 
///
/// \param[out] byte_seq the resulting 4 blocks in normal representation
///
/// \see mu
/// \see encryptBitsliced
extern void muInv(uint8_t** byte_seq);

// --------------------------------------------------------------------
/// \brief does the AddRoundKey step of the AES in a bitlsiced way.
///
/// This method performs the AddRoundKey step of the AES in a bitlsiced
/// way. The elements of the state are xored with the round key passed
/// in \a rk. The round key has to be in bitsliced representation as
/// produced by \ref initKey. The AES-state is expected to be in the
/// registers R8 to R15, also in the bitslice representation.
///
/// The method is implemented in x64 assembler in the file 
/// 'akk_round_key.asm'.
///
/// Note: This method is not intended to be called from the outside.
/// Only use \ref initKey and \ref encrypt for your encryption. The
/// method is only specified here, to do some performance measuring from
/// the outside. 
///
/// \param[in] rk the round key in bitslice representation
///
/// \see initKey
/// \see encryptBitsliced
extern void addRoundKey(uint64_t* rk);

// --------------------------------------------------------------------
/// \brief does the SubBytes step of the AES
///
/// This method implements the SubBytes step of the AES in a bitsliced 
/// way. The method updates the state, which has to be in bitslice 
/// representation in the registers R8 to R15. The implementation is
/// based on:
/// 'A Very Compact Rijndael S-box' by D. Canright.
/// and it is done in x64 assembler in the file 'shift_rows_rr16_x64.asm'.
/// The final inversion of the bits 0, 1, 5 and 6 is skipped
/// to make the implementation faster. This is undone by inverting 
/// the according bits of the round keys.
///
/// Note: This method is not intended to be called from the outside.
/// Only use \ref initKey and \ref encrypt for your encryption. The
/// method is only specified here, to do some performance measuring from
/// the outside. 
///
/// \see encryptBitsliced
extern void subBytes();

// --------------------------------------------------------------------
/// \brief does the SubBytes step of the AES
///
/// This method implements the SubBytes step  of the AES in a bitsliced 
/// way. The method transforms the data in \a tmp, which has to be in
/// bitslice representation. It is used for the calculation of the
/// round keys only and uses the \ref subBytes method. It is implemented 
/// in x64 assembler in the file 'sbox_canright_x64.asm'.
///
/// Note: This method is not intended to be called from the outside.
/// Only use \ref initKey and \ref encrypt for your encryption. The
/// method is only specified here, to do some performance measuring from
/// the outside. 
///
/// \see initKeys
/// \see subBytes
extern void subBytesRk(uint64_t *tmp);

// --------------------------------------------------------------------
/// \brief does the ShiftRows step of the AES.
///
/// This method does the ShiftRows step of the AES in a bitsliced way. 
/// This is necessary since the
/// MixColumns step is not done in the last round. Therefor the 
/// \ref mixColumnsRL16 method can not be executed in combination 
/// with the \ref shiftRowsRR16 as in all other rounds.  The method 
/// expects the state to be in the registers R8 
/// to R15 in bitslice representation and updates this state.
/// It is implemented in x64 assembler in the file 
/// 'shift_rows_x64.asm'.
///
/// Note: This method is not intended to be called from the outside.
/// Only use \ref initKey and \ref encrypt for your encryption. The
/// method is only specified here, to do some performance measuring from
/// the outside. 
///
/// \see encryptBitsliced
extern void shiftRows();

// --------------------------------------------------------------------
/// \brief does the ShiftRows step of the AES but also rotates the
///     result by 16 positions to the right.
///
/// This method implements the ShiftRows step of the AES in a bitsliced 
/// way. The result is rotated by 16 positions to the right. The
/// operation can be implemented faster this way. The rotation is
/// undone in the MixColuns step by the \ref mixColumnsRL16AddRk method.
/// The MixColuns step is not slowed down by this additional rotation.
/// The method expects the state to be in the registers R8 to R15 in
/// bitslice representation and updates this state.
/// It is implemented in x64 assembler in the file 'shift_rows_rr16_x64.asm'.
///
/// Note: This method is not intended to be called from the outside.
/// Only use \ref initKey and \ref encrypt for your encryption. The
/// method is only specified here, to do some performance measuring from
/// the outside. 
///
/// \see encryptBitsliced
/// \see mixColumnsRL16
extern void shiftRowsRR16();

// --------------------------------------------------------------------
/// \brief does the MixColumns step of the AES with
///     and additional rotation to the left by 16 positions.
///
/// This method implements the MixColumns step 
/// of the AES in a bitsliced way. The method updates the 
/// state, which has to be in bitslice representation in the registers
/// R8 to R15. The additional rotation to the left by 16
/// positions is done to undo the rotation to the right by 16 positions
/// done by shiftRowsRR16. The ShiftRows step can be done faster with
/// an rotation to the right, and for the MixColumns step, any rotation
/// by a multiple of 16 does not make any difference in the performance.
/// The method is is implemented in x64 assembler in the file
/// 'mix_cols_rl166_x64.asm'.
///
/// Note: This method is not intended to be called from the outside.
/// Only use \ref initKey and \ref encrypt for your encryption. The
/// method is only specified here, to do some performance measuring
/// from the outside.
///
/// \see shiftRowsRR16
/// \see encryptBitsliced
extern void mixColumnsRL16();

