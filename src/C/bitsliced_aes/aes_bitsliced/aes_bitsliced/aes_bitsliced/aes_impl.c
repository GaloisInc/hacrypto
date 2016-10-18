// --------------------------------------------------------------------
//
// aes_impl.c
//
// @version 1.0 (June 2007)
//
// This file contains C-code implementing the interface for the
// bitslice implementation of the AES. For better performance, parts
// of the algorithm are implemented in x64 assembler.
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

#include "aes_impl.h"
#include "types.h"

// --------------------------------------------------------------------
/// \brief rotates \a x by \a b positions to the left
///
/// This method rotates \a x by \a b positions to the left and returns
/// this result. The comiler replaces this function with the ROL
/// instruction.
///
/// \param[in] x the value to be rotated
/// \param[in] b the number of positions rotated
/// \return x rotated by b positions to the left
static uint64_t rotateLeft(const uint64_t x, const unsigned int b) {
  return ((x << b) | (x >> (64 - b)));
}

// --------------------------------------------------------------------
/// \brief does the key scheduling for rounds 0 to 10
///
/// This method calculates the round keys for the rounds 0 to 10 for
/// for the encryption of 4 blocks in a bitsliced form. The round keys
/// are derived from the 4 keys (for the 4 blocks) in normal representation.
/// in the parameter \a keys. Together with the \ref encrypt method,
/// it builds the interface to access AES functionality from the
/// outside.
///
/// \param[in] keys the keys for the 4 blocks in normal representation
/// \param[out] rk the round keys for the rounds 0 to 10 in bitslice
///      representation
///
/// \see encrypt
void initKey(uint8_t** keys, uint64_t rk[11][8])
{
  uint64_t temp;
  uint64_t tmp[8]; 
  uint8_t i,col,bit;
  uint64_t mask;
  uint8_t round;

  // transforms the keys in from representation into the bitslice
  // representation and places this key rk[0]
  murk(keys, rk[0]);


  for(round = 1; round <= 10; round++)
  {
    // take the round keys of the last round as starting
    // point for calculating the new round keys
    rk[round][7] = rk[round-1][7];
    rk[round][6] = rk[round-1][6];
    rk[round][5] = rk[round-1][5];
    rk[round][4] = rk[round-1][4];
    rk[round][3] = rk[round-1][3];
    rk[round][2] = rk[round-1][2];
    rk[round][1] = rk[round-1][1];
    rk[round][0] = rk[round-1][0];

	// the first column has to be exored with the sbox transformation
	// of the last column of the previous round key, rotated by one
	// position inside the column. We make an sbox transformation of 
	// the whole last round key first: 
    tmp[7] = rk[round][7];
    tmp[6] = rk[round][6];
    tmp[5] = rk[round][5];
    tmp[4] = rk[round][4];
    tmp[3] = rk[round][3];
    tmp[2] = rk[round][2];
    tmp[1] = rk[round][1];
    tmp[0] = rk[round][0];
    subBytesRk(tmp);

    for(i = 0; i < 8; i++)
    {
	  // now we pick the last column only:
      tmp[i] &= 0x000F000F000F000FLL;
	  // column 3 has to be xored to column 0 of the new round key
	  //   -> rotate left by 12
	  // not the column, but the column shifted by one position has to
	  // used for the xor interconnection
	  //   -> rotate left by 16
      // => this leads to an rotation to the left by 28 all together:
      tmp[i] = rotateLeft(tmp[i],28);
      rk[round][i] ^= tmp[i];
    }

	// doing the xor of column 0 with Rcon:
	// Rcon[9] = 0x1b000000
	// -> for the first row of the first columgn, 
	//    bit0, bit1, bit3 and bit4 have to be flipped
    if(round == 9)
    {
      rk[round][0] ^= 0xF000000000000000LL;
      rk[round][1] ^= 0xF000000000000000LL;
      rk[round][3] ^= 0xF000000000000000LL;
      rk[round][4] ^= 0xF000000000000000LL;
    }
	// Rcon[10] = 0x36000000
	// -> for the first row of the first columgn, 
	//    bit1, bit2, bit4 and bit5 have to be flipped
    else if(round == 10)
    {
      rk[round][1] ^= 0xF000000000000000LL;
      rk[round][2] ^= 0xF000000000000000LL;
      rk[round][4] ^= 0xF000000000000000LL;
      rk[round][5] ^= 0xF000000000000000LL;
    }
	// Rcon[1]=0x01000000
	// Rcon[2]=0x02000000
	// Rcon[3]=0x04000000
	// Rcon[4]=0x08000000
	// Rcon[5]=0x10000000
	// Rcon[6]=0x20000000
	// Rcon[7]=0x40000000
	// Rcon[8]=0x80000000
	// -> only one bit has to be flipped, and this bit is
	//    bit [round-1] of the first row of the first column.
    else 
      rk[round][round-1] ^= 0xF000000000000000LL;
  

	// calculating column 1 to 3:
	// they are defined as the same column of the last round key
	// xored with the last colung of this round:
    mask = 0xF000F000F000F000LL;
    for(col = 1; col < 4; col++)
    {
      for(bit = 0; bit < 8; bit++)
      {
	    // take one column:
        temp = rk[round][bit] & mask;
		// xor it to the next column:
        temp>>=4;
        rk[round][bit] ^= temp;
      }
	  // select the next column in the next iteration:
      mask >>= 4;
    }
  }

  // The inversion of bit 0, bit 1, bit 5 and bit 6 is skipped
  // in the sbox transformation, to make the implementation faster.
  // This can be undone by inverting the according bits of the round
  // keys:
  for(round = 1; round <= 10; round++)
  {
	  rk[round][0] = ~(rk[round][0]);
	  rk[round][1] = ~(rk[round][1]);
	  rk[round][5] = ~(rk[round][5]);
	  rk[round][6] = ~(rk[round][6]);
  }
}

// --------------------------------------------------------------------
/// \brief does encrytion of 4 blocks of data in a bitsliced manner
///
/// This method encrypts 4 blocks of data passed in \a plain with the
/// round keys in bitslice representation passed in \a rk. The result
/// is written into \a cypher. The bitslice representation of the
/// round keys can be calculated by the \ref initKey method. The
/// whole encryption is implemented in x64 assembler. Together with 
/// the \ref initKey method, it builds the interface to access AES 
/// functionality from the outside.
///
/// \param[in] plain 4 blocks of plaintext to be encrypted
/// \param[out] cypher the resulting 4 blocks of cypher text
/// \param[in] rk the round keys in bitslice representation used for
///      the encryption
///
/// \see initKey
void encrypt(uint8_t** plain, uint8_t** cypher, uint64_t rk[11][8])
{
  encryptBitsliced(plain,cypher, rk);
}

