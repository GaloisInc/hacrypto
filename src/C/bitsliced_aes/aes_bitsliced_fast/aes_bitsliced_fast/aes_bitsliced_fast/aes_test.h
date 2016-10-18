// --------------------------------------------------------------------
//
// aes_test.h
//
// @version 1.0 (June 2007)
//
// This file contains declarations for doing some tests and performance
// measurement on a bitsliced implementation of the AES. The 
// performance results are compared to the performance optimized 
// reference implementation.
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

// --------------------------------------------------------------------
/// \brief a type containing all data necessary for performance 
/// measuring
struct BenchmarkData {

  /// The start time
  uint64_t t0;

  /// The end time
  uint64_t t1;

  /// The time difference
  uint64_t ts;

  /// The calibrated time for doing nothing
  uint64_t tc;

  /// The cycle count when starting
  clock_t c0;

  /// The cycle count when finishing
  clock_t c1;

  /// The cycles needed
  clock_t cs;

  /// The calibrated number of cycles for doing nothing
  clock_t cc;

  /// Some place for cpuInfo
  int cpuInfo[4];
};

// --------------------------------------------------------------------
/// \brief a type containing all data necessary for performance 
/// measuring
typedef struct BenchmarkData BenchmarkData;

// --------------------------------------------------------------------
/// \brief checks if the bitsliced implementation of the AES is correct
///
/// This method checks if the bitsliced implementation of the AES is 
/// correct. The 4 blocks in msg are encrypted with the keys in keys,
/// the results are compared with the correct results in corr_res.
/// If the test is passed, nothing happens. If the test fails, an error
/// message is written to stdout.
void checkIfCorrect();

// --------------------------------------------------------------------
/// \brief initializes the BenchmarkData struct for measurement
///
/// The BenchmarkData struct containing all data needed for measuring
/// the number of cycles and the time needed for parts of the algorithm
/// is initialized and calibrated. After calling this method, the passed
/// pointer to the structed has to be freed by the calling part.
///
/// \param[out] bench a pointer to the struct to be initialized
/// \see BenchmarkData
void initBenchMarkData(BenchmarkData **bench);

// --------------------------------------------------------------------
/// \brief initializes the BenchmarkData struct for measurement with
/// respect to the time needed for saving and restoring the registers
///
/// The BenchmarkData struct containing all data needed for measuring
/// the number of cycles and the time needed for parts of the algorithm
/// is initialized and calibrated. After calling this method, the passed
/// pointer to the structed has to be freed by the calling part. This
/// method also respects the time needed for saving and restoring the
/// registers while calibration.
///
/// \param[in] bench a pointer to the struct to be initialized
/// \see BenchmarkData
void initBenchMarkDataSaveRestore(BenchmarkData **bench);

// --------------------------------------------------------------------
/// \brief returns and displays the cycles needed by the reference
/// implementation
///
/// This method returns and displays the cycles needed by the reference
/// implementation of the AES for encrypting 4 blocks of data. The
/// initialization (calculating the round keys) is not included.
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \return the cycles needed by the reference implementation for the
///    encryption of 4 blocks of data
uint64_t getTicksReference(BenchmarkData *bench);

// --------------------------------------------------------------------
/// \brief returns and displays the cycles needed by the bitslice
/// implementation
///
/// This method returns and displays the cycles needed by the bitslice
/// implementation of the AES for encrypting 4 blocks of data. The
/// initialization (calculating the round keys) is not included.
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \return the cycles needed by the bitslice implementation for the
///    encryption of 4 blocks of data
uint64_t getTicksBitSlice(BenchmarkData *bench);

// --------------------------------------------------------------------
/// \brief returns and displays the cycles needed for the 
/// SubBytes-operation of the bitlice implementation
///
/// This method returns and displays the cycles needed for the 
/// SubBytes-operation of the bitlice implementation of the AES 
/// (one call). 
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \return the cycles needed for the SubBytes-operation of the 
///     bitlice implementation
uint64_t getTicksSubBytes(BenchmarkData *bench);

// --------------------------------------------------------------------
/// \brief returns and displays the cycles needed for the 
/// shiftRows-operation with the AddRoundKey operation 
/// of the bitlice implementation
///
/// This method returns and displays the cycles needed for the 
/// shiftRows-operation and the AddRoundKey operation of the bitlice 
/// implementation of the AES (one call). 
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \return the cycles needed for the shiftRows-operation and the
///     of the AddRoundKey operation of the bitlice implementation
uint64_t getTicksShiftRowsAddRk(BenchmarkData *bench);

// --------------------------------------------------------------------
/// \brief returns and displays the cycles needed for the 
/// shiftRows-and-rotate-right-by-16 -operation of the bitlice 
/// implementation
///
/// This method returns and displays the cycles needed for the 
/// shiftRows-and-rotate-right-by-16 -operation of the bitlice 
/// implementation of the AES (one call). 
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \return the cycles needed for the 
///        shiftRows-and-rotate-right-by-16 -operation of the bitlice 
///        implementation
uint64_t getTicksShiftRowsRR16(BenchmarkData *bench);

// --------------------------------------------------------------------
/// \brief returns and displays the cycles needed for the 
/// MixColumns and the AddRoundKey-operation of the bitlice 
/// implementation
///
/// This method returns and displays the cycles needed for the 
/// MixColumns and the AddRoundKey-operation of the bitlice 
/// implementation of the AES (one call). 
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \return the cycles needed for the SubBytes-operation of the 
///     bitlice implementation
uint64_t getTicksMixColumnsAddRk(BenchmarkData *bench);

// --------------------------------------------------------------------
/// \brief returns and displays the cycles needed for the 
/// transformation into the bitslic domain.
///
/// This method returns and displays the cycles needed for the 
/// transformation into the bitslic domain in the bitlice 
/// implementation of the AES (one call). 
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \return the cycles needed for the transformation into the bitslic 
///     domain
uint64_t getTicksMu(BenchmarkData *bench);

// --------------------------------------------------------------------
/// \brief returns and displays the cycles needed for the 
/// transformation back from the bitslic domain.
///
/// This method returns and displays the cycles needed for the 
/// transformation back from the bitslic domain in the bitlice 
/// implementation of the AES (one call). 
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \return the cycles needed for the transformation back from the 
///     bitslice domain
uint64_t getTicksMuInv(BenchmarkData *bench);

// --------------------------------------------------------------------
/// \brief returns and displays the time needed for the encryption of
/// \a megabyte by the reference implementation.
///
/// This method returns and displays the time needed for the 
/// encryption of \a megabyte by the reference implementation.
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \param[in] megabyte the number of megabytes to encrypt
/// \return the time needed for the encryption in ms
uint64_t  getTimeForReference(BenchmarkData *bench, uint32_t megabyte);

// --------------------------------------------------------------------
/// \brief returns and displays the time needed for the encryption of
/// \a megabyte by the bitslice implementation.
///
/// This method returns and displays the time needed for the 
/// encryption of \a megabyte by the bitslice implementation.
///
/// \param[in] bench a pointer to an initialized BenchmarkData struct.
/// \param[in] megabyte the number of megabytes to encrypt
/// \return the time needed for the encryption in ms
uint64_t  getTimeForBitSlice(BenchmarkData *bench, uint32_t megabyte);

// --------------------------------------------------------------------
/// \brief saves all registers to the memory
///
/// This method saves all registers to the memory into the array 
/// \ref reg_save. This is typically
/// done before assembler code is executed, which does not restore
/// the register values. This assembler code is not inteded to be called
/// from outside, but this is done anyway in order to be able to make
/// performance measures on these parts. The method is implemented in
/// x64 assembler in the file 'save_restore_state_x64.asm'.
///
/// \see reg_save
/// \see restore
extern void save();

// --------------------------------------------------------------------
/// \brief recovers all registers from memory
///
/// This method recovers all registers from the array 
/// \ref reg_save. This can only be done, if they were saved by the
/// \ref save method before. The method is implemented in
/// x64 assembler in the file 'save_restore_state_x64.asm'.
///
/// \see reg_save
/// \see save
extern void restore();