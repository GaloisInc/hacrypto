// --------------------------------------------------------------------
//
// aes_test.c
//
// @version 1.0 (June 2007)
//
// This file contains C-code doing tests and performance measurement on
// a bitsliced implementation of the AES. The performance results are
// compared to the performance optimized reference implementation.
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
#include <intrin.h>
#include <time.h>
#include "aes_impl.h"
#include "rijndael-alg-fst.h"
#include "aes_test.h"

// --------------------------------------------------------------------
/// \brief the round key in bitsliced representation
///
/// An array containing the round keys for the rounds 0 to
/// 10 in bitsliced representation.
uint64_t rk_bs[11][8];

// --------------------------------------------------------------------
/// \brief an array for storing register values
///
/// An array where the register values are stored to. This is typically
/// done before assembler code is executed, which does not restore
/// the register values. This assembler code is not inteded to be called
/// from outside, but this is done anyway in order to be able to make
/// performance measures on these parts. After executing the assembler
/// code, the registers are restored from the stored values again.
///
/// \see save
/// \see restore
uint64_t reg_save[15];

// --------------------------------------------------------------------
/// \brief the first message block to be encrypted
static uint8_t msg0[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
                         0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

// --------------------------------------------------------------------
/// \brief the second message block to be encrypted
static uint8_t msg1[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

// --------------------------------------------------------------------
/// \brief the third message block to be encrypted
static uint8_t msg2[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// --------------------------------------------------------------------
/// \brief the fourth message block to be encrypted
static uint8_t msg3[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

// --------------------------------------------------------------------
/// \brief an array used to store the result of the encryption in it
static uint8_t res0[] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                         0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};

// --------------------------------------------------------------------
/// \brief an array used to store the result of the encryption in it
static uint8_t res1[] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                         0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};

// --------------------------------------------------------------------
/// \brief an array used to store the result of the encryption in it
static uint8_t res2[] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                         0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};

// --------------------------------------------------------------------
/// \brief an array used to store the result of the encryption in it
static uint8_t res3[] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                         0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};

// --------------------------------------------------------------------
/// \brief the key for enkryption of msg0
static uint8_t key0[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

// --------------------------------------------------------------------
/// \brief the key for enkryption of msg1
static uint8_t key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// --------------------------------------------------------------------
/// \brief the key for enkryption of msg2
static uint8_t key2[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

// --------------------------------------------------------------------
/// \brief the key for enkryption of msg3
static uint8_t key3[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
                         0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

// --------------------------------------------------------------------
/// \brief the correct result for encrypting msg0 with key0
static uint8_t corr_res0[] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 
                              0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};

// --------------------------------------------------------------------
/// \brief the correct result for encrypting msg1 with key1
static uint8_t corr_res1[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 
                              0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

// --------------------------------------------------------------------
/// \brief the correct result for encrypting msg2 with key2
static uint8_t corr_res2[] = {0x27, 0x9f, 0xb7, 0x4a, 0x75, 0x72, 0x13, 0x5e, 
                              0x8f, 0x9b, 0x8e, 0xf6, 0xd1, 0xee, 0xe0, 0x03};

// --------------------------------------------------------------------
/// \brief the correct result for encrypting msg3 with key3
static uint8_t corr_res3[] = {0xd5, 0x4e, 0x75, 0x19, 0x47, 0x4d, 0xdb, 0x7f, 
                              0xf5, 0xee, 0x71, 0x1c, 0xba, 0xb1, 0x8d, 0xee};

// --------------------------------------------------------------------
/// \brief a bundle of all 4 encryption keys key0, key1, key2 and key3
static uint8_t* keys[] = {key0,key1,key2,key3};

// --------------------------------------------------------------------
/// \brief a bundle of all 4 messages msg0, msg1, msg2 and msg3
static uint8_t* msg[] =  {msg0,msg1,msg2,msg3};

// --------------------------------------------------------------------
/// \brief a bundle of all 4 results res0, res1, res2 and res3
static uint8_t* res[] = {res0,res1,res2,res3};

// --------------------------------------------------------------------
/// \brief a bundle of all 4 correct results
static uint8_t* corr_res[] = {corr_res0,corr_res1,corr_res2,corr_res3};

// --------------------------------------------------------------------
/// \brief the iterations for measuring the number of ticks
///
/// This constant specifies the number of iterations to be done while
/// measuring the number of ticks for various parts of the algoritm.
static uint32_t const ITERATIONS = 100;

// --------------------------------------------------------------------
/// \brief the entry point of the whole test application.
///
/// This method is the entry point for the whole testing and measuring
/// on the bitsliced implementation of the AES. It does not require any
/// parameters.
///
/// \param[in] argc the number of arguments (not used)
/// \param[in] argv an array of arguments (not used)
/// \return an exit code (always 0)
int main(int argc, char* argv[])
{
  BenchmarkData *bench = 0;
  checkIfCorrect();
  initBenchMarkData(&bench);
  getTicksReference(bench);
  getTicksBitSlice(bench);  
  free(bench);
  bench = 0;
  initBenchMarkDataSaveRestore(&bench); 
  getTicksSubBytes(bench);
  getTicksShiftRowsAddRk(bench);
  getTicksShiftRowsRR16(bench);
  getTicksMixColumnsAddRk(bench);
  getTicksMu(bench);
  getTicksMuInv(bench);
  getTimeForBitSlice(bench, 100);
  getTimeForReference(bench, 100);
  free(bench);
  bench = 0;

  printf("\nTest Finished. Hit Enter to exit...");
  getchar();
  return 0;
}


// --------------------------------------------------------------------
/// \brief checks if the bitsliced implementation of the AES is correct
///
/// This method checks if the bitsliced implementation of the AES is 
/// correct. The 4 blocks in msg are encrypted with the keys in keys,
/// the results are compared with the correct results in corr_res.
/// If the test is passed, nothing happens. If the test fails, an error
/// message is written.
void checkIfCorrect()
{
  initKey(keys,rk_bs);
  encrypt(msg, res,rk_bs);

  if (memcmp(res[0],corr_res[0], 16) != 0 ||
	  memcmp(res[1],corr_res[1], 16) != 0 ||
	  memcmp(res[2],corr_res[2], 16) != 0 ||
	  memcmp(res[3],corr_res[3], 16) != 0) 
  {
    printf("Correctness test failed!\n");
  }
}

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
void initBenchMarkData(BenchmarkData **bench)
{
  uint32_t i = 0;
  *bench = (BenchmarkData*) malloc(sizeof(BenchmarkData));
  (*bench)->cpuInfo[0] = -1;
  (*bench)->cpuInfo[1] = -1;
  (*bench)->cpuInfo[2] = -1;
  (*bench)->cpuInfo[3] = -1;
    
  //calibrating:
  (*bench)->tc = 0;
  for (i = 0; i < ITERATIONS; i++) {
    __cpuid((*bench)->cpuInfo, 0);
    (*bench)->t0 = __rdtsc();
    __cpuid((*bench)->cpuInfo, 0);
    (*bench)->t1 = __rdtsc();
    (*bench)->tc += (*bench)->t1 - (*bench)->t0;
  }
  (*bench)->tc = (*bench)->tc / ITERATIONS;

  (*bench)->c0 = clock();
  (*bench)->c1 = clock();
  (*bench)->cc = (*bench)->c1 - (*bench)->c0;
}

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
void initBenchMarkDataSaveRestore(BenchmarkData **bench)
{
  uint32_t i = 0;
  *bench = (BenchmarkData*) malloc(sizeof(BenchmarkData));
  (*bench)->cpuInfo[0] = -1;
  (*bench)->cpuInfo[1] = -1;
  (*bench)->cpuInfo[2] = -1;
  (*bench)->cpuInfo[3] = -1;
    
  //calibrating:
  (*bench)->tc = 0;
  for (i = 0; i < ITERATIONS; i++) {
    __cpuid((*bench)->cpuInfo, 0);
    (*bench)->t0 = __rdtsc();
   save();
   restore();
    __cpuid((*bench)->cpuInfo, 0);
    (*bench)->t1 = __rdtsc();
    (*bench)->tc += (*bench)->t1 - (*bench)->t0;
  }
  (*bench)->tc = (*bench)->tc / ITERATIONS;

  (*bench)->c0 = clock();
  (*bench)->c1 = clock();
  (*bench)->cc = (*bench)->c1 - (*bench)->c0;
}


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
uint64_t getTicksReference(BenchmarkData *bench)
{
  int Nr = 0;
  uint32_t i = 0;
  uint32_t rk_ref[44];
  bench->ts = 0;
  for (i = 0; i < ITERATIONS; i++) 
  {
	Nr = rijndaelKeySetupEnc(rk_ref, key1, 128);
    __cpuid(bench->cpuInfo, 0);
    bench->t0 = __rdtsc();
    rijndaelEncrypt(rk_ref, Nr, msg1, res1);
	rijndaelEncrypt(rk_ref, Nr, msg1, res1);
	rijndaelEncrypt(rk_ref, Nr, msg1, res1);
	rijndaelEncrypt(rk_ref, Nr, msg1, res1);
    __cpuid(bench->cpuInfo, 0);
    bench->t1 = __rdtsc();
    bench->ts += bench->t1 - bench->t0 - bench->tc;
  }
  bench->ts = bench->ts / ITERATIONS;

  printf("reference implementation took %I64d ticks\n", bench->ts);
  return bench->ts;
}

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
uint64_t getTicksBitSlice(BenchmarkData *bench)
{
  uint32_t i = 0;
  bench->ts = 0;
  for (i = 0; i < ITERATIONS; i++) 
  {
    initKey(keys,rk_bs);
    __cpuid(bench->cpuInfo, 0);
    bench->t0 = __rdtsc();
    encrypt(msg, res,rk_bs);
    __cpuid(bench->cpuInfo, 0);
    bench->t1 = __rdtsc();
    bench->ts += bench->t1 - bench->t0 - bench->tc;
  }
  bench->ts = bench->ts / ITERATIONS;

  printf("bitslice implementation took %I64d ticks\n", bench->ts);
  return bench->ts;
}

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
uint64_t getTicksShiftRowsRR16(BenchmarkData *bench)
{
  uint32_t i = 0;
  bench->ts = 0;
  for (i = 0; i < ITERATIONS; i++) 
  {
    __cpuid(bench->cpuInfo, 0);
    bench->t0 = __rdtsc();
    save();
	shiftRowsRR16();
    restore();
    __cpuid(bench->cpuInfo, 0);
    bench->t1 = __rdtsc();
    bench->ts += bench->t1 - bench->t0 - bench->tc;
  }
  bench->ts = bench->ts  / (ITERATIONS);

  printf("shiftRowsRR16 took %I64d ticks\n", bench->ts);
    return bench->ts;
}


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
uint64_t getTicksShiftRowsAddRk(BenchmarkData *bench)
{
  uint32_t i = 0;
  bench->ts = 0;
  for (i = 0; i < ITERATIONS; i++) 
  {
    __cpuid(bench->cpuInfo, 0);
    bench->t0 = __rdtsc();
	save();
	shiftRowsAddRk(rk_bs);
	restore();
    __cpuid(bench->cpuInfo, 0);
    bench->t1 = __rdtsc();
    bench->ts += bench->t1 - bench->t0 - bench->tc;
  }
  bench->ts = bench->ts  / (ITERATIONS);

  printf("shiftRows took %I64d ticks\n", bench->ts);
    return bench->ts;
}

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
uint64_t getTicksSubBytes(BenchmarkData *bench)
{
  uint32_t i = 0;
  bench->ts = 0;
  for (i = 0; i < ITERATIONS; i++) 
  {
    __cpuid(bench->cpuInfo, 0);
    bench->t0 = __rdtsc();
	save();
	subBytes();
	restore();
    __cpuid(bench->cpuInfo, 0);
    bench->t1 = __rdtsc();
    bench->ts += bench->t1 - bench->t0 - bench->tc;
  }
  bench->ts = bench->ts / (ITERATIONS);

  printf("subBytes took %I64d ticks\n", bench->ts);
  return bench->ts;
}

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
uint64_t getTicksMixColumnsAddRk(BenchmarkData *bench)
{
  uint32_t i = 0;
  bench->ts = 0;
  for (i = 0; i < ITERATIONS; i++) 
  {
    __cpuid(bench->cpuInfo, 0);
    bench->t0 = __rdtsc();
	save();
	mixColumnsRL16AddRk(rk_bs[0]);
	restore();
    __cpuid(bench->cpuInfo, 0);
    bench->t1 = __rdtsc();
    bench->ts += bench->t1 - bench->t0 - bench->tc;
  }
  bench->ts = bench->ts / (ITERATIONS);

  printf("mixColumnsRL16AddRk took %I64d ticks\n", bench->ts);
  return bench->ts;
}


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
uint64_t getTicksMu(BenchmarkData *bench)
{
  uint32_t i = 0;
  bench->ts = 0;
  for (i = 0; i < ITERATIONS; i++) 
  {
    __cpuid(bench->cpuInfo, 0);
    bench->t0 = __rdtsc();
	save();
	muAddRk(msg);
	restore();
    __cpuid(bench->cpuInfo, 0);
    bench->t1 = __rdtsc();
    bench->ts += bench->t1 - bench->t0 - bench->tc;
  }
  bench->ts = bench->ts  / (ITERATIONS);

  printf("mu took %I64d ticks\n", bench->ts);
  return bench->ts;
}

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
uint64_t getTicksMuInv(BenchmarkData *bench)
{
  uint32_t i = 0;
  bench->ts = 0;
  for (i = 0; i < ITERATIONS; i++) 
  {
    __cpuid(bench->cpuInfo, 0);
    bench->t0 = __rdtsc();
	save();
	muInv(res);
	restore();
    __cpuid(bench->cpuInfo, 0);
    bench->t1 = __rdtsc();
    bench->ts += bench->t1 - bench->t0 - bench->tc;
  }
  bench->ts = bench->ts / (ITERATIONS);

  printf("muInv took %I64d ticks\n", bench->ts);
  return bench->ts;
}

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
uint64_t getTimeForReference(BenchmarkData *bench, uint32_t megabyte)
{
  uint64_t i = 0;
  int Nr = 0;
  uint32_t rk_ref[44];
  uint64_t encryptions = megabyte*1024*1024/16;
  bench->c0 = clock();
  Nr = rijndaelKeySetupEnc(rk_ref, key1, 128);
  for (i = 0; i < encryptions; i++) {
    rijndaelEncrypt(rk_ref, Nr, msg1, res1);
  }
  bench->c1 = clock();
  bench->cs = bench->c1 - bench->c0 - bench->cc;

  printf("reference implementation took %ld ms for %d MB\n", 
          (bench->cs)*1000/CLOCKS_PER_SEC,megabyte);
  return (bench->cs)*1000/CLOCKS_PER_SEC;
}

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
uint64_t getTimeForBitSlice(BenchmarkData *bench, uint32_t megabyte)
{
  uint64_t i = 0;
  uint64_t encryptions = megabyte*1024*1024/64;
  bench->c0 = clock();
  initKey(keys,rk_bs);
  for (i = 0; i < encryptions; i++) {
    encrypt(msg, res,rk_bs);
  }
  bench->c1 = clock();
  bench->cs = bench->c1 - bench->c0 - bench->cc;

  printf("bitslice implementation took %ld ms for %d MB\n", 
          (bench->cs)*1000/CLOCKS_PER_SEC,megabyte);
  return (bench->cs)*1000/CLOCKS_PER_SEC;
}