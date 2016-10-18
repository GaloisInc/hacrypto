/*
 * pmac_main.c
 *
 * Author:  Ted Krovetz (tdk@acm.org)
 * History: 1 April 2000 - first release (TK) - version 0.9
 *
 * This is the driver program for the OCB-AES-n reference code. 
 * It prints out some AES-OCB-n test vectors.  You have to 
 * compile the code with the appropriate value of 
 * OCB_AES_KEY_BITLEN (one of 128, 192, 256) to generate the
 * desired set of test vectors.
 *
 * OCB-AES-n is defined in the NIST submission "OCB Mode"
 * (dated 1 April 2000), submitted by Phillip Rogaway, with
 * auxiliary submitters Mihir Bellare, John Black, and Ted Krovetz.
 *
 * This code is freely available, and may be modified as desired.
 * Please retain the authorship and change history.
 * Note that OCB mode itself is patent pending.
 *
 * The code in this distribution is NOT optimized for speed; it is 
 * only designed to clarify the algorithm and to provide a point
 * of comparison for other implementations.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include "ocb.h"



void print_hex_string(char* buf, int len)
{
    int i;

    if (len==0) { printf("<empty string>"); return; }
    if (len>=40) {
        for (i = 0; i < 10; i++)
             printf("%02x", *((unsigned char *)buf + i));
        printf(" ... ");
        for (i = len-10; i < len; i++)
             printf("%02x", *((unsigned char *)buf + i));
        printf(" [%d bytes]", len);
        return;
    }
    for (i = 0; i < len; i++)
        printf("%02x", *((unsigned char *)buf + i));
}


void print_pmac_test_case(int   i,
                          char* K,
                          char* M,
                          char* T)
{
   keystruct *keys = NULL;
   keys = ocb_aes_init(K, 16, NULL);

   pmac_aes(keys, M, i, T);

   printf("\n\nTest Case PMAC-AES-%d-%dB", AES_KEY_BITLEN, i);
   printf(  "\nKey       ");  print_hex_string(K, AES_KEY_BITLEN/8);
   printf(  "\nMessage   ");  print_hex_string(M, i);
   printf(  "\nTag       ");  print_hex_string(T, 16);
}


int print_pmac_test_vectors ( void )
{
    char z[1000]={0,}, key[32], pt[50], ct[1000], 
         nonce[16] = {0,}, tag[16];
    int i;

    nonce[15] = 1;
    for (i=0; i<32; i++) {
        key[i] = i;
    }
    for (i=0; i<34; i++) {
        pt[i] = i;
    }

    print_pmac_test_case(   0,key,pt,tag);
    print_pmac_test_case(   3,key,pt,tag);
    print_pmac_test_case(  16,key,pt,tag);
    print_pmac_test_case(  20,key,pt,tag);
    print_pmac_test_case(  32,key,pt,tag);
    print_pmac_test_case(  34,key,pt,tag);
    print_pmac_test_case(1000,key, z,tag);
    printf("\n");
 
    return 0;
} 


int main(void)
{
    printf("Some PMAC test vectors\n\n");
    print_pmac_test_vectors();
    printf("\n\n");
}
