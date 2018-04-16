/*********************************************************************************************
 * DAGS: Key Encapsulation using Dyadic GS Codes.                             *
 * This code is exclusively intended for submission to the NIST Post=Quantum Cryptography.    *
 * For any other usage , contact the author(s) to ask permission.                             *
 **********************************************************************************************
 */

#include "decapsulation.h"

/*
 * Decapsulation() fuction compute the shared secret (ss) of type
 * unsigned char* and the ciphertext *(ct) of type unsigned char* by using the
 * secret key (sk)                             *
 */
int decapsulation(unsigned char *ss, const unsigned char *ct,
                  const unsigned char *sk)
{

    int i, test, decode_value;
    gf_init(6);                                            // Initialize of Log Antilog table
    const unsigned char *custom = (unsigned char *)"DAGs"; // customization = "DAGs";
    unsigned char *mot;
    unsigned char *m1, *rho1;
    unsigned char *r1, *d1, *rho2, *sigma, *e2, *hash_sigma, *e_prime;
    binmat_t H_alt;

    /*
    * Read in the alternative matrix from the secret key
    */
    H_alt = read_sk(sk);

    /*
   * Step_1 of the decapsulation :  Decode the noisy codeword C received as
   * part of the ciphertext ct = (c||d) with d is “ a plaintext confirmation”.
   * We obtain codeword mot = u1G and error e
   */
    e_prime = (unsigned char *)calloc(code_length, sizeof(unsigned char));
    mot = (unsigned char *)malloc(code_length);

    decode_value = decoding_H(H_alt, ct, e_prime, mot);
    mat_free(H_alt);

    /*
   * Step_2 of the decapsulation :  Output ⊥ if decoding fails or wt(e) != n0_w
   */

    if (decode_value == -1 || weight(e_prime, code_length) != n0_w)
    {
        return -1;
    }

    /*
   * Step_3 of the decapsulation :  Recover u_prime = mot and parse it as (rho1||m1)
   */
    m1 = (unsigned char *)malloc(k_prime);
    rho1 = (unsigned char *)malloc(k_sec);

    // Optimize modulo and removed copy to u1
    memcpy(rho1, mot, k_sec);
    memcpy(m1, mot + k_sec, code_dimension - k_sec);
    free(mot);

    /*
   * Step_4 of the decapsulation :  Compute r1 = G(m1) and d1 = H(m1)
   */
    r1 = (unsigned char *)malloc(code_dimension);
    d1 = (unsigned char *)malloc(k_prime);

    // Compute r1 = G(m1) where G is composed of sponge SHA-512 function and extend function.
    // m_extend is no longer required because we are using KangarooTwelve which handles sizing

    // m: input type unsigned char len k_prime | r: output type unsigned char len code_dimesion
    test = KangarooTwelve(m1, k_prime, r1, code_dimension, custom, cus_len);
    assert(test == 0); // Catch Error

    // Compute d1 = H(m1) where H is  sponge SHA-512 function

    test = KangarooTwelve(m1, k_prime, d1, k_prime, custom, cus_len);
    assert(test == 0); // Catch Error

    for (i = 0; i < k_prime; i++)
    {
        d1[i] = d1[i] % gf_card_sf;
    }
    // Return -1 if d distinct d1.
    // d starts at ct+code_length.
    if (memcmp(ct + code_length, d1, k_prime) != 0)
    {
        return -1;
    }
    free(d1);

    /*
   * Step_5 of the decapsulation: Parse r1 as (rho2||sigma1)
   */
    rho2 = (unsigned char *)malloc(k_sec);
    sigma = (unsigned char *)malloc(code_dimension);

    for (i = 0; i < code_dimension; i++)
    {
        if (i < k_sec)
        {
            // Optimize modulo
            rho2[i] = r1[i] & gf_ord_sf; //rho2 recovery
        }
        else
        {
            // Optimize modulo
            sigma[i - k_sec] = r1[i] & gf_ord_sf; // sigma1 recovery
        }
    }
    //Return ⊥ if rho1 distinct rho2
    if (memcmp(rho1, rho2, k_sec) != 0)
    {
        return -1;
    }
    free(r1);
    free(rho1);
    free(rho2);

    /*
   * Step_6 of the decapsulation: Generate error vector e2 of length n and
   * weight n0_w from sigma1
   */
    hash_sigma = (unsigned char *)malloc(code_length);

    //Hashing sigma_extend by using KangarooTwelve function.

    test = KangarooTwelve(sigma, k_prime, hash_sigma, code_length, custom, cus_len);
    assert(test == 0); // Catch Error
    free(sigma);

    //Generate error vector e2 of length code_length and weight n0_w from
    //hash_sigma1 by using random_e function.
    e2 = random_e(code_length, gf_card_sf, n0_w, hash_sigma);
    free(hash_sigma);

    /*
   * Step_7 of the decapsulation: Return ⊥ if e_prime distinct e.
   */
    if (memcmp(e_prime, e2, code_length) != 0)
    {
        return -1;
    }
    free(e_prime);
    free(e2);

    /*
   * Step_7 of the decapsulation: If the previous condition is not satisfied,
   * compute the shared secret ss by using KangarooTwelve 
   */
    test = KangarooTwelve(m1, k_prime, ss, ss_length, custom, cus_len);
    assert(test == 0); // Catch Error
    free(m1);

    return 0;
}
/*END*/
