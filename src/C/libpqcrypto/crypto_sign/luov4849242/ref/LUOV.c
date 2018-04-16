#include "LUOV.h"

/*
	Writes the seed for the secret key to a char array

	W  : A writer object
	sk : a secret key
*/
void serialize_SecretKey(writer *W, SecretKey *sk) {
	reader R = newReader(sk->privateseed);
	// write the 32-byte seed  
	transcribe(W, &R, 32);
}

/*
	Reads the seed for a secret key from a char array and recompute the public seed and T

	R : A reader object
	sk : receives the secret key
*/
void deserialize_SecretKey(reader *R, SecretKey *sk) {
	writer W = newWriter(sk->privateseed);
	// read the 32-byte seed
	transcribe(&W, R, 32);

	// compute the public seed
	Sponge sponge;
	initializeAndAbsorb(&sponge , sk->privateseed , 32);
	unsigned char publicseed[32];
	squeezeBytes(&sponge , publicseed , 32);

	// compute the matrix T
	sk->T[0] = empty; // this makes the linear map T linear, picking the first row of T random would make T an affine transformation
	squeezeBitcontainerArray(&sponge, &(sk->T[1]) , VINEGAR_VARS);
}

/*
	Frees the memory allocated by a secret key
*/
void destroy_SecretKey(SecretKey *sk) {
}

/*
	Writes a public key to a char array

	W : A writer object
	pk : the public key
*/
void serialize_PublicKey(writer* W, PublicKey* pk) {
	int i;

	// Write the public seed
	reader R = newReader(pk->publicseed);
	transcribe(W,&R,32);

	// Write Q_2
	for (i = 0; i < STORED_COLS_OF_P ; i++) {
		serialize_bitcontainer(W, pk->Q2[i]);
	}
	return;
}

/*
	Reads a public key from a char array

	R : A reader object
	pk : receives the public key
*/
void deserialize_PublicKey(reader* R, PublicKey* pk) {
	int i;

	// Read the public seed
	writer W = newWriter(pk->publicseed);
	transcribe(&W,R,32);

	// Allocate memory and read Q_2
	pk->Q2 = malloc(sizeof(bitcontainer)*STORED_COLS_OF_P);
	for (i = 0; i < STORED_COLS_OF_P ; i++) {
		pk->Q2[i] = deserialize_bitcontainer(R);
	}
	return;
}

/*
	Frees the memory allocated by a public key
*/
void destroy_PublicKey(PublicKey *pk) {
	free(pk->Q2);
}

/*
	Writes a signature to a char array

	W : A writer object
	S : the signature
*/
void serialize_signature(writer* W, Signature* S) {
	int i;

	// writes all the entries of the vector s, except the first entry, 
	// which corresponds to a homogenizing variable and is always equal to 1
	for(i=1 ; i<=VARS ; i++){
		serialize_FELT(W,S->s[i]);
	}
}

/*
	Reads a signature from a char array

	R : A reader object
	S : receives the signature
*/
void deserialize_signature(reader* R, Signature* S) {
	int i;
	// sets the first variable, which is a homogenizing variable to 1
	S->s[0] = ONE;

	// read the remaining variables
	for(i=1; i<=VARS; i++){
		S->s[i] = deserialize_FELT(R);
	}
}

/*
	Frees the memory allocated by a signature
*/
void destroy_signature(Signature *S) {
}

/*
	Calculates Q_2, the last OIL_VARS*(OIL_VARS+1)/2 columns of the macaulay matrix of the public system

	sk : the secret key
	pk : the public key
*/
void calculateQ2(SecretKey *sk , PublicKey *pk) {
	int i, j, k, col;
	bitcontainer **TempMat = malloc(sizeof(bitcontainer*) * (VINEGAR_VARS+1));
	bitcontainer r;

	// Absorb the public seed in a sponge object
	Sponge sponge;
	initializeAndAbsorb(&sponge, pk->publicseed , 32);

	// Allocate memory for temporary matrices that will store the values P_i,1 T + P_i,2 for i from 1 to OIL_VARS.
	// These OIL_VARS matrices are bitsliced into one OIL_VARS by OIL_VARS array of bitcontainers.
	// All entries of the matrices are initialized to zero.
	for (i = 0; i <= VINEGAR_VARS; i++) {
		TempMat[i] = malloc(sizeof(bitcontainer)*OIL_VARS);
		for (j = 0; j < OIL_VARS; j++) {
			TempMat[i][j] = empty;
		}
	}

	// Simultaneously calculate P_i,1*T + P_i,2 for all i from 1 to OIL_VARS
	for (i = 0; i <= VINEGAR_VARS; i++) {
		// Calculates P_i,1*T
		for (j = i; j <= VINEGAR_VARS; j++) {
			r = randomBitcontainer(&sponge);
			for (k = 0; k < OIL_VARS; k++) {
				if (getBit(sk->T[j], k)) {
					TempMat[i][k] = xor(TempMat[i][k], r);
				}
			}
		}
		// Add P_i,2
		for (j = 0; j < OIL_VARS; j++) {
			r = randomBitcontainer(&sponge);
			TempMat[i][j] = xor(TempMat[i][j], r);
		}
	}

	// Calculate P_i,3 = Transpose(T)*TempMat_i, and store the result in Q_2
	col = 0;
	pk->Q2 = malloc(STORED_COLS_OF_P * sizeof(bitcontainer));
	for (i = 0; i < OIL_VARS; i++) {
		for (j = i; j < OIL_VARS; j++) {
			pk->Q2[col] = empty;
			for (k = 0; k <= VINEGAR_VARS; k++) {
				if (getBit(sk->T[k] , i ) ) {
					pk->Q2[col] = xor(pk->Q2[col], TempMat[k][j]);
				}
			}
			if (j != i){
				for (k = 0; k <= VINEGAR_VARS; k++) {
					if (getBit(sk->T[k] , j ) ) {
						pk->Q2[col] = xor(pk->Q2[col], TempMat[k][i]);
					}
				}
			}
			col ++ ;
		}
	}

	// Free the memory occupied by TempMat
	for (i = 0; i <= VINEGAR_VARS; i++) {
		free(TempMat[i]);	}
	free(TempMat);
}

/*
	Generates a key pair

	pk : receives the public key
	sk : receives the secret key
*/
void generateKeyPair(PublicKey *pk, SecretKey *sk) {
	randombytes(sk->privateseed , 32);

	// Calculate public seed
	Sponge sponge;
	initializeAndAbsorb(&sponge , sk->privateseed, 32);
	squeezeBytes(&sponge, pk->publicseed , 32);

	// Calculate T
	sk->T[0]=empty;/* makes T linear instead of affine*/
	squeezeBitcontainerArray(&sponge , &(sk->T[1]) , VINEGAR_VARS);

	// Calculates Q_2, the part of the public map P that cannot be generated from the public seed
	calculateQ2( sk , pk );
}


/*
	Builds the augmented matrix for the system F(x) = target , after fixing the vinegar variables

	A                 : Receives the augmented matrix, should be initialized to zero the zero matrix
	vinegar_variables : An assignment to the vinegar variables
	target            : The target vector to find a solution for
	T                 : The V-by-M matrix that determines the linear transformation T
	sponge            : The sponge object used to generate the first part of the public map P
*/
void BuildAugmentedMatrix(Matrix A, FELT *vinegar_variables , FELT *target, bitcontainer *T, Sponge *sponge) {
	int i, j, k;
	bitcontainer r, **F2;
	FELT prod;

	// Sets the right hand side of the Augmented matrix to the target vector
	for (k = 0; k < OIL_VARS; k++) {
		A.array[k][OIL_VARS] = target[k];
	}

	// Allocate memory for the matrices F_1,2, ... , F_OIL_VARS,2.
	// These matrices are bit sliced together and stored as a OIL_VARS by VINEGAR_VARS array of bitcontainers.
	// All entries of these matrices are initialized to zero.
	F2 = malloc(sizeof(bitcontainer*)*OIL_VARS);
	for (k = 0; k < OIL_VARS; k++) {
		F2[k] = calloc(VINEGAR_VARS+1,sizeof(bitcontainer));
	}

	// Computes F_i,2 = (P_i,1 + Transpose(P_i,1)*T + P_i,2 ) simultaneously for all i from 1 to OIL_VARS
	// and subtracts the evaluation of P in the vinegar variables from the right hand side 
	for (i = 0; i <= VINEGAR_VARS; i++) {
		for (j = i; j <= VINEGAR_VARS; j++) {
			r = randomBitcontainer(sponge);

			prod = multiply(vinegar_variables[i], vinegar_variables[j]);
			for (k = 0; k < OIL_VARS; k++) {
				if (getBit(r,k)) {
					// subtract the term in v_i*v_j from the right hand side 
					A.array[k][OIL_VARS] = add(A.array[k][OIL_VARS],prod);
					
					// add (P_i,1 + Transpose(P_i,1)*T part to F_i,2
					F2[k][j] = xor(F2[k][j],T[i]); 
					F2[k][i] = xor(F2[k][i],T[j]); 
				}
			}
		}
		// add P_i,2 part to F_i,2 
		for (j = 0; j < OIL_VARS; j++) {
			r = randomBitcontainer(sponge);
			for (k = 0; k < OIL_VARS; k++) {
				if (getBit(r,k)) {
					flipBit(&F2[k][i],j);
				}
			}
		}
	}

	// Calculate v*P_i,2 and assign to the i-th row of the LHS of the augmented matrix
	for (k = 0; k < OIL_VARS; k++)	{
		for (i = 0; i <= VINEGAR_VARS; i++) {
			for (j = 0; j < OIL_VARS; j++)	{
				if (getBit(F2[k][i],j)) {
					A.array[k][j] = add(A.array[k][j],vinegar_variables[i]);
				}
			}
		}
	}

	// free the memory occupied by the F_i,2
	for (k = 0; k<OIL_VARS; k++){
		free(F2[k]);
	}
	free(F2);
}

/*
	Solves the system F(x) = target for x

	sk : The secret key
	target : The target vector to find a solution for
	vinegar_sponge : The sponge object used to generate the assignment to the vinegar variables
	signature : A signature object, used to store the solution x 
*/
void solvePrivateUOVSystem(SecretKey sk, FELT *target , Sponge *vinegar_sponge , Signature *signature) {
	Matrix A;
	int solution_found = 0;

	// calculate public seed from private seed 
	Sponge seedsponge;
	initializeAndAbsorb(&seedsponge, sk.privateseed , 32);
	unsigned char publicseed[32];
	squeezeBytes(&seedsponge, publicseed , 32);

    // Repeatedly try an assignment to the vinegar variables until a unique solution is found
	Sponge sponge;
	while (solution_found == 0) {
		// Initialize sponge for squeezin the public map P
		initializeAndAbsorb(&sponge, publicseed , 32);

		// Set homogenizing variable to one and squeeze an assignment to the vinegar variables from the vinegar sponge
		signature->s[0] = ONE;
		squeezeVector(vinegar_sponge , &(signature->s[1]) , VINEGAR_VARS);

		// Print vinegar values if KAT is defined
		printVinegarValues(&(signature->s[1]));

		// Build the augmented matrix for the linear system
		A = zeroMatrix(OIL_VARS, OIL_VARS + 1);
		BuildAugmentedMatrix(A, signature->s , target, sk.T , &sponge);

		// Print augmented matrix if KAT is defined
		printAugmentedMatrix(A);

		// Try to find a unique solution to the linear system
		solution_found = getUniqueSolution(A,&(signature->s[1+VINEGAR_VARS]));

		// Report whether a solution is found if KAT is defined
		reportSolutionFound(solution_found);

		// Free the memory occupied by the augmented matrix
		destroy_matrix(A);
	}
}

#ifndef MESSAGE_RECOVERY

/*
	Computes the target vector by hashing the document, after padding it with a 0x00 byte
	(Only used in appended signature mode)

	document : The document that is being signed
	len : The number of bytes of the document being signed
	target : receives the target vector
 */
void computeTarget(const unsigned char* document , uint64_t len, FELT *target){
	Sponge sponge;
	unsigned char pad = 0;

	Keccak_HashInitialize_SHAKE(&sponge);
	Keccak_HashUpdate(&sponge,document , len*8);
	Keccak_HashUpdate(&sponge,&pad , 8);
	Keccak_HashFinal(&sponge , 0);
	squeezeVector(&sponge  , target , OIL_VARS);
}
#else

/*
	Computes the target vector. 
	The document is hashed, after padding it with a 0x01 byte, to get the first part of the target.
	Then, the first part is hashed again and xored with the last part of the padded document to get the second part of the target.
	(Only used in message recovery mode)

	document : The document that is being signed
	len : The number of bytes of the document being signed
	target : receives the target vector
 */
void computeTarget(const unsigned char* document , uint64_t len, FELT *target){
	int i,start_recovery;
	Sponge sponge;
	unsigned char buf[FIRST_PART_TARGET + SECOND_PART_TARGET];
	unsigned char pad = 1;

	// Compute first part of the target and put in the first part of the buffer 
	Keccak_HashInitialize_SHAKE(&sponge);
	Keccak_HashUpdate(&sponge,document , len*8);
	Keccak_HashUpdate(&sponge,&pad , 8);
	Keccak_HashFinal(&sponge , 0);
	squeezeBytes(&sponge  , buf , FIRST_PART_TARGET );

	// Absorb first part of target into a Sponge object and squeeze into the second part of the buffer
	initializeAndAbsorb(&sponge, buf , FIRST_PART_TARGET);
	squeezeBytes(&sponge  , &(buf[FIRST_PART_TARGET]) , SECOND_PART_TARGET );

	// If not the entire document can be covered from a signature, we xor the last part of the message 
	// into the second part of the buffer and we xor the last byte with a 0x01.
	// Otherwise, we xor the entire document into the second part of the buffer, and we xor the next byte with a 0x01
	if(len > RECOVERED_PART_MESSAGE){
		start_recovery = len- RECOVERED_PART_MESSAGE;
		buf[FIRST_PART_TARGET + SECOND_PART_TARGET - 1] ^= 1;
	}
	else{
		start_recovery = 0;
		buf[FIRST_PART_TARGET + len] ^= 1;
	}
	for(i = start_recovery ; i<len ; i++){
		buf[FIRST_PART_TARGET + i-start_recovery] ^= document[i];
	}

	// Interpret the contents of the buffer as a list of fied elements.
	reader R = newReader(buf);
	for (i = 0; i < OIL_VARS ; i++)
	{
		target[i] = deserialize_FELT(&R);
	}
}
#endif

/*
	If message recovery is enabled, this function extracts the last part of the document from the evaluated signature and appends it to the first part of document

	document : Initially this contains the first part of the document, after the call to this function this contains the entire original document
	len      : pointer to the length of document, which is altered appropriately
	evaluation : The evaluation of the public map in the signature
*/
void extractMessage(unsigned char *document ,unsigned long long *len , FELT *evaluation){
	#ifdef MESSAGE_RECOVERY
	int i, reading;
	unsigned char buf[FIRST_PART_TARGET+SECOND_PART_TARGET];
	unsigned char buf2[SECOND_PART_TARGET];
	Sponge sponge;

	// Interpret the evaluation of P as an array of bytes
	writer W = newWriter(buf);
	for(i = 0 ; i<OIL_VARS ; i++){
		serialize_FELT(&W,evaluation[i]);
	}

	// Absorb the first part of the buffer into a Sponge object and squeeze into buffer 2
	initializeAndAbsorb(&sponge, buf , FIRST_PART_TARGET );
	squeezeBytes(&sponge  , buf2 , SECOND_PART_TARGET );

	// Xor the secon part of the evaluation into buffer 2
	for(i = 0 ; i<SECOND_PART_TARGET ; i++ ){
		buf2[i] ^= buf[FIRST_PART_TARGET + i];
	}

	// Start searching from the left for the first byte equal to 0x01
	// All bytes before this byte are appended to the document and len is increased
	reading = 0;
	unsigned long long oldlen = *len; 
	for (i = SECOND_PART_TARGET-1; i >= 0 ; i--)
	{
		if(reading){
			document[oldlen + i] = buf2[i];
		}
		else{
			if(buf2[i] == 1){
				reading = 1;
				*len += i;
			}
		}
	}

	#endif
}

/*
	Generates a signature for a document

	sk : the secret key
	document : a char array containing the document to be signed
	len : the length of the document

	returns : A signature for the document
*/
Signature signDocument(SecretKey sk,const unsigned char *document , uint64_t len) {
	int i, j;
	Signature signature;
	FELT target[OIL_VARS];

	// Define the appropriate padding, based on wheter we are in message recovery mode or not
	unsigned char pad = 0;
	#ifdef MESSAGE_RECOVERY
		pad = 1;
	#endif

	// compute the target for the public map P
	computeTarget(document, len , target);

	// Initialize the vinegar sponge from the padded document and the private key
	Sponge vinegar_sponge;
	Keccak_HashInitialize_SHAKE(&vinegar_sponge);
	Keccak_HashUpdate(&vinegar_sponge, document, len*8 );
	Keccak_HashUpdate(&vinegar_sponge, &pad , 8);
	Keccak_HashUpdate(&vinegar_sponge, sk.privateseed , 32*8);
	Keccak_HashFinal(&vinegar_sponge, 0 );

	// Generate a solution to F(x) = target
	solvePrivateUOVSystem(sk, target, &vinegar_sponge , &signature);

	// Print solution to the equation F(x) = target if KAT is defined
	printPrivateSolution(signature.s);

	// Convert into a solution for P(x) = target
	for (i = 0; i <= VINEGAR_VARS; i++) {
		for (j = 0; j < OIL_VARS; j++) {
			if ( getBit(sk.T[i] , j )) {
				signature.s[i] = subtract(signature.s[i],signature.s[VINEGAR_VARS +1+ j]);
			}
		}
	}

	return signature;
}

/* 
	Evaluated the public map P in a signature

	pk : The public key
	signature : The point that P is evaluated in
	evaluation : Receives the vector P(signature)
*/
void evaluatePublicMap(PublicKey *pk, Signature *signature , FELT* evaluation){
	int i,j,k,col;
	FELT prod;
	bitcontainer r;
	Sponge sponge;

	// initialize evaluation to zero
	for(i = 0 ; i<OIL_VARS ; i++){
		evaluation[i] = ZERO;
	}
	
	// Prepare a sponge for squeezing the first part of the public map P
	initializeAndAbsorb(&sponge , pk->publicseed , 32);

	// Evaluate the part of P that is generated from the public seed
	for (i = 0; i <= VINEGAR_VARS; i++) {
		for (j = i; j <= VARS ; j++) {
			r = randomBitcontainer(&sponge);

			prod = multiply(signature->s[i], signature->s[j]);
			for (k = 0; k < OIL_VARS; k++) {
				if (getBit(r,k)) {
					evaluation[k] = add(evaluation[k],prod);
				}
			}
		}
	}
	// Evaluate the part of P that is stored in the public key
	col = 0;
	for (i = VINEGAR_VARS +1 ; i <= VARS; i++) {
		for (j = i; j <= VARS; j++) {
			prod = multiply(signature->s[i], signature->s[j]);
			for (k = 0; k < OIL_VARS; k++) {
				if ( getBit(pk->Q2[col] , k) ) {
					evaluation[k] = add(evaluation[k],prod);
				}
			}
			col++;
		}
	}

	// prints the evaluation of the public map if KAT is defined
	printEvaluation(evaluation);
}

/*
	Verifies a signature for a document

	Remark : If we are in message recovery mode, this function does more work than strictly necessary 

	pk : the public key
	signature : a signature
	document : a char array containing a document
	len : the length of the document

	returns : 0 if the signature is valid, -1 otherwise
*/
int verify(PublicKey *pk, Signature *signature, unsigned char *document , unsigned long long *len) {
	int i;
	FELT evaluation[OIL_VARS];
	FELT target[OIL_VARS];

	// Evaluate the public map P at the signature
	evaluatePublicMap(pk, signature , evaluation);

	// If we are in message recovery mode, we extracts a part of the document from the signature
	extractMessage(document , len , evaluation);

	// We compute the target based on the full document
	computeTarget(document, *len, target);
	
	// Output 0 if the evaluation of the public map is equal to the target, otherwise output -1
	for(i=0 ; i<OIL_VARS ; i++){
		if (! isEqual(target[i], evaluation[i])){
			return -1;
		}
	}
	return 0;
}
