#include "intermediateValues.h"

void printVinegarValues(FELT *vinegar){
	#ifdef KAT
		int i,j;
		unsigned char buf[FIELD_SIZE/8] = {0};
		writer W; 
		printf("vinegar values = ");
		for(i=0 ; i<VINEGAR_VARS ; i++){
			W = newWriter(buf);
			serialize_FELT(&W,vinegar[i]);
			for(j=0 ; j<FIELD_SIZE/8 ; j++){
				printf("%02X", buf[j]);
			}
		}
		printf("\n");
	#endif
}


void printAugmentedMatrix(Matrix A){
	#ifdef KAT
		int i,j,k;
		unsigned char buf[FIELD_SIZE/8] = {0};
		writer W; 
		printf("Augmented matrix = ");
		for(i=0 ; i<OIL_VARS ; i++){
			for(j=0 ; j<=OIL_VARS ; j++){
				W = newWriter(buf);
				serialize_FELT(&W,A.array[i][j]);
				for(k=0 ; k<FIELD_SIZE/8 ; k++){
					printf("%02X", buf[k]);
				}
			}
			printf("\n");
		}
	#endif
}

void reportSolutionFound(int solution_found){
	#ifdef KAT
		if(solution_found == 0){
			printf("solution not found, retry\n");
		}
		else{
			printf("solution found\n");
		}
	#endif
}

void printPrivateSolution(FELT *sig){
	#ifdef KAT
		int i,j;
		unsigned char buf[FIELD_SIZE/8] = {0};
		writer W; 
		printf("private solution = ");
		for(i=0 ; i<VINEGAR_VARS + OIL_VARS  ; i++){
			W = newWriter(buf);
			serialize_FELT(&W,sig[i+1]);
			for(j=0 ; j<FIELD_SIZE/8 ; j++){
				printf("%02X", buf[j]);
			}
		}
		printf("\n");
	#endif
}

void printEvaluation(FELT *eval){
	#ifdef KAT
		int i,j;
		unsigned char buf[FIELD_SIZE/8] = {0};
		writer W; 
		printf("evaluation = ");
		for(i=0 ; i< OIL_VARS  ; i++){
			W = newWriter(buf);
			serialize_FELT(&W,eval[i]);
			for(j=0 ; j<FIELD_SIZE/8 ; j++){
				printf("%02X", buf[j]);
			}
		}
		printf("\n");
	#endif
}
