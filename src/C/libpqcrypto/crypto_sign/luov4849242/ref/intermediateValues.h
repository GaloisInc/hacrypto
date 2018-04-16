#ifndef INTERMEDIATE_VALUES_H
#define INTERMEDIATE_VALUES_H

#include "parameters.h"
#include "LinearAlgebra.h"

void printVinegarValues(FELT *vinegar);
void printAugmentedMatrix(Matrix A);
void reportSolutionFound(int solution_found);
void printPrivateSolution(FELT *sig);
void printEvaluation(FELT *eval);

#endif