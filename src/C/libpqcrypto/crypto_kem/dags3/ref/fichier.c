#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "matrix.h"
#include "fichier.h"

void cfile_vec_F12(char *file, int n, gf *L)
{
    FILE *fichier;
    fichier = fopen(file, "wb");
    unsigned char c = 0;
    unsigned char c1 = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        c = L[i] & 255;
        c1 = (L[i] >> 8) & 255;
        fprintf(fichier, "%c", c1);
        fprintf(fichier, "%c", c);
    }
    fclose(fichier);
}

void cfile_vec_F12_int(char *file, int n, int *L)
{
    FILE *fichier;
    fichier = fopen(file, "wb");
    unsigned char c = 0;
    unsigned char c1 = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        c = L[i] & 255;
        c1 = (L[i] >> 8) & 255;
        fprintf(fichier, "%c", c1);
        fprintf(fichier, "%c", c);
    }
    fclose(fichier);
}
void cfile_vec_F6(char *file, int n, gf_t *L)
{
    FILE *fichier;
    fichier = fopen(file, "wb");
    unsigned char c = 0;
    int i;

    for (i = 0; i < n; i++)
    {
        c = L[i];
        fprintf(fichier, "%c", c);
    }
    fclose(fichier);
}

void cfile_vec_char(char *file, int n, unsigned char *L)
{
    FILE *fichier;
    fichier = fopen(file, "wb");
    unsigned char c = 0;
    int i;

    for (i = 0; i < n; i++)
    {
        c = L[i];
        fprintf(fichier, "%c", c);
    }
    fclose(fichier);
}

void cfile_matrix_F6(char *file, int dimension, int longueur, binmat_t M)
{
    FILE *fichier;
    fichier = fopen(file, "wb");
    unsigned char c = 0;
    int i, j;
    for (i = 0; i < dimension; i++)
    {
        for (j = 0; j < longueur; j++)
        {
            c = M.coeff[i][j] & 255;
            fprintf(fichier, "%c", c);
        }
    }
    fclose(fichier);
}
void cfile_matrix_F12(char *file, int dimension, int longueur, binmat_t M)
{
    FILE *fichier;
    fichier = fopen(file, "wb");
    unsigned char c = 0;
    unsigned char c1 = 0;
    int i, j;
    for (i = 0; i < dimension; i++)
    {
        for (j = 0; j < longueur; j++)
        {
            c = M.coeff[i][j] & 255;
            c1 = (M.coeff[i][j] >> 8) & 255;
            fprintf(fichier, "%c", c1);
            fprintf(fichier, "%c", c);
        }
    }
    fclose(fichier);
}
void Lecture_cfile_vec_F12(char *file, int n, gf *L)
{
    FILE *fichier;
    fichier = fopen(file, "rb");
    unsigned char c = 0;
    unsigned char c1 = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        c1 = fgetc(fichier);
        c = fgetc(fichier);
        L[i] = (c1 << 8) ^ c;
    }
    fclose(fichier);
}
void Lecture_cfile_vec_F12_int(char *file, int n, int *L)
{
    FILE *fichier;
    fichier = fopen(file, "rb");
    unsigned char c = 0;
    unsigned char c1 = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        c1 = fgetc(fichier);
        c = fgetc(fichier);
        L[i] = (c1 << 8) ^ c;
    }
    fclose(fichier);
}
void Lecture_cfile_vecF6(char *file, int n, gf_t *L)
{
    FILE *fichier;
    fichier = fopen(file, "rb");
    unsigned char c = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        c = fgetc(fichier);
        L[i] = c;
    }
    fclose(fichier);
}

void Lecture_cfile_matrix_F6(char *file, int dimension, int longueur, binmat_t M)
{
    FILE *fichier;
    fichier = fopen(file, "rb");
    unsigned char c = 0;
    int i, j;
    for (i = 0; i < dimension; i++)
    {
        for (j = 0; j < longueur; j++)
        {
            c = fgetc(fichier);
            M.coeff[i][j] = c;
        }
    }
    fclose(fichier);
}
void Lecture_cfile_matrix_F12(char *file, int dimension, int longueur, binmat_t M)
{
    FILE *fichier;
    fichier = fopen(file, "rb");
    unsigned char c = 0;
    unsigned char c1 = 0;
    int i, j;
    for (i = 0; i < dimension; i++)
    {
        for (j = 0; j < longueur; j++)
        {

            c1 = fgetc(fichier);
            c = fgetc(fichier);
            M.coeff[i][j] = (c1 << 8) ^ c;
        }
    }
}

void Lecture_cfile_vec_F6_int(char *file, int n, int *L)
{
    FILE *fichier;
    fichier = fopen(file, "rb");
    unsigned char c = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        c = fgetc(fichier);
        L[i] = c;
    }
    fclose(fichier);
}
