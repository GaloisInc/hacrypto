#include "matrix.h"
#include "time.h"

/*
 ~~~~~~~~Matrix Operations ~~~~~~~~~~~~~~~~ */

binmat_t matrix_multiplication(binmat_t A, binmat_t B)
{
    binmat_t res;
    if (A.coln != B.rown)
    {
        printf("Error: Impossible to multiply\n");
        return res;
    }
    else
    {
        int i, j, k;

        gf a;
        res = matrix_init(A.rown, B.coln);
        for (i = 0; i < A.rown; i++)
        {
            for (j = 0; j < B.coln; j++)
            {
                a = 0;
                for (k = 0; k < A.coln; k++)
                {
                    a = a ^ gf_mult(A.coeff[i][k], B.coeff[k][j]);
                }
                res.coeff[i][j] = a;
            }
        }
        return res;
    }
}

binmat_t matrix_transpose(binmat_t A)
{
    int i, j;
    binmat_t Res;
    Res = matrix_init(A.coln, A.rown);
    for (i = 0; i < A.rown; i++)
    {
        for (j = 0; j < A.coln; j++)
        {
            Res.coeff[j][i] = A.coeff[i][j];
        }
    }
    return Res;
}

binmat_t matrix_multiplicaion_subfield(binmat_t A, binmat_t B)
{
    binmat_t Res;
    if (A.coln != B.rown)
    {
        printf("Error: not possible to multiply\n");

        return Res;
    }
    else
    {
        int i, j, k;
        gf a;
        Res = matrix_init(A.rown, B.coln);
        for (i = 0; i < A.rown; i++)
        {
            for (j = 0; j < B.coln; j++)
            {
                a = 0;
                for (k = 0; k < A.coln; k++)
                {
                    a = a ^ gf_Mult_subfield(A.coeff[i][k], B.coeff[k][j]);
                }
                Res.coeff[i][j] = a;
            }
        }
        return Res;
    }
}

binmat_t matrix_permutation(int *P)
{
    binmat_t M;
    int i;
    M = matrix_init(code_length, code_length);
    for (i = 0; i < code_length; i++)
    {
        M.coeff[P[i]][i] = 1;
    }
    return M;
}

binmat_t matrix_init(int rown, int coln)
{
    unsigned int i;
    binmat_t A;
    A.coln = coln;
    A.rown = rown;

    A.coeff = (gf **)malloc(A.rown * sizeof(gf *));
    for (i = 0; i < A.rown; i++)
    {
        A.coeff[i] = (gf *)calloc(A.coln, sizeof(gf));
    }

    return A;
}

binmat_t matrix_init_identity(int rown)
{
    unsigned int i;
    binmat_t A;
    A.coln = rown;
    A.rown = rown;
    A.coeff = (gf **)malloc(A.rown * sizeof(gf *));
    for (i = 0; i < A.rown; i++)
    {
        A.coeff[i] = (gf *)calloc(A.coln, sizeof(gf));
        A.coeff[i][i] = 1;
    }
    return A;
}

void mat_free(binmat_t A)
{
    unsigned int i;
    for (i = 0; i < A.rown; i++)
    {
        free(A.coeff[i]);
    }
    free(A.coeff);
}

void aff_mat(binmat_t mat)
{
    printf("Show new Matrix\n");
    int i, j;
    for (i = 0; i < (mat.rown); i++)
    {
        for (j = 0; j < (mat.coln); j++)
        {
            printf("%d\t", mat.coeff[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

binmat_t matrix_copy(binmat_t A)
{
    binmat_t X;
    int i, j;
    X = matrix_init(A.rown, A.coln);
    for (i = 0; i < A.rown; i++)
    {
        for (j = 0; j < A.coln; j++)
        {
            X.coeff[i][j] = A.coeff[i][j];
        }
    }
    return X;
}

void mat_rowxor(binmat_t A, int i, int j)
{
    int k;
    for (k = 0; k < A.coln; k++)
    {
        A.coeff[i][k] ^= A.coeff[j][k];
    }
}

void mat_rowxor_with_another(binmat_t A, int i, gf *Line)
{
    int k;
    for (k = 0; k < A.coln; k++)
    {
        //A.coeff[i][k]=(A.coeff[i][k]+ opp_gf(Line[k],q))%(q);
        A.coeff[i][k] = (A.coeff[i][k]) ^ (Line[k]);
    }
}

void mat_swapcol(binmat_t A, int i, int j)
{
    int k;
    gf tmp[A.rown];
    for (k = 0; k < A.rown; k++)
    {
        tmp[k] = A.coeff[k][i];
    }
    for (k = 0; k < A.rown; k++)
    {
        A.coeff[k][i] = A.coeff[k][j];
    }
    for (k = 0; k < A.rown; k++)
    {
        A.coeff[k][j] = tmp[k];
    }
}

void mat_random_swapcol(binmat_t A)
{
    int k, i, j;
    gf tmp[A.rown];
    unsigned char *random_bytes_col = malloc(A.coln);
    randombytes(random_bytes_col, A.coln);
    unsigned char *random_bytes_col_2 = malloc(A.coln);
    randombytes(random_bytes_col_2, A.coln);
    //srand(time(NULL));
    i = (random_bytes_col[0] % (A.coln));
    j = (random_bytes_col_2[1] % (A.coln));

    free(random_bytes_col);
    free(random_bytes_col_2);

    for (k = 0; k < A.rown; k++)
    {
        tmp[k] = A.coeff[k][i];
        A.coeff[k][i] = A.coeff[k][j];
        A.coeff[k][j] = tmp[k];
    }
}

void mat_swaprow(binmat_t A, int i, int j)
{
    int k;
    gf tmp[A.coln];
    for (k = 0; k < A.coln; k++)
    {
        tmp[k] = A.coeff[i][k];
        A.coeff[i][k] = A.coeff[j][k];
        A.coeff[j][k] = tmp[k];
    }
}

void mat_line_mult_by_gf(binmat_t A, gf a, int i)
{
    int j;
    for (j = 0; j < A.coln; j++)
    {
        A.coeff[i][j] = gf_Mult_subfield(A.coeff[i][j], a);
    }
}

gf *mat_line_mult_with_return(binmat_t A, gf a, int i)
{
    int j;
    gf *Line;
    Line = (gf *)calloc(A.coln, sizeof(gf));
    for (j = 0; j < A.coln; j++)
    {
        Line[j] = gf_Mult_subfield(A.coeff[i][j], a);
    }
    return Line;
}

gf eltseq(gf a, int k)
{
    gf x[m_val];
    x[0] = a >> gf_extd_sf;
    x[1] = a & (u_val-1);
    return x[k];
}
binmat_t mat_Into_base(binmat_t H)
{
    int k, i, j;
    int r = order * pol_deg;

    binmat_t HH = matrix_init(m_val * r, code_length);
    for (k = 0; k < m_val; k++)
    {
        for (i = 0; i < r; i++)
        {
            for (j = 0; j < code_length; j++)
            {
                HH.coeff[k * r + i][j] = eltseq(H.coeff[i][j], k);
            }
        }
    }
    return HH;
}

int *test_mat(binmat_t A)
{
    //int k =A->coln-NB_ERRORS*EXT_DEGREE;
    int k = code_dimension;
    int l;
    int i = k;
    while (((A.coeff[i - k][i]) == 1) && (i < A.coln)) //Stop when a coefficient on the "diagonal" is not 1
    {
        i++;
    }
    l = 0;
    if (i >= A.coln) //if the while did not stop then we have identity on the right
    {
        return NULL;
    }
    else // else we look for the first not column which has a 1 on the row
    {
        while ((A.coeff[i - k][i]) == 0 && (l < k))
        {
            l++;
        }
        int *test = malloc(2 * sizeof(int));
        test[0] = i;
        test[1] = l;
        return test;
    }
}

int syst_mat(binmat_t H)
{
    int i, j, l, test = 0;
    gf temp;
    int n = H.coln;
    int k = H.rown;

    for (i = 0; i < k; i++)
    {
        j = i + n - k;

        if (H.coeff[i][i + n - k] == 0)
        { //We're looking for a non-zero pivot
            test = 1;
            for (j = 0; j < n; j++)
            {
                if (H.coeff[i][j])
                {
                    break;
                }
            }
        }
        if (j == n)
        {
            return 0;
        }
        if (test == 1)
        { // We switches the columns J and i + n = k
            test = 0;
            for (l = 0; l < k; l++)
            {
                temp = H.coeff[l][i + n - k];
                H.coeff[l][i + n - k] = H.coeff[l][j];
                H.coeff[l][j] = temp;
            }
        }
        if (H.coeff[i][i + n - k] != 1)
        {
            for (j = 0; j < n; j++)
            {
                H.coeff[i][j] = gf_mult(H.coeff[i][j],
                                        gf_Inv_subfield(H.coeff[i][i + n - k]));
            }
        }

        //Here we do the elimination on column i + n-k
        gf elim;
        for (l = 0; l < k; l++)
        {
            if (l == i)
            {
                continue;
            }
            if (H.coeff[l][i + n - k])
            {
                j = 0;
                for (j = 0; j < n; j++)
                {
                    elim = gf_mult(H.coeff[i][i + n - k], H.coeff[l][j]);
                    elim = elim ^ (gf_mult(H.coeff[l][i + n - k], H.coeff[i][j]));
                    H.coeff[l][j] = elim;
                }
            }
        }
    }

    return 1;
}

//=============================================================================================

int equals_matrxi(binmat_t H, binmat_t S)
{
    int i, j;
    for (i = 0; i < H.rown; i++)
    {
        for (j = 0; j < H.coln; j++)
        {
            if (H.coeff[i][j] == S.coeff[i][j])
                return 0;
        }
    }

    return 1;
}

int syst(binmat_t H)
{

    int i, j, l = 0, test = 0;
    gf temp;
    int n = H.coln;
    int k = H.rown;
    for (i = 0; i < k; i++)
    {

        test = 0;

        l = 0;
        j = i + n - k;
        if (H.coeff[i][i + n - k] == 0)
        { //We're looking for a non-zero pivot
            test = 1;
            //printf("search Pivot\n");
            for (l = i + 1; l < k; l++)
            {
                if (H.coeff[l][j])
                {
                    //printf("Find Pivot\n");
                    break;
                }
            }
        }
        if (l == k && (i != (k - 1)))
        {
            // printf("Non systematic Matrix %d\n", l);
            return -1;
        }
        if (test == 1)
        { // We switches the lines l and i
            test = 0;
            //printf("Permut line\n");
            //temp=P[i+n-k];
            //P[i+n-k]=P[j];
            //P[j]=temp;
            for (j = 0; j < n; j++)
            {
                temp = H.coeff[l][j];
                H.coeff[l][j] = H.coeff[i][j];
                H.coeff[i][j] = temp;
            }
        }
        //   Matrix standardization
        gf invPiv = 1, aa;
        if (H.coeff[i][i + n - k] != 1)
        {
            aa = H.coeff[i][i + n - k];
            invPiv = gf_Inv_subfield(aa);
            H.coeff[i][i + n - k] = 1;

            for (j = 0; j < n; j++)
            {
                if (j == i + n - k)
                {
                    continue;
                }
                H.coeff[i][j] = gf_Mult_subfield(H.coeff[i][j], invPiv);
            }
        }

        //Here we do the elimination on column i + n-k
        gf piv_align;
        for (l = 0; l < k; l++)
        {
            if (l == i)
            {
                continue;
            }
            if (H.coeff[l][i + n - k])
            {
                piv_align = H.coeff[l][i + n - k];

                for (j = 0; j < n; j++)
                {
                    H.coeff[l][j] = H.coeff[l][j] ^ (gf_Mult_subfield(piv_align, H.coeff[i][j]));
                }
            }
        }
    }

    return 0;
}

//===============================================================================

void G_mat(binmat_t G, binmat_t H_syst)
{
    int i, j;
    binmat_t H;
    H = matrix_copy(H_syst);
    for (i = 0; i < code_length - code_dimension; i++)
    {
        for (j = 0; j < code_dimension; j++)
        {
            G.coeff[j][i] = H.coeff[i][j];
        }
    }
}

void affiche_vecteur(gf *v, int taille)
{
    printf("\n~~ Vector display ~~\n");
    int i = 0;
    for (i = 0; i < taille; i++)
    {
        printf("%d ", v[i]);
    }
    printf("\n");
}

gf *mult_matrix_vector_subfield(binmat_t A, gf *v)
{
    int i, k;
    gf *Res = (gf *)calloc(A.rown, sizeof(gf));
    for (i = 0; i < A.rown; i++)
    {
        for (k = 0; k < A.coln; k++)
        {
            Res[i] ^= gf_Mult_subfield(A.coeff[i][k], v[k]);
        }
    }
    return Res;
}

gf *mult_vector_matrix_subfield(gf *v, binmat_t A)
{
    int i, k;
    gf *Res = (gf *)calloc(A.coln, sizeof(gf));
    for (i = 0; i < A.coln; i++)
    {
        for (k = 0; k < A.rown; k++)
        {
            Res[i] ^= gf_Mult_subfield(A.coeff[k][i], v[k]);
        }
    }
    return Res;
}

gf *mult_vector_matrix(gf *v, binmat_t A)
{
    int i, k;
    gf *Res = (gf *)calloc(A.coln, sizeof(gf));
    for (i = 0; i < A.coln; i++)
    {
        for (k = 0; k < A.rown; k++)
        {
            Res[i] ^= gf_mult(A.coeff[k][i], v[k]);
        }
    }
    return Res;
}

gf *mult_vector_matrix_Sf(gf *v, binmat_t A)
{
    int i, k;
    gf *Res = (gf *)calloc(A.coln, sizeof(gf));
    for (i = 0; i < A.coln; i++)
    {
        for (k = 0; k < A.rown; k++)
        {
            Res[i] ^= gf_mult(A.coeff[k][i], v[k]);
        }
    }
    return Res;
}

gf *mult_matrix_vector(binmat_t A, gf *v)
{
    int i, k;
    gf *Res = (gf *)calloc(A.rown, sizeof(gf));
    for (i = 0; i < A.rown; i++)
    {
        Res[i] = 0;
        for (k = 0; k < A.coln; k++)
        {
            Res[i] ^= gf_mult(A.coeff[i][k], v[k]);
        }
    }
    return Res;
}
void vector_permutation(int *P, gf *c, int taille)
{
    int i = 0;
    gf *v = (gf *)calloc(code_length, sizeof(gf));
    for (i = 0; i < taille; i++)
    {
        v[P[i]] = c[i];
    }
    for (i = 0; i < taille; i++)
    {
        c[i] = v[i];
    }
}

int matrix_inverse(binmat_t A, binmat_t S)
{

    int i, j, l, test = 0;
    gf temp, temp1;
    binmat_t H = matrix_copy(A);
    int n = H.coln;
    int k = H.rown;
    for (i = 0; i < k; i++)
    {
        j = i;
        if (H.coeff[i][i] == 0)
        { //We're looking for a non-zero pivot
            test = 1;
            for (j = i + 1; j < n; j++)
            {
                if (H.coeff[j][i])
                {
                    //r++;
                    break;
                }
            }
        }
        if (j == n)
        {
            return 0;
        }
        if (test == 1)
        { // We switches line j and i
            test = 0;
            for (l = 0; l < k; l++)
            {
                temp = H.coeff[i][l];
                H.coeff[i][l] = H.coeff[j][l];
                H.coeff[j][l] = temp;
                // transformation sur S
                temp1 = S.coeff[i][l];
                S.coeff[i][l] = S.coeff[j][l];
                S.coeff[j][l] = temp1;
            }
        }
        // Matrix standardization
        gf invPiv = 1, aa;
        if (H.coeff[i][i] != 1)
        {
            aa = H.coeff[i][i];
            invPiv = gf_inv(aa);
            for (l = 0; l < n; l++)
            {
                H.coeff[i][l] = gf_mult(H.coeff[i][l], invPiv);
                // Transformation on S
                S.coeff[i][l] = gf_mult(S.coeff[i][l], invPiv);
            }
        }

        // Here we do the elimination on column i + n-k
        gf piv_align;
        for (l = 0; l < k; l++)
        {
            if (l == i)
            {
                continue;
            }
            if (H.coeff[l][i])
            {
                piv_align = H.coeff[l][i];

                for (j = 0; j < n; j++)
                {
                    H.coeff[l][j] = H.coeff[l][j] ^
                                    (gf_mult(piv_align, H.coeff[i][j]));
                    S.coeff[l][j] = S.coeff[l][j] ^
                                    (gf_mult(piv_align, S.coeff[i][j]));
                }
            }
        }
    }
    mat_free(H);

    return 1;
}

void secret_matrix(binmat_t H, gf *u, gf *v, gf *z)
{
    binmat_t H_fin;
    binmat_t T[pol_deg]; // T will contain all the block matrices H1 to H2
    gf *Z;
    Z = (gf *)calloc(code_length, sizeof(gf));
    int i, j, k, l = 0;
    for (i = 0; i < pol_deg; i++)
    {
        T[i] = matrix_init(order, code_length);
    }
    H_fin = matrix_init(pol_deg * (order), code_length);

    for (i = 0; i < order; i++)
    {
        for (j = 0; j < code_length; j++)
        {
            T[0].coeff[i][j] = gf_inv(u[i] ^ v[j]);
        }
    }
    for (k = 1; k < pol_deg; k++)
    {
        for (i = 0; i < order; i++)
        {
            for (j = 0; j < code_length; j++)
            {
                T[k].coeff[i][j] = gf_mult(T[0].coeff[i][j],
                                           T[k - 1].coeff[i][j]);
            }
        }
    }
    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    ///// Zi fillfull the following restriction: Zis+j=Zis, for i=0...n0-1, j=0...s-1
    //// That means that Z0=Z1=...=Z(s-1); Zs=Z(s+1)=...=Z(2s-1);  ... Z(n-s-1)=Z(n-s)=...=Z(n-1)
    //// At the end, we just have to choose n0 distincts elements.
    ///////////////////////////////////////////////////////////////////////////////////////////////////////

    for (i = 0; i < n0_val; i++)
    {
        for (j = 0; j < order; j++)
        {
            Z[i * (order) + j] = z[i];
        }
    }
    //***************************************************************************************************
    //        Construct the matrix H_fin which consists of the concatenation of th matrices hat(H)_i
    //
    /////////////////////////////////////////////////////////////////////////////////////////////////////

    for (k = 0; k < pol_deg; k++)
    {
        l = (order)*k;
        for (i = 0; i < order; i++)
        {
            for (j = 0; j < code_length; j++)
            {
                H_fin.coeff[l + i][j] = T[k].coeff[i][j];
            }
        }
    }
    //cfile_matrix_F12("secret_matrix.txt", H_fin.rown, H_fin.coln, H_fin);
    //***************************************************************************************************
    //           Construction of the matrix H=H_fin.D  where D=diag(Zi)
    //
    /////////////////////////////////////////////////////////////////////////////////////////////////////
    for (i = 0; i < pol_deg * (order); i++)
    {
        for (j = 0; j < code_length; j++)
        {
            H.coeff[i][j] = gf_mult(H_fin.coeff[i][j], Z[j]);
        }
    }
    mat_free(H_fin);
    free(Z);
    for (i = 0; i < pol_deg; i++)
    {
        mat_free(T[i]);
    }
}

void quasi_dyadic_bloc_mat(int s, binmat_t M, gf *sig, int ind_col, int ind_rown)
{
    int i, j;
    for (i = ind_rown; i < s + ind_rown; i++)
    {
        for (j = ind_col; j < s + ind_col; j++)
        {
            M.coeff[i][j] = sig[(i ^ j) % s];
        }
    }
}
