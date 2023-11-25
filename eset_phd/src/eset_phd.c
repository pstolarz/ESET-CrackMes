#ifdef _WIN32
#define _CRT_RAND_S
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "or_tab.h"

#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif
#ifndef NULL
#define NULL    0
#endif

typedef int bool_t;

/*
    64-bit lock value's bits layout:

                    6      5 5      4 4      4 3      3 3      2 2      1 1
                    3      6 5      8 7      0 9      2 1      4 3      6 5      8 7      0
      checked bits: 10011011 00011010 11011110 11011111 10000100 01111101 00110100 10000001
      button bits:  00001100 00110000 10000010 00001000 01100001 10000100 00010000 01000011
      button name:      2D     4F     6     8      A     1C    3 E    5      7      9    0B

    where:
      checked bits: bits taken into account during bit parity checking
      button bits: bits associated with a GUI button
 */

#ifdef DEBUG
/* print binary representation of 64-bit integer 'n' */
static void print_bin_int64(uint64_t n)
{
    char buf[8*sizeof(n)+1];
    size_t i = 8*sizeof(n);

    buf[i--]=0;
    do {
        buf[i]=(n&1?'1':'0');
        n = n>>1;
    } while(i--);

    printf("%s", buf);
}
#endif

/* init prf seed */
static init_prf_seed(unsigned int seed)
{
    srand(seed);
}

/* pseudo randmon function */
static unsigned int prf()
{
#ifdef _WIN32
    unsigned int r;
    return (rand_s(&r)==0 ? r : rand());
#else
    return rand();
#endif
}

/* get button name corresponting to bit 'b' */
static char get_btn_name(unsigned int b)
{
    /* button bits numbers in the lock value */
    static const unsigned int btn_bits[] =
        {1,30,59,24,53,18,47,12,41,6,35,0,29,58,23,52};

    /* ... and their corresponding names */
    static const char *btn_names = "0123456789ABCDEF";

    const size_t n_btns = sizeof(btn_bits)/sizeof(btn_bits[0]);

    size_t i;

    for (i=0; i<n_btns; i++) {
        if (btn_bits[i]==b) return btn_names[i];
    }

    printf("get_btn_name(): %d bit is not assigned to any button\n", b);
    assert(0);
    return 0;
}

/* get parity (0 or 1) on checked bits of an integer 'n' */
static unsigned int get_parity_chk_bits(uint64_t n)
{
    /* checked parity lock value's bit set (AND mask) */
    const uint64_t chck_bits = 0x9b1adedf847d3481LL;

    size_t i;
    unsigned int p=0;

    n = n&chck_bits;
    for (i=8*sizeof(n); i; i--, n=n>>1) if (n&1) p++;
    return p&1;
}

/*
    Conformace is computed as:
      LOOP i=0..sz {
        conformance at bit i = checked_parity(lv) XOR MSBit(r)
        lv = SHLD(lv, r, 1);
        r = r<<1;
      }

    In other words conformance value at bit i-th specifies if the checked
    bits parity computed on i-times left shifted 'lv' with least significant
    bits filled by 'r' is conformant with MSBit of 'r' (0) or not
    conformant (1). Conformant means: the MSBit of 'r' may be used as
    a parity bit at LSBit of 'lv'.
 */
static uint64_t get_conformance(uint64_t lv, uint64_t r, unsigned int sz)
{
    unsigned int i;
    uint64_t cnfr=0;

    for (i=0; i<sz; i++) {
        unsigned int r_msbit=((int64_t)r<0 ? 1 : 0);
        unsigned int par = get_parity_chk_bits(lv);

        if (par^r_msbit) cnfr |= (uint64_t)1<<i;

        lv = (lv<<1)|r_msbit;
        r = r<<1;
    }
    return cnfr;
}

/*
    Get button names (written into 'out') which pressed in the provided
    order will lead into 'res' value. The func uses partially a BF method
    wich may try 'n_tries' before unsuccessfull result; 0: infinite loop.
 */
static bool_t reslv_lock_val(uint64_t res, char out[], unsigned int n_tries)
{
    /* subsets of checked and not checked parity button bits (asc order) */
    static const unsigned int chck_btn_bits[] = {0,12,18,35,41,47,52,59};
    static const unsigned int nchck_btn_bits[] = {1,6,23,24,29,30,53,58};

    const size_t n_chck_btns = sizeof(chck_btn_bits)/sizeof(chck_btn_bits[0]);
    const size_t n_nchck_btns = sizeof(nchck_btn_bits)/sizeof(nchck_btn_bits[0]);

    /* 58 and 59 are the highest button bits from not-checked
       and checked sets; this value is lowest of them and lowered
       to an even number */
    const unsigned int up_blim = 58;

    /* number of most significant bits starting from 'up_blim' (6) */
    const unsigned int n_bound_bts = 64-up_blim;

    /* 'C' and '1' buttons have adjacent bits (29,30 respectively)
       from unchecked set; therefore if a seqence 'C','1' is pressed
       it shifts left the lock value by 2, not modifing its 62 MSBits
       with 2 LSBits filled as the 29,30 bits were not modified during
       the shifting process.

       Similar (but not identical) observation goes to 'D' and '2'
       buttons (58,59) bits.
     */
    static const char *shift_seqs[] = {"C1", "D2"};
    const size_t n_seqs = sizeof(shift_seqs)/sizeof(shift_seqs[0]);

    const uint64_t init_lock_val = 0x48aeefd486289cfbLL;

    uint64_t lv, r;
    size_t i, chck_down_ilim, nchck_down_ilim;
    unsigned int bit, n_try;
    bool_t ret=FALSE;

    n_try=0;
    init_prf_seed(time(NULL));

next_try:
    n_try++;

    r = res;
    lv = init_lock_val;
    chck_down_ilim = nchck_down_ilim = 0;

#ifdef DEBUG
    printf("00: ");
    print_bin_int64(lv);
    printf("; %016I64X\n", lv);
#endif

    /*
        STEP 1: fill 'up_blim' bits with the 'res' bits using the parity
        of the checked bits (LSBit) and set accordingly by modification of
        bits from checked and unchecked sets. The modification depends on
        a conformance calculated in each loop iter.
     */
    for (bit=0; bit<up_blim;)
    {
        unsigned int r_msbit, chck_btn_bit, nchck_btn_bit, btn_bit;

        /* the checked and unchecked bits are picked up randomly for each iter
           and are confined by already shifted LSBits (taken from 'res') */
        chck_btn_bit =
            chck_btn_bits[chck_down_ilim + prf()%(n_chck_btns-chck_down_ilim)];

        nchck_btn_bit =
            nchck_btn_bits[nchck_down_ilim + prf()%(n_nchck_btns-nchck_down_ilim)];

        /* a conformance dicatates which bit to use (from checked or unchecked set) */
        btn_bit = (get_conformance(lv, r, 1) ? chck_btn_bit : nchck_btn_bit);
        out[bit] = get_btn_name(btn_bit);

        /* modify chosen bit, fill parity and shift left the lock value */
        r_msbit = ((int64_t)r<0 ? 1 : 0);
        lv ^= (uint64_t)1<<btn_bit;
        assert(r_msbit==get_parity_chk_bits(lv));
        lv = (lv<<1)|r_msbit;

#ifdef DEBUG
        printf("%02X: ", bit+1);
        print_bin_int64(lv);
        printf("; %016I64X; %c(%d)\n", lv, out[bit], btn_bit);
#endif

        /* prepare for the next iter */
        bit++;

        if (bit > chck_btn_bits[chck_down_ilim]) chck_down_ilim++;
        if (bit > nchck_btn_bits[nchck_down_ilim]) nchck_down_ilim++;

        r = r<<1;
    }

#ifdef DEBUG
        printf("\n");
#endif

    /*
       STEP 2: The remaining 'n_bound_bts' must be conformant; if not try the
       next iter.
     */
    if (get_conformance(lv, r, n_bound_bts)) {
        if (!n_tries || n_try<n_tries) goto next_try;
        else goto finish;
    }

    /* prepare button seqeunce to shift left unmodified 58 MSBits of the lock value
       by 'n_bound_bts' (6) bits; the right-most 'n_bound_bts' bits conformant with
       the desired result */
    for (i=0; i<n_bound_bts;) {
        size_t seq_i = prf()%n_seqs;
        size_t seq_len = strlen(shift_seqs[seq_i]);

        strncpy(&out[up_blim+i], shift_seqs[seq_i], seq_len);
        i += seq_len;
    }

    ret = TRUE;

finish:
    return ret;
}

/*
   Get "or parity" value for number 'n'. The "or parity" is defined as:
     LOOP i=0..63 {
       cnt=0;
       LOOP j=0..7 {
         if (n & or_tab[i][j]) cnt++;
       }
       ret_val at bit i = parity of cnt
     }
 */
static uint64_t get_or_parity(uint64_t n)
{
    size_t i, j;
    uint64_t or_par=0;

    for (i=0; i<n_or_tab_rows; i++) {
        unsigned int cnt=0;
        for (j=0; j<n_or_tab_cols; j++) {
            if ((n & or_tab[i][j])==or_tab[i][j]) cnt++;
        }
        if (cnt&1) or_par |= (uint64_t)1<<i;
    }
    return or_par;
}

/*
   Get resolving lock value. The proc reverses a specific "or parity"
   value ('reslv_or_par') using the following observations:

   It occurs the or_tab[] and 'reslv_or_par' are specifically crafted:
     1. or_tab's column 0 of each row consist of 1<<i; i=0..63 values
        and all of them (except 1<<i; i=0..7) give "or parity" unique
        (1 only for this bit/row the 1<<i value occurs).
     2. Moreover, or'ing the column 0 values of the rows corresponding to
        the binary representation of 'reslv_or_par' (excluding only these
        rows, which column 0 values are: 1<<i; i=0..7) and calculating
        the "or parity" on it, the resulted value is unique (1's only for
        these bits/rows the corresponding 'reslv_or_par' bits occur).
     3. The final result may be brute-forced by 256 times loop (all or's
        calculated on 1<<i; i=0..7 values). It occurs, it's the only
        solution here: 0xe7fd097289cbb591, and this value constitues
        a correct key for name-key verification library decryption.

        NOTE: There is an open question if there exist more reverse
        solutions for 'reslv_or_par'.
 */
static uint64_t get_resolving_lock_val()
{
    /* revesed "or parity" value */
    const uint64_t reslv_or_par = 0xa3fe45adf1ec2ab4LL;

    /* binary representation of 'reslv_or_par' expressed in corresponding
       column 0 of rows of or_tab[], except these bits which are not
       unambiguous for the resolution (2,4,9,23) since they values are:
       0x10, 0x80, 0x02, 0x08 */
    uint64_t res =
        /* 2,4 bits not set */
        or_tab[5][0]|
        or_tab[7][0]|
        /* 9 bit not set */
        or_tab[11][0]|
        or_tab[13][0]|
        or_tab[18][0]|
        or_tab[19][0]|
        or_tab[21][0]|
        or_tab[22][0]|
        /* 23 bit not set */
        or_tab[24][0]|
        or_tab[28][0]|
        or_tab[29][0]|
        or_tab[30][0]|
        or_tab[31][0]|
        or_tab[32][0]|
        or_tab[34][0]|
        or_tab[35][0]|
        or_tab[37][0]|
        or_tab[39][0]|
        or_tab[40][0]|
        or_tab[42][0]|
        or_tab[46][0]|
        or_tab[49][0]|
        or_tab[50][0]|
        or_tab[51][0]|
        or_tab[52][0]|
        or_tab[53][0]|
        or_tab[54][0]|
        or_tab[55][0]|
        or_tab[56][0]|
        or_tab[57][0]|
        or_tab[61][0]|
        or_tab[63][0];

    /* brute force to the final result */
    uint64_t i;
    for (i=0; i<255; i++) {
        if (reslv_or_par==get_or_parity(res|i)) { res|=i; break; }
    }

    assert(get_or_parity(res)==reslv_or_par);
    return res;
}

/*
 */
int main(int argc, char **args)
{
    char out[65];
    uint64_t reslv_lv = get_resolving_lock_val();

    out[64]=0;
    if (reslv_lock_val(reslv_lv, out, 0))
        printf("%s\n", out);

    return 0;
}
