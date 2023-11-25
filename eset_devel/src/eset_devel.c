/*
    ESET Engine Developer's challenge resolving library & app.
    (c) 2014 by Piotr Stolarz [pstolarz@gmail.com]
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define UNICODE
#include <windows.h>

#ifdef DLL_BUILD
#include "stage5.h"
#endif

#define MIN(x,y) ((x)<=(y)?(x):(y))

#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif
#ifndef NULL
#define NULL    0
#endif

/* max. N input for reversed CRC32 */
#define MAX_N  1000

typedef int bool_t;

static const char *fname_def = "eset_devel.def";
static const char *fname_s5_inc = "stage5.h";

/* 32-bit RSA stage 3 spec. */
static const struct
{
    uint32_t p;
    uint32_t q;     /* modulus = p*q */
    uint32_t e;     /* public exponent */
    uint32_t d;     /* reverse exponent */
} s3_rsa =
{
    0xB40B,     /* p */
    0x1428B,    /* q */
    0x10001,    /* e */
    /*
       n (modulus) = p*q = 3805779961 = 0xE2D797F9
       phi(n) = (p-1)(q-1) = 3805651300, where phi(n) is the Euler's totient function
       The extended euclidean algo gives: =(-19239)*phi(n)+(1117184573)*e = gcd(phi(n),e) = 1
       d = 1117184573 = 0x4296E23D
     */
    0x4296E23D  /* d */
};

static const uint32_t crc_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

/*
    CRC32 algo is defined as follows:
      t[0]=0xffffffff
      t[n]=(t[n-1]>>8)^crc_tab[y[n]], where y[n]=s[n-1]^in[n-1]; s[n]=t[n]&0xff; n=1..N
      computed crc32: ~t[N]
 */
static uint32_t crc32(const uint8_t in[], size_t sz_in)
{
    size_t n;
    uint32_t crc = 0xffffffff;

    for (n=1; n<=sz_in; n++) crc = (crc>>8)^crc_tab[(crc&0xff)^in[n-1]];
    return ~crc;
}

/*
    Search 'crc_tab' for entry with a specific HSB byte
 */
static uint8_t crc_tab_search(uint8_t hsb)
{
    size_t i, sz_crc_tab = sizeof(crc_tab)/sizeof(crc_tab[0]);

    for (i=0; i<sz_crc_tab; i++) {
        if (hsb==(uint8_t)(crc_tab[i]>>24)) break;
    }
    if (i>=sz_crc_tab) {
        printf("CRC32 fatal error!\n");
        assert(0);
    }
    return (uint8_t)i;
}

/*
   Return TRUE in case the input byte corresponding to s[n] is within
   a specific alphabet given in the table 'in_alpha'.
 */
static bool_t check_s_n(
    uint8_t s_n, uint8_t y_n_1, const uint8_t *p_in_alpha, size_t sz_in_alpha)
{
    size_t i;
    bool_t found = FALSE;
    uint8_t in_n = y_n_1^s_n;

    for (i=0; i<sz_in_alpha; i++) {
        if (found=(in_n==p_in_alpha[i])) break;
    }
    return found;
}

/*
   Look for s[n] starting from value 's_n_start' with given y[n+1]
   to correspond with an input byte within a specific alphabet given in
   the table 'in_alpha'. Return (uint32_t)-1 if not found.
 */
static uint32_t look_s_n(
    uint8_t s_n_start, uint8_t y_n_1, const uint8_t *p_in_alpha, size_t sz_in_alpha)
{
    uint32_t s_n = s_n_start;

    for (; s_n<=0xff; s_n++) {
        if (check_s_n((uint8_t)s_n, y_n_1, p_in_alpha, sz_in_alpha)) break;
    }
    return (s_n>0xff ? (uint32_t)-1 : s_n);
}

/*
    Update 't' table for a new iteration calculation starting from 'n_start'.
    Return an index from which the calculation shall start or -1 if the
    table can't be updated for the passed 'n_start'.
 */
static int update_t_for_n_start(int n_start, int N, uint32_t t[])
{
    int n, i;
    for (n=n_start; n<=N-1; n++)
    {
        uint8_t s_n = t[n]&0xff;
        if (s_n<0xff)
        {
            t[n] = s_n+1;

#ifdef DEBUG
            printf("update t (%d->%d):\n", n_start, n);
#endif
            n_start = n;
            for (i=n-1; i>=1; i--) t[i]=0;

#ifdef DEBUG
            for (i=1; i<=N; i++) printf("  t[%d]:%08X\n", i, t[i]);
#endif
            break;
        }
    }
    if (n>=N) n_start = -1;

    return n_start;
}

/*
    Reverse CRC32 checksum 'crc' into input (solutions written under 'in') for
    a given input length 'N' and input alphabet 'in_alpha'. In case CRC32 can't
    be computed the func returns FALSE.
 */
static unsigned int reverse_crc32(uint32_t crc, int N,
    uint8_t in[], size_t in_sz, const uint8_t *p_in_alpha, size_t sz_in_alpha)
{
#define update_t_for_n_start_from_beg()     \
    n_start = update_t_for_n_start(4, N, t);\
    if (n_start!=-1) {                      \
        goto start_t_calc;                  \
    } else {                                \
        goto finish;                        \
    }

    unsigned int n_in=0;

    if (in_sz<N) goto finish;

    if (N>=4 && N<=MAX_N)
    {
        /*
            Reverse algo for N>=4:
              find crc_tab[y[N]] and y[N] as an entry with HSB of t[N]

              for n=N-1..1
              {
                // t[n] is specified for 3 higher bytes with LSB shifted out right in CRC process
                t[n]>>8=t[n+1]^crc_tab[y[n+1]]

                // s[n] may be chosen arbitrarily, e.g. to meet a specific criteria of input
                // alphabet. In this case i[n]=y[n+1]^s[n] and
                // a) for s[1]..s[3] can't be adjusted, since they (as LSB of t[1]..t[4]) are
                //    recalculated in the next step using t[0] and y[1]..y[3], where the y
                //    values depends on t[4] only
                // b) for s[n] n>=4 may be adjusted in this loop
                t[n]=(t[n]<<8)|s[n]

                t[n] has the same highest bytes as crc_tab[y[n]], so find crc_tab[y[n]] and y[n]
              }

              // adjust t[1]..t[3] basing on t[0]
              // NOTE: t[n] for n>=4 are the same, therefore t[N] always resolves the CRC32 (in case
              // no additional constraints on the input alphabet is given)
              for n=1..3 {
                t[n]=(t[n-1]>>8)^crc_tab[y[n]]
              }

              // input recognition
              for n=0..N-1 {
                in[n]=y[n+1]^s[n]
              }
        */
        int n, n_start;
        uint32_t t[MAX_N+1];
        uint8_t y[MAX_N+1];
        size_t in_i=0;

        memset(t, 0, sizeof(t));

        /* given in advance */
        t[0] = 0xffffffff;
        t[N] = ~crc;

        y[N] = crc_tab_search((uint8_t)(t[N]>>24));
        n_start = N-1;

start_t_calc:
        for (n=n_start; n>=1; n--)
        {
            uint32_t s_n = t[n]&0xff;

            if (p_in_alpha && n>=4)
            {
                /* find matching s[n] for the given alphabet */
                s_n = look_s_n((uint8_t)s_n, y[n+1], p_in_alpha, sz_in_alpha);
                if (s_n==(uint32_t)-1)
                {
                    n_start = update_t_for_n_start(n+1, N, t);
                    if (n_start!=-1) {
                        goto start_t_calc;
                    } else {
                        goto finish;
                    }
                }
            }

            t[n] = ((t[n+1]^crc_tab[y[n+1]])<<8) | s_n;
            y[n] = crc_tab_search((uint8_t)(t[n]>>24));
        }

        /* adjust t[1]..t[3] basing on the boundary condition of t[0] */
        for (n=1; n<=3; n++)
            t[n] = (t[n-1]>>8)^(crc_tab[y[n]]);

#ifdef DEBUG
        printf("calc t:\n");
        for (n=1; n<=N; n++) {
            printf("  y[%d]:%02X, crc[y[%d]]:%08X, t[%d]:%08X\n", n, y[n], n, crc_tab[y[n]], n, t[n]);
        }
#endif
        if (p_in_alpha) {
            /* check correctness of s[0]..s[3] with a given alphabet */
            for (n=0; n<=3; n++) {
                if (!check_s_n(t[n]&0xff, y[n+1], p_in_alpha, sz_in_alpha)) {
                    update_t_for_n_start_from_beg();
                }
            }
        }

        n_in++;

        if (in_sz==(size_t)-1)
        {
            /* special case: write solution to the output stream */
            uint8_t in[MAX_N+1];

            for (n=0; n<N; n++) {
                in[n] = (uint8_t)(y[n+1]^(t[n]&0xff));
            }
            in[N]=0;
            printf("%s\n", (char*)in);
        } else {
            /* compute & write the resolved input */
            for (n=0; n<N; n++, in_i++) {
                in[in_i] = (uint8_t)(y[n+1]^(t[n]&0xff));
            }

            in_sz-=N;
            if (in_sz<N) goto finish;
        }

        update_t_for_n_start_from_beg();
    } else
    if (N>=1 && N<=3)
    {
        /*
           For N<=3 y[1]..y[N] are unique and can be calculated from a given crc (~t[N]).
           Therefore, having t[0], all t[n] can be calculated unambiguously.
           In this case, there is only a need to check if calculated t[N] matches a given
           crc, and if so if the resulting input matches a given alphabet.
         */
        int n;
        uint32_t t[5];
        uint8_t y[5], in_print[5];

        if (in_sz==-1) in=in_print;

        /* given in advance */
        t[0] = 0xffffffff;
        t[N] = ~crc;

        /* calculate y[] */
        y[N] = crc_tab_search((uint8_t)(t[N]>>24));
        for (n=N-1; n>=1; n--) {
            t[n] = (t[n+1]^crc_tab[y[n+1]])<<8;
            y[n] = crc_tab_search((uint8_t)(t[n]>>24));
        }

        /* calculate t[] */
        for (n=1; n<=N; n++)
            t[n] = (t[n-1]>>8)^(crc_tab[y[n]]);

#ifdef DEBUG
        printf("calc t:\n");
        for (n=1; n<=N; n++) {
            printf("  y[%d]:%02X, crc[y[%d]]:%08X, t[%d]:%08X\n", n, y[n], n, crc_tab[y[n]], n, t[n]);
        }
#endif
        /* check if the solution exists */
        if (t[N]!=~crc) goto finish;

        /* calculate in[] and check alphabet */
        for (n=0; n<N; n++)
        {
            uint8_t s_n = t[n]&0xff;
            in[n]=y[n+1]^s_n;

            if (p_in_alpha) {
                if (!check_s_n(s_n, y[n+1], p_in_alpha, sz_in_alpha)) goto finish;
            }
        }

        if (in_sz==-1) {
            in[N]=0;
            printf("%s\n", (char*)in);
        }

        n_in++;
    }

finish:
    return n_in;
}

/* Presentation routine */
static void print_crc_results(uint32_t crc,
    const uint8_t *p_in_alpha, size_t sz_in_alpha,
    const char *p_hdr_info, const char *p_alpha_name)
{
    int N;
    uint8_t in[0x100];

    printf("%s\n", p_hdr_info);
    printf("  CRC32 [%08X] Searching for solutions...\n", crc);
    printf("  Input alphabet: %s\n", p_alpha_name);

    for (N=1;; N++)
    {
        unsigned int n_res;

        printf("    N:%d -> ", N);
        if (n_res =
            reverse_crc32(crc, N, in, sizeof(in), p_in_alpha, sz_in_alpha))
        {
            size_t i,j;

            if (crc!=crc32(in, N)) {
                printf("CRC32 mismatch!\n");
                assert(0);
            }

            printf("\n");
            for (i=0, j=N; i<n_res; i++, j+=N) {
                uint8_t tmp=in[j];

                in[j]=0;
                printf("      %s\n", &in[j-N]);
                in[j]=tmp;
            }

            break;
        } else {
            printf("Can't be resolved for this alphabet\n");
        }
    }
}

/*
    32-bit modular exponentiation of base 'b' by exponent 'e' modulo 'm'.
    Returns 0 in case of error.
 */
static uint32_t mod_exp32(uint32_t b, uint32_t e, uint32_t m)
{
    uint64_t res=0;

    if (b && m) {
        res=1;
        while (e) {
            if (e&1) res = (uint32_t)((res*(uint64_t)b)%m);
            e = e>>1;
            b = (uint32_t)((b*(uint64_t)b)%m);
        }
    }
    return (uint32_t)res;
}

/*
    'validity_days' specifies a period of days for the 5th stage library
    validity time. Return TRUE if success, FALSE otherwise (access file error).
 */
static bool_t generate_stage5_names(int validity_days)
{
    static const WORD month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    SYSTEMTIME time;
    WORD year, month, day;
    FILE *fh_def, *fh_inc;
    bool_t ret = FALSE;

    GetLocalTime(&time);
    year = time.wYear;
    month = time.wMonth;
    day = time.wDay;

    fh_def = fopen(fname_def, "w");
    fh_inc = fopen(fname_s5_inc, "w");

    fprintf(fh_def, "EXPORTS\n  Z1IBF\n  OOkE2\n  W9Grz5\n  pNtwA\n");

    if (fh_def && fh_inc)
    {
        int day_i;
        /*
        // detect platform endianess to patch a bug in the stage 5 checking library.
        uint32_t x = 0x01020304;
        WORD hour_min_limit = ((*(uint8_t*)&x)==0x04 ? 24 : 60);
        */
        WORD hour_min_limit = 24;

        for (day_i=0; day_i<=validity_days; day_i++)
        {
            WORD hour_min;
            WORD cur_month_days = month_days[(size_t)(month-1)];

            if (!(year%4) && month==2) cur_month_days++; /* Feb in an odd year */

            if (day>cur_month_days) {
                day=1;
                if (++month > 12) {
                    month=1;
                    year++;
                }
            }

            /* assume BE platforms only */
            for (hour_min=0; hour_min<hour_min_limit; hour_min++) {
                char proc_name[32];

                sprintf(proc_name, "%04X%04X%04X%04X",
                    (~year)&0xffff, (~month)&0xffff, (~day)&0xffff, (~hour_min)&0xffff);
                fprintf(fh_inc, "uint32_t __stdcall %s() { return 0x35371337; }\n", proc_name);
                fprintf(fh_def, "  %s\n", proc_name);
            }

            /* prepare for the next loop iter */
            day++;
        }

        if (fh_def) fclose(fh_def);
        if (fh_inc) fclose(fh_inc);

        ret = TRUE;
    } else {
        printf("Error: generate_stage5_names() can't access the output files\n");
    }

    return ret;
}

/*
    Stage 2 callback
    Must return buffer, where in[i]<=in[j] if and only if i<=j
 */
void __stdcall Z1IBF(uint16_t buf[], uint32_t sz_buf)
{
    uint32_t i;
    for (i=0; i<sz_buf; i++) buf[i]=(uint16_t)i;
}

/*
    Stage 3 callback
    32-bit reverse RSA (with a private exponent d) over a user name
    (as returned by GetUserName()).
 */
void __stdcall OOkE2(uint8_t buf[], uint32_t sz_buf)
{
    const uint32_t s3_rsa_modulus = s3_rsa.p*s3_rsa.q;

    size_t i, j;
    TCHAR user_name[0x100];
    DWORD sz_user_name = sizeof(user_name)/sizeof(user_name[0]);

    if (GetUserName(user_name, &sz_user_name)) {
        for (i=0, j=0; user_name[i] && j<sz_buf; i++, j+=8)
        {
            /* to avoid base=1 modify HSBs by the loop index */
            uint32_t base = (uint32_t)(((i+1)<<16)|(user_name[i]&0xffff));
            uint32_t powm = mod_exp32(base, s3_rsa.d, s3_rsa_modulus);
            sprintf((char*)&buf[j], "%08X", powm);
        }
    }
}

/*
    Stage 4 callback
    Sets polynomial coefficients (Ni, Ni>=0) of degree 5 for given roots
    Xi (Xi>=0), i=0..4. The coefficients are results of the polynomial expansion:

    (x-X0)(x-X1)(x-X2)(x-X4)(x-X5) =  x^5 - N0*x^4 + N1*x^3 - N2*x^2 + N3*x - N4

    Poly roots are a calculation result of passed 'vol_sn' and a user name (as
    returned by GetUserName()). Coefficients are converted to 40-bit hex ints,
    concatenated into one string and passed as a result of the function by buf[].
 */
void __stdcall W9Grz5(uint8_t buf[], uint32_t sz_buf, uint32_t vol_sn)
{
    TCHAR user_name[0x100];
    DWORD sz_user_name = sizeof(user_name)/sizeof(user_name[0]);

    if (GetUserName(user_name, &sz_user_name))
    {
        size_t i, j;
        uint64_t roots;
        uint64_t X[5], N[5];

        /* convert user_name to ascii chars */
        for (i=0; i<sz_user_name; i++)
            ((uint8_t*)&user_name[0])[i] = (uint8_t)user_name[i];

        roots = (uint64_t)crc32((uint8_t*)user_name, sz_user_name)*vol_sn;

        /* create the root table X[] containing 5 LSBes of the previous multiplication */
        for (i=0; i<sizeof(X)/sizeof(X[0]); i++) {
            X[i] = roots&0xff;
            roots = roots>>8;
        }

        /* calculate the poly coefficients */
        N[0] = X[0]+X[1]+X[2]+X[3]+X[4];
        N[1] = X[0]*(X[1]+X[2]+X[3]+X[4]) + X[1]*(X[2]+X[3]+X[4]) + X[2]*(X[3]+X[4]) + X[3]*X[4];
        N[2] = X[0]*(X[1]*(X[2]+X[3]+X[4]) + X[2]*(X[3]+X[4]) + X[3]*X[4]) + X[1]*(X[2]*(X[3]+X[4]) + X[3]*X[4]) + X[2]*X[3]*X[4];
        N[3] = X[0]*(X[1]*(X[2]*(X[3]+X[4]) + X[3]*X[4]) + X[2]*X[3]*X[4]) + X[1]*X[2]*X[3]*X[4];
        N[4] = X[0]*X[1]*X[2]*X[3]*X[4];

        /* .. and convert them to 40-bit hex ints */
        for (i=0, j=0; i<sizeof(N)/sizeof(N[0]) && j<sz_buf; i++, j+=10) {
            sprintf((char*)&buf[j], "%010I64X", N[i]);
        }
    }
}

static DWORD WINAPI msg_box_thread(LPVOID lpParameter)
{
    MessageBox(
        FindWindow(WC_DIALOG, NULL),
        L"Message Box", L"Message Box", MB_OK);
    return 0;
}

/*
    The "flames callback"
 */
DWORD __stdcall pNtwA()
{
    static bool_t msg_box=FALSE;

    if (!msg_box) {
        CreateThread(NULL, 0, msg_box_thread, NULL, 0, NULL);
        msg_box = TRUE;
    }
    return GetTickCount();
}

#ifndef DLL_BUILD
/*
    app's main()
 */
int main(int argc, char **args)
{
    /* CRC32 alphabets */
    const uint8_t A_Z_0_9[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const uint8_t a_z_A_Z_0_9_[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

    const uint32_t n = s3_rsa.p * s3_rsa.q;
    const uint32_t phi_n = (s3_rsa.p-1)*(s3_rsa.q-1);

    const int def_stage5_validity_days = 7;

    int i;
    bool_t prnt_stages=FALSE;
    int stage5_validity_days = def_stage5_validity_days;

    for (i=1; i<argc; i++)
    {
        if (args[i][0]=='-' || args[i][0]=='/')
        {
            if (args[i][1]=='p') prnt_stages=TRUE;
            else
            if (args[i][1]>='0' && args[i][1]<='9') {
                stage5_validity_days = (int)strtoul(&args[i][1], NULL, 10);
                if (stage5_validity_days<=0 || stage5_validity_days>2700) {
                    printf("Incorrect number of days provided\n");
                    goto finish;
                }
            } else
            if (args[i][1]=='h' || args[i][1]=='?') {
                printf("Usage:\n"
                       "  %s [-p] [-{days}]\n"
                       "  p: Show stages solutions details\n"
                       "  days: number of validity days for the library being generated to pass the 5th stage; default: %d\n",
                       args[0], def_stage5_validity_days);
                goto finish;
            }
        }
    }

    if (prnt_stages)
    {
        print_crc_results(0x35370000,
            A_Z_0_9, sizeof(A_Z_0_9)-1,
            "STAGE 1: Resolving library name",
            "A-Z,0-9");

        print_crc_results(0xDEADC0DE,
            a_z_A_Z_0_9_, sizeof(a_z_A_Z_0_9_)-1,
            "\nSTAGE 2: Resolving export name",
            "a-z,A-Z,0-9,_");

        print_crc_results(0xDEADBEEF,
            a_z_A_Z_0_9_, sizeof(a_z_A_Z_0_9_)-1,
            "\nSTAGE 3: Resolving export name",
            "a-z,A-Z,0-9,_");

        printf("\n  32-bit RSA spec. details:\n");
        printf("    p=%u, q=%u:\n", s3_rsa.p, s3_rsa.q);
        printf("    modulus [n]: p*q=%u (0x%08X)\n", n, n);
        printf("    pub-exp [e]: %u (0x%08X)\n", s3_rsa.e, s3_rsa.e);
        printf("    priv-exp [d]: %u (0x%08X)\n\n", s3_rsa.d, s3_rsa.d);
        printf("    phi(n)=(p-1)(q-1)=%u\n", phi_n);
        printf("    d*e mod phi(n)=%u\n", (uint32_t)((s3_rsa.e*(uint64_t)s3_rsa.d)%phi_n));

        print_crc_results(0xDEADCAFE,
            a_z_A_Z_0_9_, sizeof(a_z_A_Z_0_9_)-1,
            "\nSTAGE 4: Resolving export name",
            "a-z,A-Z,0-9,_");

        print_crc_results(0x76666667,
            a_z_A_Z_0_9_, sizeof(a_z_A_Z_0_9_)-1,
            "\nFLAMES CALLBACK: Resolving export name",
            "a-z,A-Z,0-9,_");
    }

    if (generate_stage5_names(stage5_validity_days)) {
        printf("\nSTAGE5:\n  Files %s and %s have been generated for %d days ahead.\n",
            fname_def, fname_s5_inc, stage5_validity_days);
    }

finish:
    return 0;
}
#endif /* DLL_BUILD */
