/*
 * Copyright (c) 2014-2016 John Doering <ghostlander@phoenixcoin.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/* NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20
 * Optimised for the AMD GCN, VLIW4 and VLIW5 architectures
 * v6, 16-Jan-2016 */


/* Vectorised constants */
__constant uint4 V7  = (uint4)( 7,  7,  7,  7);
__constant uint4 V8  = (uint4)( 8,  8,  8,  8);
__constant uint4 V9  = (uint4)( 9,  9,  9,  9);
__constant uint4 V12 = (uint4)(12, 12, 12, 12);
__constant uint4 V13 = (uint4)(13, 13, 13, 13);
__constant uint4 V16 = (uint4)(16, 16, 16, 16);
__constant uint4 V18 = (uint4)(18, 18, 18, 18);
__constant uint4 V20 = (uint4)(20, 20, 20, 20);
__constant uint4 V24 = (uint4)(24, 24, 24, 24);
__constant uint4 V25 = (uint4)(25, 25, 25, 25);


/* Vector code preferred for VLIW5 and VLIW4 */
#if (__Cypress__) || (__Barts__) || (__Juniper__) || \
(__Turks__) || (__Caicos__) || (__Redwood__) || (__Cedar__) || \
(__BeaverCreek__) || (__WinterPark__) || (__Loveland__) || \
(__Cayman__) || (__Devastator__) || (__Scrapper__)
#define SALSA_SCALAR 0
#define CHACHA_SCALAR 0
#define BLAKE2S_SCALAR 0
#define FASTKDF_SCALAR 0
#elif (__Tahiti__) || (__Pitcairn__) || (__Capeverde__) || \
(__Oland__) || (__Hainan__) || \
(__Hawaii__) || (__Bonaire__) || \
(__Kalindi__) || (__Mullins__) || (__Spectre__) || (__Spooky__) || \
(__Tonga__) || (__Iceland__)
#define SALSA_SCALAR 1
#define CHACHA_SCALAR 1
#define BLAKE2S_SCALAR 1
#define FASTKDF_SCALAR 0
#else
#define SALSA_SCALAR 1
#define CHACHA_SCALAR 1
#define BLAKE2S_SCALAR 1
#define FASTKDF_SCALAR 1
#endif

/* Unroll levels for Salsa and ChaCha */
#define SALSA_UNROLL_LEVEL 4
#define CHACHA_UNROLL_LEVEL 4

/* Reduces FastKDF kernel size by half;
 * might improve performance, disabled by default */
#define FASTKDF_COMPACT 0

/* Reduces BLAKE2s kernel size by half;
 * unlikely to improve performance, disabled by default */
#define BLAKE2S_COMPACT 0


#if !(cl_khr_byte_addressable_store)
#error "Device does not support unaligned stores"
#endif


/* Slow bytewise memcpy() of unaligned memory */
void neoscrypt_bcopy(void *restrict dstp, const void *restrict srcp, const uint len) {
    uchar *dst = (uchar *) dstp;
    uchar *src = (uchar *) srcp;
    uint i;

    for(i = 0; i < len; i++)
      dst[i] = src[i];
}

/* Slow bytewise memcpy() of unaligned memory to local memory */
void neoscrypt_blcopy(__local void *dstp, const void *restrict srcp, const uint len) {
    __local uchar *dst = (__local uchar *) dstp;
    uchar *src = (uchar *) srcp;
    uint i;

    for(i = 0; i < len; i++)
      dst[i] = src[i];
}

/* Slow bytewise XOR of unaligned memory */
void neoscrypt_bxor(void *restrict dstp, const void *restrict srcp, const uint len) {
    uchar *dst = (uchar *) dstp;
    uchar *src = (uchar *) srcp;
    uint i;

    for(i = 0; i < len; i++)
      dst[i] ^= src[i];
}

void neoscrypt_copy256(void *restrict dstp, const void *restrict srcp) {
    ulong16 *dst = (ulong16 *) dstp;
    ulong16 *src = (ulong16 *) srcp;

    dst[0] = src[0];
    dst[1] = src[1];
}

void neoscrypt_xor256(void *restrict dstp, const void *restrict srcp) {
    ulong16 *dst = (ulong16 *) dstp;
    ulong16 *src = (ulong16 *) srcp;

    dst[0] ^= src[0];
    dst[1] ^= src[1];
}

/* XOR based block swapper */
void neoscrypt_swap256(void *restrict blkAp, void *restrict blkBp) {
    ulong16 *blkA = (ulong16 *) blkAp;
    ulong16 *blkB = (ulong16 *) blkBp;

    blkA[0] ^= blkB[0];
    blkB[0] ^= blkA[0];
    blkA[0] ^= blkB[0];
    blkA[1] ^= blkB[1];
    blkB[1] ^= blkA[1];
    blkA[1] ^= blkB[1];
}


/* BLAKE2s */

/* Initialisation vector */
static const __constant uint8 blake2s_IV4[1] = {
    (uint8)(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
};

static const __constant uchar blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

#define G(x, y, a, b, c, d) \
    a += b + m[blake2s_sigma[x][y]]; \
    d = rotate(d ^ a, 16U); \
    c += d; \
    b = rotate(b ^ c, 20U); \
    a += b + m[blake2s_sigma[x][y + 1]]; \
    d = rotate(d ^ a, 24U); \
    c += d; \
    b = rotate(b ^ c, 25U);

#define G1(x, a, b, c, d) \
    a += b + (uint4)(m[blake2s_sigma[x][0]], m[blake2s_sigma[x][2]], m[blake2s_sigma[x][4]], m[blake2s_sigma[x][6]]); \
    d = rotate(d ^ a, V16); \
    c += d; \
    b = rotate(b ^ c, V20); \
    a += b + (uint4)(m[blake2s_sigma[x][1]], m[blake2s_sigma[x][3]], m[blake2s_sigma[x][5]], m[blake2s_sigma[x][7]]); \
    d = rotate(d ^ a, V24); \
    c += d; \
    b = rotate(b ^ c, V25);

#define G2(x, a, b, c, d) \
    a += b + (uint4)(m[blake2s_sigma[x][8]], m[blake2s_sigma[x][10]], m[blake2s_sigma[x][12]], m[blake2s_sigma[x][14]]); \
    d = rotate(d ^ a, V16); \
    c += d; \
    b = rotate(b ^ c, V20); \
    a += b + (uint4)(m[blake2s_sigma[x][9]], m[blake2s_sigma[x][11]], m[blake2s_sigma[x][13]], m[blake2s_sigma[x][15]]); \
    d = rotate(d ^ a, V24); \
    c += d; \
    b = rotate(b ^ c, V25);


/* Salsa20/20 */

#define SALSA_CORE_SCALAR(Y) \
    Y.s4 ^= rotate(Y.s0 + Y.sc, 7U);  Y.s8 ^= rotate(Y.s4 + Y.s0, 9U);  \
    Y.sc ^= rotate(Y.s8 + Y.s4, 13U); Y.s0 ^= rotate(Y.sc + Y.s8, 18U); \
    Y.s9 ^= rotate(Y.s5 + Y.s1, 7U);  Y.sd ^= rotate(Y.s9 + Y.s5, 9U);  \
    Y.s1 ^= rotate(Y.sd + Y.s9, 13U); Y.s5 ^= rotate(Y.s1 + Y.sd, 18U); \
    Y.se ^= rotate(Y.sa + Y.s6, 7U);  Y.s2 ^= rotate(Y.se + Y.sa, 9U);  \
    Y.s6 ^= rotate(Y.s2 + Y.se, 13U); Y.sa ^= rotate(Y.s6 + Y.s2, 18U); \
    Y.s3 ^= rotate(Y.sf + Y.sb, 7U);  Y.s7 ^= rotate(Y.s3 + Y.sf, 9U);  \
    Y.sb ^= rotate(Y.s7 + Y.s3, 13U); Y.sf ^= rotate(Y.sb + Y.s7, 18U); \
    Y.s1 ^= rotate(Y.s0 + Y.s3, 7U);  Y.s2 ^= rotate(Y.s1 + Y.s0, 9U);  \
    Y.s3 ^= rotate(Y.s2 + Y.s1, 13U); Y.s0 ^= rotate(Y.s3 + Y.s2, 18U); \
    Y.s6 ^= rotate(Y.s5 + Y.s4, 7U);  Y.s7 ^= rotate(Y.s6 + Y.s5, 9U);  \
    Y.s4 ^= rotate(Y.s7 + Y.s6, 13U); Y.s5 ^= rotate(Y.s4 + Y.s7, 18U); \
    Y.sb ^= rotate(Y.sa + Y.s9, 7U);  Y.s8 ^= rotate(Y.sb + Y.sa, 9U);  \
    Y.s9 ^= rotate(Y.s8 + Y.sb, 13U); Y.sa ^= rotate(Y.s9 + Y.s8, 18U); \
    Y.sc ^= rotate(Y.sf + Y.se, 7U);  Y.sd ^= rotate(Y.sc + Y.sf, 9U);  \
    Y.se ^= rotate(Y.sd + Y.sc, 13U); Y.sf ^= rotate(Y.se + Y.sd, 18U);

#define SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3) \
    Y0 ^= rotate(Y3 + Y2, V7);  \
    Y1 ^= rotate(Y0 + Y3, V9);  \
    Y2 ^= rotate(Y1 + Y0, V13); \
    Y3 ^= rotate(Y2 + Y1, V18); \
    Y2 ^= rotate(Y3.wxyz + Y0.zwxy, V7);  \
    Y1 ^= rotate(Y2.wxyz + Y3.zwxy, V9);  \
    Y0 ^= rotate(Y1.wxyz + Y2.zwxy, V13); \
    Y3 ^= rotate(Y0.wxyz + Y1.zwxy, V18);

uint16 neoscrypt_salsa(uint16 X) {
    uint i;

#if (SALSA_SCALAR)

    uint16 Y = X;

#if (SALSA_UNROLL_LEVEL == 2)

    for(i = 0; i < 5; i++) {
        SALSA_CORE_SCALAR(Y0, Y1, Y2, Y3);
        SALSA_CORE_SCALAR(Y0, Y1, Y2, Y3);
    }

#elif (SALSA_UNROLL_LEVEL == 3)

    for(i = 0; i < 4; i++) {
        SALSA_CORE_SCALAR(Y);
        if(i == 3) break;
        SALSA_CORE_SCALAR(Y);
        SALSA_CORE_SCALAR(Y);
    }

#elif (SALSA_UNROLL_LEVEL == 4)

    for(i = 0; i < 3; i++) {
        SALSA_CORE_SCALAR(Y);
        SALSA_CORE_SCALAR(Y);
        if(i == 2) break;
        SALSA_CORE_SCALAR(Y);
        SALSA_CORE_SCALAR(Y);
     }

#else

    for(i = 0; i < 2; i++) {
        SALSA_CORE_SCALAR(Y);
        SALSA_CORE_SCALAR(Y);
        SALSA_CORE_SCALAR(Y);
        SALSA_CORE_SCALAR(Y);
        SALSA_CORE_SCALAR(Y);
    }

#endif

    return(X + Y);

#else /* SALSA_VECTOR */

    uint4 Y0 = (uint4)(X.s4, X.s9, X.se, X.s3);
    uint4 Y1 = (uint4)(X.s8, X.sd, X.s2, X.s7);
    uint4 Y2 = (uint4)(X.sc, X.s1, X.s6, X.sb);
    uint4 Y3 = (uint4)(X.s0, X.s5, X.sa, X.sf);

#if (SALSA_UNROLL_LEVEL == 2)

    for(i = 0; i < 5; i++) {
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
    }

#elif (SALSA_UNROLL_LEVEL == 3)

    for(i = 0; i < 4; i++) {
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        if(i == 3) break;
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
    }

#elif (SALSA_UNROLL_LEVEL == 4)

    for(i = 0; i < 3; i++) {
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        if(i == 2) break;
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
     }

#else

    for(i = 0; i < 2; i++) {
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
    }

#endif

    return(X + (uint16)(Y3.x, Y2.y, Y1.z, Y0.w, Y0.x, Y3.y, Y2.z, Y1.w,
                        Y1.x, Y0.y, Y3.z, Y2.w, Y2.x, Y1.y, Y0.z, Y3.w));

#endif
}


/* ChaCha20/20 */

#define CHACHA_CORE_SCALAR(Y) \
    Y.s0 += Y.s4; Y.sc = rotate(Y.sc ^ Y.s0, 16U); \
    Y.s8 += Y.sc; Y.s4 = rotate(Y.s4 ^ Y.s8, 12U); \
    Y.s0 += Y.s4; Y.sc = rotate(Y.sc ^ Y.s0, 8U);  \
    Y.s8 += Y.sc; Y.s4 = rotate(Y.s4 ^ Y.s8, 7U);  \
    Y.s1 += Y.s5; Y.sd = rotate(Y.sd ^ Y.s1, 16U); \
    Y.s9 += Y.sd; Y.s5 = rotate(Y.s5 ^ Y.s9, 12U); \
    Y.s1 += Y.s5; Y.sd = rotate(Y.sd ^ Y.s1, 8U);  \
    Y.s9 += Y.sd; Y.s5 = rotate(Y.s5 ^ Y.s9, 7U);  \
    Y.s2 += Y.s6; Y.se = rotate(Y.se ^ Y.s2, 16U); \
    Y.sa += Y.se; Y.s6 = rotate(Y.s6 ^ Y.sa, 12U); \
    Y.s2 += Y.s6; Y.se = rotate(Y.se ^ Y.s2, 8U);  \
    Y.sa += Y.se; Y.s6 = rotate(Y.s6 ^ Y.sa, 7U);  \
    Y.s3 += Y.s7; Y.sf = rotate(Y.sf ^ Y.s3, 16U); \
    Y.sb += Y.sf; Y.s7 = rotate(Y.s7 ^ Y.sb, 12U); \
    Y.s3 += Y.s7; Y.sf = rotate(Y.sf ^ Y.s3, 8U);  \
    Y.sb += Y.sf; Y.s7 = rotate(Y.s7 ^ Y.sb, 7U);  \
    Y.s0 += Y.s5; Y.sf = rotate(Y.sf ^ Y.s0, 16U); \
    Y.sa += Y.sf; Y.s5 = rotate(Y.s5 ^ Y.sa, 12U); \
    Y.s0 += Y.s5; Y.sf = rotate(Y.sf ^ Y.s0, 8U);  \
    Y.sa += Y.sf; Y.s5 = rotate(Y.s5 ^ Y.sa, 7U);  \
    Y.s1 += Y.s6; Y.sc = rotate(Y.sc ^ Y.s1, 16U); \
    Y.sb += Y.sc; Y.s6 = rotate(Y.s6 ^ Y.sb, 12U); \
    Y.s1 += Y.s6; Y.sc = rotate(Y.sc ^ Y.s1, 8U);  \
    Y.sb += Y.sc; Y.s6 = rotate(Y.s6 ^ Y.sb, 7U);  \
    Y.s2 += Y.s7; Y.sd = rotate(Y.sd ^ Y.s2, 16U); \
    Y.s8 += Y.sd; Y.s7 = rotate(Y.s7 ^ Y.s8, 12U); \
    Y.s2 += Y.s7; Y.sd = rotate(Y.sd ^ Y.s2, 8U);  \
    Y.s8 += Y.sd; Y.s7 = rotate(Y.s7 ^ Y.s8, 7U);  \
    Y.s3 += Y.s4; Y.se = rotate(Y.se ^ Y.s3, 16U); \
    Y.s9 += Y.se; Y.s4 = rotate(Y.s4 ^ Y.s9, 12U); \
    Y.s3 += Y.s4; Y.se = rotate(Y.se ^ Y.s3, 8U);  \
    Y.s9 += Y.se; Y.s4 = rotate(Y.s4 ^ Y.s9, 7U);

#define CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3) \
    Y0 += Y1; Y3 = rotate(Y3 ^ Y0, V16); \
    Y2 += Y3; Y1 = rotate(Y1 ^ Y2, V12); \
    Y0 += Y1; Y3 = rotate(Y3 ^ Y0, V8);  \
    Y2 += Y3; Y1 = rotate(Y1 ^ Y2, V7);  \
    Y0 += Y1.yzwx; Y3 = rotate(Y3 ^ Y0.yzwx, V16); \
    Y2 += Y3.yzwx; Y1 = rotate(Y1 ^ Y2.yzwx, V12); \
    Y0 += Y1.yzwx; Y3 = rotate(Y3 ^ Y0.yzwx, V8);  \
    Y2 += Y3.yzwx; Y1 = rotate(Y1 ^ Y2.yzwx, V7);

uint16 neoscrypt_chacha(uint16 X) {
    uint i;

#if (CHACHA_SCALAR)

    uint16 Y = X;

#if (CHACHA_UNROLL_LEVEL == 2)

    for(i = 0; i < 5; i++) {
        CHACHA_CORE_SCALAR(Y);
        CHACHA_CORE_SCALAR(Y);
    }

#elif (CHACHA_UNROLL_LEVEL == 3)

    for(i = 0; i < 4; i++) {
        CHACHA_CORE_SCALAR(Y);
        if(i == 3) break;
        CHACHA_CORE_SCALAR(Y);
        CHACHA_CORE_SCALAR(Y);
    }

#elif (CHACHA_UNROLL_LEVEL == 4)

    for(i = 0; i < 3; i++) {
        CHACHA_CORE_SCALAR(Y);
        CHACHA_CORE_SCALAR(Y);
        if(i == 2) break;
        CHACHA_CORE_SCALAR(Y);
        CHACHA_CORE_SCALAR(Y);
     }

#else

    for(i = 0; i < 2; i++) {
        CHACHA_CORE_SCALAR(Y);
        CHACHA_CORE_SCALAR(Y);
        CHACHA_CORE_SCALAR(Y);
        CHACHA_CORE_SCALAR(Y);
        CHACHA_CORE_SCALAR(Y);
    }

#endif

    return(X + Y);

#else /* CHACHA_VECTOR */

    uint4 Y0 = X.s0123, Y1 = X.s4567, Y2 = X.s89ab, Y3 = X.scdef;

#if (CHACHA_UNROLL_LEVEL == 2)

    for(i = 0; i < 5; i++) {
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
    }

#elif (CHACHA_UNROLL_LEVEL == 3)

    for(i = 0; i < 4; i++) {
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        if(i == 3) break;
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
    }

#elif (CHACHA_UNROLL_LEVEL == 4)

    for(i = 0; i < 3; i++) {
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        if(i == 2) break;
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
     }

#else

    for(i = 0; i < 2; i++) {
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
    }

#endif

    return(X + (uint16)(Y0, Y1, Y2, Y3));

#endif
}


/* For compatibility */
#if (WORKGROUPSIZE) && !(WORKSIZE)
#define WORKSIZE WORKGROUPSIZE
#endif

/* CodeXL only */
#if !(WORKSIZE)
#define WORKSIZE 128
#endif


/* FastKDF, a fast buffered key derivation function;
 * this algorithm makes extensive use of bytewise operations
 * which may not do the best for GPUs especially VLIW powered */
static void neoscrypt_fastkdf(__global const uint4 *input, __private ulong16 *XZ,
  __local uint16 *L, const uint glbid, const uint lclid, uint mode) {

    /* FastKDF needs 256 + 64 bytes for the password buffer,
     * 256 + 32 bytes for the salt buffer, 64 + 64 + 32 bytes for BLAKE2s */

    uint i, j, bufptr, out_len;

    const uint4 mod = (uint4)(input[4].x, input[4].y, input[4].z, glbid);

    uint16 *XZh = (uint16 *) &XZ[0];
    uint4  *XZq = (uint4 *)  &XZ[0];

    /* Password buffer */
    uchar *Aa = (uchar *) &XZh[0];
    /* Salt buffer */
    uchar *Bb = (uchar *) &XZh[5];
    /* BLAKE2s temp buffer */
    uint8 *T = (uint8 *)  &XZq[38];
    uint4 *t = (uint4 *)  &XZq[38];
    /* BLAKE2s memory space */
     __local uint *m = (__local uint *) &L[lclid];

    /* Mode 0 (extend) and mode 1 (compress) */

    /* Salt buffer */
    if(!mode) {
        out_len = 256;
        XZh[5]  = ((__global const uint16 *) input)[0];
        XZq[24] = mod;
        XZq[25] = input[0];
        XZq[26] = input[1];
        XZq[27] = input[2];
        XZq[28] = input[3];
        XZq[29] = mod;
        XZq[30] = input[0];
        XZq[31] = input[1];
        XZq[32] = input[2];
        XZq[33] = input[3];
        XZq[34] = mod;
        XZq[35] = input[0];
        XZq[36] = input[0];
        XZq[37] = input[1];
    } else {
        out_len = 32;
        XZh[5]  = XZh[0];
        XZh[6]  = XZh[1];
        XZh[7]  = XZh[2];
        XZh[8]  = XZh[3];
        XZq[36] = XZq[0];
        XZq[37] = XZq[1];
    }

    /* Password buffer */
    XZh[0]  = ((__global const uint16 *) input)[0];
    XZq[4]  = mod;
    XZq[5]  = input[0];
    XZq[6]  = input[1];
    XZq[7]  = input[2];
    XZq[8]  = input[3];
    XZq[9]  = mod;
    XZq[10] = input[0];
    XZq[11] = input[1];
    XZq[12] = input[2];
    XZq[13] = input[3];
    XZq[14] = mod;
    XZq[15] = input[0];
    XZq[16] = input[0];
    XZq[17] = input[1];
    XZq[18] = input[2];
    XZq[19] = input[3];

    /* The primary iteration */
    for(i = 0, bufptr = 0; i < 32; i++) {

        /* BLAKE2s state block */
        uint16 S;

        neoscrypt_blcopy(&L[lclid], &Bb[bufptr], 32);
        m[8]  = 0;
        m[9]  = 0;
        m[10] = 0;
        m[11] = 0;
        m[12] = 0;
        m[13] = 0;
        m[14] = 0;
        m[15] = 0;

        T[0] = blake2s_IV4[0];
        S.lo = S.hi = T[0];

        S.s0 ^= 0x01012020;
        S.sc ^= 64;

#if (BLAKE2S_COMPACT)

        for(uint z = 0; z < 2; z++) {

#pragma unroll
            for(j = 0; j < 10; j++) {
#if (BLAKE2S_SCALAR)
                G(j,  0, S.s0, S.s4, S.s8, S.sc);
                G(j,  2, S.s1, S.s5, S.s9, S.sd);
                G(j,  4, S.s2, S.s6, S.sa, S.se);
                G(j,  6, S.s3, S.s7, S.sb, S.sf);
                G(j,  8, S.s0, S.s5, S.sa, S.sf);
                G(j, 10, S.s1, S.s6, S.sb, S.sc);
                G(j, 12, S.s2, S.s7, S.s8, S.sd);
                G(j, 14, S.s3, S.s4, S.s9, S.se);
#else
                G1(j, S.s0123, S.s4567, S.s89ab, S.scdef);
                G2(j, S.s0123, S.s5674, S.sab89, S.sfcde);
#endif
            }

            if(z) break;

            S.lo ^= S.hi ^ T[0];
            S.s0 ^= 0x01012020;
            S.hi = T[0];
            T[0] = S.lo;
            S.sc ^= 128;
            S.se ^= 0xFFFFFFFFU;

            neoscrypt_blcopy(&L[lclid], &Aa[bufptr], 64);

        }

#else

#pragma unroll
        for(j = 0; j < 10; j++) {
#if (BLAKE2S_SCALAR)
            G(j,  0, S.s0, S.s4, S.s8, S.sc);
            G(j,  2, S.s1, S.s5, S.s9, S.sd);
            G(j,  4, S.s2, S.s6, S.sa, S.se);
            G(j,  6, S.s3, S.s7, S.sb, S.sf);
            G(j,  8, S.s0, S.s5, S.sa, S.sf);
            G(j, 10, S.s1, S.s6, S.sb, S.sc);
            G(j, 12, S.s2, S.s7, S.s8, S.sd);
            G(j, 14, S.s3, S.s4, S.s9, S.se);
#else
            G1(j, S.s0123, S.s4567, S.s89ab, S.scdef);
            G2(j, S.s0123, S.s5674, S.sab89, S.sfcde);
#endif
        }

        S.lo ^= S.hi ^ T[0];
        S.s0 ^= 0x01012020;
        S.hi = T[0];
        T[0] = S.lo;
        S.sc ^= 128;
        S.se ^= 0xFFFFFFFFU;

        neoscrypt_blcopy(&L[lclid], &Aa[bufptr], 64);

#pragma unroll
        for(j = 0; j < 10; j++) {
            G(j,  0, S.s0, S.s4, S.s8, S.sc);
            G(j,  2, S.s1, S.s5, S.s9, S.sd);
            G(j,  4, S.s2, S.s6, S.sa, S.se);
            G(j,  6, S.s3, S.s7, S.sb, S.sf);
            G(j,  8, S.s0, S.s5, S.sa, S.sf);
            G(j, 10, S.s1, S.s6, S.sb, S.sc);
            G(j, 12, S.s2, S.s7, S.s8, S.sd);
            G(j, 14, S.s3, S.s4, S.s9, S.se);
        }

#endif /* BLAKE2S_COMPACT */

        T[0] ^= S.lo ^ S.hi;

        /* Calculate the next buffer pointer */
#if (FASTKDF_SCALAR)
        uint8 temp;

        temp.lo = t[0];
        temp.hi = t[1];

        bufptr  = temp.s0;
        bufptr += rotate(temp.s0, 24U);
        bufptr += rotate(temp.s0, 16U);
        bufptr += rotate(temp.s0, 8U);
        bufptr += temp.s1;
        bufptr += rotate(temp.s1, 24U);
        bufptr += rotate(temp.s1, 16U);
        bufptr += rotate(temp.s1, 8U);
        bufptr += temp.s2;
        bufptr += rotate(temp.s2, 24U);
        bufptr += rotate(temp.s2, 16U);
        bufptr += rotate(temp.s2, 8U);
        bufptr += temp.s3;
        bufptr += rotate(temp.s3, 24U);
        bufptr += rotate(temp.s3, 16U);
        bufptr += rotate(temp.s3, 8U);
        bufptr += temp.s4;
        bufptr += rotate(temp.s4, 24U);
        bufptr += rotate(temp.s4, 16U);
        bufptr += rotate(temp.s4, 8U);
        bufptr += temp.s5;
        bufptr += rotate(temp.s5, 24U);
        bufptr += rotate(temp.s5, 16U);
        bufptr += rotate(temp.s5, 8U);
        bufptr += temp.s6;
        bufptr += rotate(temp.s6, 24U);
        bufptr += rotate(temp.s6, 16U);
        bufptr += rotate(temp.s6, 8U);
        bufptr += temp.s7;
        bufptr += rotate(temp.s7, 24U);
        bufptr += rotate(temp.s7, 16U);
        bufptr += rotate(temp.s7, 8U);

        bufptr &= 0xFF;
#else
        uint4 temp;
        temp  = t[0];
        temp += rotate(t[0], V24);
        temp += rotate(t[0], V16);
        temp += rotate(t[0], V8);
        temp += t[1];
        temp += rotate(t[1], V24);
        temp += rotate(t[1], V16);
        temp += rotate(t[1], V8);

        bufptr = (temp.x + temp.y + temp.z + temp.w) & 0xFF;
#endif

        /* Modify the salt buffer */
        neoscrypt_bxor(&Bb[bufptr], &T[0], 32);

        /* Head modified, tail updated */
        if(bufptr < 32)
          neoscrypt_bcopy(&Bb[256 + bufptr], &Bb[bufptr], 32 - bufptr);

        /* Tail modified, head updated */
        if(bufptr > 224)
          neoscrypt_bcopy(&Bb[0], &Bb[256], bufptr - 224);

    }

    /* XOR into the password */
    i = 256 - bufptr;
    if(i >= out_len) {
        neoscrypt_bxor(&Aa[0], &Bb[bufptr], out_len);
    } else {
        neoscrypt_bxor(&Aa[0], &Bb[bufptr], i);
        neoscrypt_bxor(&Aa[i], &Bb[0], out_len - i);
    }

}


__kernel __attribute__((vec_type_hint(uint4)))
__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global const uint4 *restrict input, __global uint *restrict output,
  __global ulong16 *globalcache, const uint target) {
    uint i, j, k;

    uint glbid = get_global_id(0);
    uint grpid = get_group_id(0);
    __global ulong16 *G = (__global ulong16 *) &globalcache[(grpid * WORKSIZE) << 8];

    uint lsize = WORKSIZE;
    uint lclid = glbid & (WORKSIZE - 1);
    __local uint16 L[WORKSIZE];

    __private ulong16 XZ[5];
    uint16 *XZh = (uint16 *) &XZ[0];
    uint   *XZi = (uint *)   &XZ[0];

#if (FASTKDF_COMPACT)
    for(uint mode = 0; mode < 2; mode++) {

        /* X = KDF(password, salt) */
        neoscrypt_fastkdf(input, XZ, L, glbid, lclid, mode);

        if(mode) break;

#else

        neoscrypt_fastkdf(input, XZ, L, glbid, lclid, 0U);

#endif

        /* blkcpy(Z, X) */
        neoscrypt_copy256(&XZ[2], &XZ[0]);

        /* X = SMix(X) and Z = SMix(Z) */
        for(i = 0; i < 2; i++) {

            for(j = 0; j < 128; j++) {

                /* blkcpy(G, X) */
                k = (j * lsize + lclid) << 1;
                G[k]     = XZ[0];
                G[k + 1] = XZ[1];

                /* blkmix(X) */
                XZh[0] ^= XZh[3];
                if(i) {
                    XZh[0] = neoscrypt_salsa(XZh[0]);
                    XZh[1] ^= XZh[0];
                    XZh[1] = neoscrypt_salsa(XZh[1]);
                    XZh[2] ^= XZh[1];
                    XZh[2] = neoscrypt_salsa(XZh[2]);
                    XZh[3] ^= XZh[2];
                    XZh[3] = neoscrypt_salsa(XZh[3]);
                } else {
                    XZh[0] = neoscrypt_chacha(XZh[0]);
                    XZh[1] ^= XZh[0];
                    XZh[1] = neoscrypt_chacha(XZh[1]);
                    XZh[2] ^= XZh[1];
                    XZh[2] = neoscrypt_chacha(XZh[2]);
                    XZh[3] ^= XZh[2];
                    XZh[3] = neoscrypt_chacha(XZh[3]);
                }
                XZh[1] ^= XZh[2];
                XZh[2] ^= XZh[1];
                XZh[1] ^= XZh[2];

            }

            for(j = 0; j < 128; j++) {

                /* integerify(X) mod N */
                k = (convert_uchar(((uint *) XZ)[48] & 0x7F) * lsize + lclid) << 1;

                /* blkxor(X, G) */
                XZ[0] ^= G[k];
                XZ[1] ^= G[k + 1];

                /* blkmix(X) */
                XZh[0] ^= XZh[3];
                if(i) {
                    XZh[0] = neoscrypt_salsa(XZh[0]);
                    XZh[1] ^= XZh[0];
                    XZh[1] = neoscrypt_salsa(XZh[1]);
                    XZh[2] ^= XZh[1];
                    XZh[2] = neoscrypt_salsa(XZh[2]);
                    XZh[3] ^= XZh[2];
                    XZh[3] = neoscrypt_salsa(XZh[3]);
                } else {
                    XZh[0] = neoscrypt_chacha(XZh[0]);
                    XZh[1] ^= XZh[0];
                    XZh[1] = neoscrypt_chacha(XZh[1]);
                    XZh[2] ^= XZh[1];
                    XZh[2] = neoscrypt_chacha(XZh[2]);
                    XZh[3] ^= XZh[2];
                    XZh[3] = neoscrypt_chacha(XZh[3]);
                }
                XZh[1] ^= XZh[2];
                XZh[2] ^= XZh[1];
                XZh[1] ^= XZh[2];

            }

            if(i) break;

            /* Swap the buffers and repeat */
            neoscrypt_swap256(&XZ[2], &XZ[0]);

        }

        /* blkxor(X, Z) */
        neoscrypt_xor256(&XZ[0], &XZ[2]);

#if (FASTKDF_COMPACT)

    }

#else

    neoscrypt_fastkdf(input, XZ, L, glbid, lclid, 1U);

#endif

#define NEOSCRYPT_FOUND (0xFF)
#ifdef cl_khr_global_int32_base_atomics
    #define SETFOUND(nonce) output[atomic_add(&output[NEOSCRYPT_FOUND], 1)] = nonce
#else
    #define SETFOUND(nonce) output[output[NEOSCRYPT_FOUND]++] = nonce
#endif

    if(XZi[7] <= target) SETFOUND(glbid);

    return;
}
