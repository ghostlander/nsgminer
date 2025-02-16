/*
 * Copyright (c) 2014-2025 John Doering <ghostlander@phoenixcoin.org>
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
 * Optimised for modern AMD and NVIDIA GPU architectures
 * v8c, 16-Feb-2025 */


#if (cl_amd_media_ops)
#define AMD 1
#elif (cl_nv_pragma_unroll)
#define NVIDIA 1
#endif

#if (AMD)
#define SALSA_SCALAR 0
#define CHACHA_SCALAR 0
#define BLAKE2S_SCALAR 0
#define FASTKDF_SCALAR 0
#define SALSA_UNROLL_LEVEL 4
#define CHACHA_UNROLL_LEVEL 4
#define FASTKDF_COMPACT 0
#define BLAKE2S_COMPACT 0
#elif (NVIDIA)
#define SALSA_SCALAR 0
#define CHACHA_SCALAR 0
#define BLAKE2S_SCALAR 0
#define FASTKDF_SCALAR 0
#define SALSA_UNROLL_LEVEL 1
#define CHACHA_UNROLL_LEVEL 1
#define FASTKDF_COMPACT 1
#define BLAKE2S_COMPACT 1
#else
#define SALSA_SCALAR 1
#define CHACHA_SCALAR 1
#define BLAKE2S_SCALAR 1
#define FASTKDF_SCALAR 1
#define SALSA_UNROLL_LEVEL 2
#define CHACHA_UNROLL_LEVEL 2
#define FASTKDF_COMPACT 0
#define BLAKE2S_COMPACT 0
#endif


#if (AMD)
/* memcpy() of 4-byte aligned memory */
void neoscrypt_copy4(void *restrict dstp, const void *restrict srcp,
  uint len) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;
    uint i;

    len >>= 2;

    for(i = 0; i < len; i++)
      dst[i] = src[i];
}
#else
#define amd_bitalign(src0, src1, src2) ((uint)(((((ulong)src0) << 32) | (ulong)src1) >> (src2 & 0x1F)))
#endif

/* 32-byte memcpy() of possibly unaligned private memory to 32-byte aligned
 * private memory */
void neoscrypt_copy32_upap(uint8 *restrict dstp, const void *restrict srcp,
  uint offset) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;

    offset = amd_bitalign(offset, offset, 29U);

    dst[0] = amd_bitalign(src[1], src[0], offset);
    dst[1] = amd_bitalign(src[2], src[1], offset);
    dst[2] = amd_bitalign(src[3], src[2], offset);
    dst[3] = amd_bitalign(src[4], src[3], offset);
    dst[4] = amd_bitalign(src[5], src[4], offset);
    dst[5] = amd_bitalign(src[6], src[5], offset);
    dst[6] = amd_bitalign(src[7], src[6], offset);
    dst[7] = amd_bitalign(src[8], src[7], offset);
}

/* 64-byte memcpy() of possibly unaligned local memory to 32-byte aligned
 * private memory */
void neoscrypt_copy64_ulap(uint8 *restrict dstp, const __local void *restrict srcp,
  uint offset) {
    uint *dst = (uint *) dstp;
    __local uint *src = (__local uint *) srcp;

    offset = amd_bitalign(offset, offset, 29U);

    dst[0]  = amd_bitalign(src[1],  src[0], offset);
    dst[1]  = amd_bitalign(src[2],  src[1], offset);
    dst[2]  = amd_bitalign(src[3],  src[2], offset);
    dst[3]  = amd_bitalign(src[4],  src[3], offset);
    dst[4]  = amd_bitalign(src[5],  src[4], offset);
    dst[5]  = amd_bitalign(src[6],  src[5], offset);
    dst[6]  = amd_bitalign(src[7],  src[6], offset);
    dst[7]  = amd_bitalign(src[8],  src[7], offset);
    dst[8]  = amd_bitalign(src[9],  src[8], offset);
    dst[9]  = amd_bitalign(src[10], src[9], offset);
    dst[10] = amd_bitalign(src[11], src[10], offset);
    dst[11] = amd_bitalign(src[12], src[11], offset);
    dst[12] = amd_bitalign(src[13], src[12], offset);
    dst[13] = amd_bitalign(src[14], src[13], offset);
    dst[14] = amd_bitalign(src[15], src[14], offset);
    dst[15] = amd_bitalign(src[16], src[15], offset);
}

/* 32-byte memcpy() of possibly unaligned private memory to 32-byte aligned
 * private memory (iterated) */
void neoscrypt_copy32_upap_it(uint8 *restrict dstp, const void *restrict srcp,
  uint offset, uint it) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;
    uint i;

    offset = amd_bitalign(offset, offset, 29U);

    it = amd_bitalign(it, it, 29U);

    for(i = 0; i < it; i += 8) {
        dst[i]     = amd_bitalign(src[i + 1], src[i],     offset);
        dst[i + 1] = amd_bitalign(src[i + 2], src[i + 1], offset);
        dst[i + 2] = amd_bitalign(src[i + 3], src[i + 2], offset);
        dst[i + 3] = amd_bitalign(src[i + 4], src[i + 3], offset);
        dst[i + 4] = amd_bitalign(src[i + 5], src[i + 4], offset);
        dst[i + 5] = amd_bitalign(src[i + 6], src[i + 5], offset);
        dst[i + 6] = amd_bitalign(src[i + 7], src[i + 6], offset);
        dst[i + 7] = amd_bitalign(src[i + 8], src[i + 7], offset);
    }
}

/* 4-byte XOR of possibly unaligned private memory to 4-byte aligned
 * private memory */
void neoscrypt_xor4_upap(uint *restrict dst, const uint *restrict src, uint offset) {
    offset = amd_bitalign(offset, offset, 29U);
    dst[0] ^= amd_bitalign(src[1], src[0], offset);
}

/* 32-byte XOR of 32-byte aligned private memory to possibly unaligned
 * private memory */
void neoscrypt_xor32_apup(void *restrict dstp, const uint8 *restrict srcp,
  uint offset) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;
    uint roffset;

    /* OpenCL cannot shift uint by 32 to zero value */

#if (AMD)
    if(offset) {
        /* 75% chance */
        roffset = 32U - amd_bitalign(offset, offset, 29U);
        dst[0] ^= amd_bitalign(src[0], 0U,     roffset);
        dst[1] ^= amd_bitalign(src[1], src[0], roffset);
        dst[2] ^= amd_bitalign(src[2], src[1], roffset);
        dst[3] ^= amd_bitalign(src[3], src[2], roffset);
        dst[4] ^= amd_bitalign(src[4], src[3], roffset);
        dst[5] ^= amd_bitalign(src[5], src[4], roffset);
        dst[6] ^= amd_bitalign(src[6], src[5], roffset);
        dst[7] ^= amd_bitalign(src[7], src[6], roffset);
        dst[8] ^= amd_bitalign(0U,     src[7], roffset);
    } else {
        /* 25% chance */
        dst[0] ^= src[0];
        dst[1] ^= src[1];
        dst[2] ^= src[2];
        dst[3] ^= src[3];
        dst[4] ^= src[4];
        dst[5] ^= src[5];
        dst[6] ^= src[6];
        dst[7] ^= src[7];
    }
#else
    offset <<= 3;
    roffset = 32U - offset;

    dst[0] ^= (src[0] << offset);
    dst[1] ^= ((src[1] << offset) | (uint)((ulong)src[0] >> roffset));
    dst[2] ^= ((src[2] << offset) | (uint)((ulong)src[1] >> roffset));
    dst[3] ^= ((src[3] << offset) | (uint)((ulong)src[2] >> roffset));
    dst[4] ^= ((src[4] << offset) | (uint)((ulong)src[3] >> roffset));
    dst[5] ^= ((src[5] << offset) | (uint)((ulong)src[4] >> roffset));
    dst[6] ^= ((src[6] << offset) | (uint)((ulong)src[5] >> roffset));
    dst[7] ^= ((src[7] << offset) | (uint)((ulong)src[6] >> roffset));
    dst[8] ^= (uint)((ulong)src[7] >> roffset);
#endif
}

void neoscrypt_copy128_pl(uint16 __local *restrict dst, const uint16 *restrict src) {
    dst[0] = src[0];
    dst[1] = src[1];
}

void neoscrypt_copy256(uint16 *restrict dst, const uint16 *restrict src) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

void neoscrypt_xor256(uint16 *restrict dst, const uint16 *restrict src) {
    dst[0] ^= src[0];
    dst[1] ^= src[1];
    dst[2] ^= src[2];
    dst[3] ^= src[3];
}

/* 64-byte XOR based block swapper */
void neoscrypt_swap64(uint16 *restrict blkA, uint16 *restrict blkB) {
    blkA[0] ^= blkB[0];
    blkB[0] ^= blkA[0];
    blkA[0] ^= blkB[0];
}

/* 256-byte XOR based block swapper */
void neoscrypt_swap256(uint16 *restrict blkA, uint16 *restrict blkB) {
    blkA[0] ^= blkB[0];
    blkB[0] ^= blkA[0];
    blkA[0] ^= blkB[0];
    blkA[1] ^= blkB[1];
    blkB[1] ^= blkA[1];
    blkA[1] ^= blkB[1];
    blkA[2] ^= blkB[2];
    blkB[2] ^= blkA[2];
    blkA[2] ^= blkB[2];
    blkA[3] ^= blkB[3];
    blkB[3] ^= blkA[3];
    blkA[3] ^= blkB[3];
}


/* BLAKE2s */

/* Initialisation vector */
static const __constant uint8 blake2s_IV4[1] = {
    (uint8)(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
};

static const __constant uint blake2s_sigma[10][16] = {
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
    d = rotate(d ^ a, (uint4)(16, 16, 16, 16)); \
    c += d; \
    b = rotate(b ^ c, (uint4)(20, 20, 20, 20)); \
    a += b + (uint4)(m[blake2s_sigma[x][1]], m[blake2s_sigma[x][3]], m[blake2s_sigma[x][5]], m[blake2s_sigma[x][7]]); \
    d = rotate(d ^ a, (uint4)(24, 24, 24, 24)); \
    c += d; \
    b = rotate(b ^ c, (uint4)(25, 25, 25, 25));

#define G2(x, a, b, c, d) \
    a += b + (uint4)(m[blake2s_sigma[x][8]], m[blake2s_sigma[x][10]], m[blake2s_sigma[x][12]], m[blake2s_sigma[x][14]]); \
    d = rotate(d ^ a, (uint4)(16, 16, 16, 16)); \
    c += d; \
    b = rotate(b ^ c, (uint4)(20, 20, 20, 20)); \
    a += b + (uint4)(m[blake2s_sigma[x][9]], m[blake2s_sigma[x][11]], m[blake2s_sigma[x][13]], m[blake2s_sigma[x][15]]); \
    d = rotate(d ^ a, (uint4)(24, 24, 24, 24)); \
    c += d; \
    b = rotate(b ^ c, (uint4)(25, 25, 25, 25));


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
    Y0 ^= rotate(Y3 + Y2, (uint4)( 7,  7,  7,  7)); \
    Y1 ^= rotate(Y0 + Y3, (uint4)( 9,  9,  9,  9)); \
    Y2 ^= rotate(Y1 + Y0, (uint4)(13, 13, 13, 13)); \
    Y3 ^= rotate(Y2 + Y1, (uint4)(18, 18, 18, 18)); \
    Y2 ^= rotate(Y3.wxyz + Y0.zwxy, (uint4)( 7,  7,  7,  7)); \
    Y1 ^= rotate(Y2.wxyz + Y3.zwxy, (uint4)( 9,  9,  9,  9)); \
    Y0 ^= rotate(Y1.wxyz + Y2.zwxy, (uint4)(13, 13, 13, 13)); \
    Y3 ^= rotate(Y0.wxyz + Y1.zwxy, (uint4)(18, 18, 18, 18));

uint16 neoscrypt_salsa(uint16 X) {
    uint i;

#if (SALSA_SCALAR)

    uint16 Y = X;

#if (SALSA_UNROLL_LEVEL == 1)

    for(i = 0; i < 10; i++) {
        SALSA_CORE_SCALAR(Y);
    }

#elif (SALSA_UNROLL_LEVEL == 2)

    for(i = 0; i < 5; i++) {
        SALSA_CORE_SCALAR(Y);
        SALSA_CORE_SCALAR(Y);
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

#if (SALSA_UNROLL_LEVEL == 1)

    for(i = 0; i < 10; i++) {
        SALSA_CORE_VECTOR(Y0, Y1, Y2, Y3);
    }

#elif (SALSA_UNROLL_LEVEL == 2)

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
    Y0 += Y1; Y3 = rotate(Y3 ^ Y0, (uint4)(16, 16, 16, 16)); \
    Y2 += Y3; Y1 = rotate(Y1 ^ Y2, (uint4)(12, 12, 12, 12)); \
    Y0 += Y1; Y3 = rotate(Y3 ^ Y0, (uint4)( 8,  8,  8,  8)); \
    Y2 += Y3; Y1 = rotate(Y1 ^ Y2, (uint4)( 7,  7,  7,  7)); \
    Y0 += Y1.yzwx; Y3 = rotate(Y3 ^ Y0.yzwx, (uint4)(16, 16, 16, 16)); \
    Y2 += Y3.yzwx; Y1 = rotate(Y1 ^ Y2.yzwx, (uint4)(12, 12, 12, 12)); \
    Y0 += Y1.yzwx; Y3 = rotate(Y3 ^ Y0.yzwx, (uint4)( 8,  8,  8,  8)); \
    Y2 += Y3.yzwx; Y1 = rotate(Y1 ^ Y2.yzwx, (uint4)( 7,  7,  7,  7));

uint16 neoscrypt_chacha(uint16 X) {
    uint i;

#if (CHACHA_SCALAR)

    uint16 Y = X;

#if (CHACHA_UNROLL_LEVEL == 1)

    for(i = 0; i < 10; i++) {
        CHACHA_CORE_SCALAR(Y);
    }

#elif (CHACHA_UNROLL_LEVEL == 2)

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

#if (CHACHA_UNROLL_LEVEL == 1)

    for(i = 0; i < 10; i++) {
        CHACHA_CORE_VECTOR(Y0, Y1, Y2, Y3);
    }

#elif (CHACHA_UNROLL_LEVEL == 2)

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
 * this algorithm makes extensive use of bytewise operations */
uint neoscrypt_fastkdf_update(uint16 *XZ, __local uint16 *Lh) {

    /* FastKDF needs 256 + 64 bytes for the password buffer,
     * 256 + 32 bytes for the salt buffer, 64 + 64 + 32 bytes for BLAKE2s */

    uint i, bufptr, passptr, offset;

    /* Password buffer */
    __local uint *Ai = (__local uint *) &Lh[0];
    /* Salt buffer */
    uint4 *Bq = (uint4 *) &XZ[0];
    uint  *Bi = (uint  *) &XZ[0];
    /* BLAKE2s temp buffer */
    uint8 *T = (uint8 *)  &Bq[18];
    uint4 *t = (uint4 *)  &Bq[18];
    /* BLAKE2s memory space */
    uint8 *M = (uint8 *)  &Bq[20];
    uint  *m = (uint *)   &Bq[20];

    /* The primary iteration */
    for(i = 0, bufptr = 0; i < 32; i++) {

        /* BLAKE2s state block */
        uint16 S;

        offset = bufptr & 0x03;
        neoscrypt_copy32_upap(&M[0], &Bi[bufptr >> 2], offset);

        M[1] = (uint8)(0, 0, 0, 0, 0, 0, 0, 0);

        T[0] = blake2s_IV4[0];
        S.lo = S.hi = T[0];

        S.s0 ^= 0x01012020U;
        S.sc ^= 64U;

#if (BLAKE2S_COMPACT)

        for(uint z = 0; z < 2; z++) {

#pragma unroll
            for(uint j = 0; j < 10; j++) {
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
            S.s0 ^= 0x01012020U;
            S.hi = T[0];
            T[0] = S.lo;
            S.sc ^= 128U;
            S.se ^= 0xFFFFFFFFU;

            passptr = bufptr - 80U;
            neoscrypt_copy64_ulap(&M[0], &Ai[min(passptr, bufptr) >> 2], offset);

        }

#else

#pragma unroll
        for(uint j = 0; j < 10; j++) {
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
        S.s0 ^= 0x01012020U;
        S.hi = T[0];
        T[0] = S.lo;
        S.sc ^= 128U;
        S.se ^= 0xFFFFFFFFU;

        passptr = bufptr - 80U;
        neoscrypt_copy64_ulap(&M[0], &Ai[min(passptr, bufptr) >> 2], offset);

#pragma unroll
        for(uint j = 0; j < 10; j++) {
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

        bufptr = convert_uchar(bufptr);
#else
        uint4 temp;
        temp  = t[0];
        temp += rotate(t[0], (uint4)(24, 24, 24, 24));
        temp += rotate(t[0], (uint4)(16, 16, 16, 16));
        temp += rotate(t[0], (uint4)( 8,  8,  8,  8));
        temp += t[1];
        temp += rotate(t[1], (uint4)(24, 24, 24, 24));
        temp += rotate(t[1], (uint4)(16, 16, 16, 16));
        temp += rotate(t[1], (uint4)( 8,  8,  8,  8));

        bufptr = convert_uchar(temp.x + temp.y + temp.z + temp.w);
#endif

        /* Modify the salt buffer */
        offset = bufptr & 0x03;
        neoscrypt_xor32_apup(&Bi[bufptr >> 2], &T[0], offset);

#if (AMD)
        /* Head modified, 4-byte aligned copy to tail */
        if(bufptr < 32U) {
            neoscrypt_copy4(&Bi[(256 + bufptr) >> 2], &Bi[bufptr >> 2], 32U - bufptr + offset);
            continue;
        }

        /* Tail modified, 4-byte aligned copy to head */
        if(bufptr > 224U) {
            neoscrypt_copy4(&Bi[0], &Bi[64], bufptr - 224U + (4U - offset));
        }
#else
        /* Head modified, full copy to tail */
        if(bufptr < 32U) {
            Bq[16] = Bq[0];
            Bq[17] = Bq[1];
            continue;
        }

        /* Tail modified, full copy to head */
        if(bufptr > 224U) {
            Bq[0] = Bq[16];
            Bq[1] = Bq[17];
        }
#endif

    }

    return(bufptr);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global const uint4 *restrict input, __global uint *restrict output,
  __global ulong16 *restrict globalcache, const uint target) {
    uint i, j, k, bufptr, result;

    uint glbid = get_global_id(0);
    uint grpid = get_group_id(0);
    __global uint16 *G = (__global uint16 *) &globalcache[mul24(grpid, (uint)(WORKSIZE << 8))];

    uint lclid = glbid & (WORKSIZE - 1);
    __local uint16 L[WORKSIZE << 2];
    __local uint16 *Lh = (__local uint16 *) &L[lclid << 2];

    uint16 XZ[5];
    uint4 *XZq = (uint4 *) &XZ[0];
    uint  *XZi = (uint *)  &XZ[0];

    uint16 Y[4];
    uint8 *Yo = (uint8 *) &Y[0];

    result = input[1].w;

    /* 1st FastKDF buffer initialisation */
    const uint4 mod = (uint4)(input[4].x, input[4].y, input[4].z, glbid);

    XZ[0] = (uint16)(input[0], input[1], input[2], input[3]);
    XZ[1] = (uint16)(mod, input[0], input[1], input[2]);
    XZ[2] = (uint16)(input[3], mod, input[0], input[1]);
    XZ[3] = (uint16)(input[2], input[3], mod, input[0]);
    XZq[16] = XZq[0];
    XZq[17] = XZq[1];

    neoscrypt_copy128_pl(&Lh[0], &XZ[0]);
    Lh[2] = (uint16)(input[3], mod, input[0], input[0]);
    Lh[3] = (uint16)(input[1], input[2], input[3], mod);

#if (FASTKDF_COMPACT)
    /* Mode 0 (stretching) and mode 1 (compressing) */
    for(uint mode = 0; mode < 2; mode++) {

        /* X = KDF(password, salt) */
        bufptr = neoscrypt_fastkdf_update(XZ, Lh);

        if(mode) break;
#else
        bufptr = neoscrypt_fastkdf_update(XZ, Lh);
#endif

        /* FastKDF finish, mode 0 (stretching) */
        uint it = (256 - bufptr + 31) >> 5;
        neoscrypt_copy32_upap_it(&Yo[0], &XZi[bufptr >> 2], bufptr & 0x03, it);
        neoscrypt_copy32_upap_it(&Yo[it], &XZi[(bufptr & 0x1FU) >> 2], bufptr & 0x03, 8U - it);

        XZ[0] = Y[0] ^ Lh[0];
        XZ[1] = Y[1] ^ Lh[1];
        XZ[2] = Y[2] ^ (uint16)(input[3], mod, input[0], input[1]);
        XZ[3] = Y[3] ^ (uint16)(input[2], input[3], mod, input[0]);

        /* blkcpy(Y, X/Z) */
        neoscrypt_copy256(&Y[0], &XZ[0]);

        /* X = SMix(X) and Z = SMix(Z) */
        for(i = 0; i < 2; i++) {

            for(j = 0; j < 128; j++) {

                /* blkcpy(G, X) */
                k = rotate(mad24(j, (uint)WORKSIZE, lclid), 2U);
                G[k]     = XZ[0];
                G[k + 1] = XZ[1];
                G[k + 2] = XZ[2];
                G[k + 3] = XZ[3];

                /* blkmix(X) */
                if(i) {
                    XZ[0] = neoscrypt_salsa(XZ[0] ^ XZ[3]);
                    XZ[1] = neoscrypt_salsa(XZ[1] ^ XZ[0]);
                    XZ[2] = neoscrypt_salsa(XZ[2] ^ XZ[1]);
                    XZ[3] = neoscrypt_salsa(XZ[3] ^ XZ[2]);
                } else {
                    XZ[0] = neoscrypt_chacha(XZ[0] ^ XZ[3]);
                    XZ[1] = neoscrypt_chacha(XZ[1] ^ XZ[0]);
                    XZ[2] = neoscrypt_chacha(XZ[2] ^ XZ[1]);
                    XZ[3] = neoscrypt_chacha(XZ[3] ^ XZ[2]);
                }
                neoscrypt_swap64(&XZ[2], &XZ[1]);

            }

            for(j = 0; j < 128; j++) {

                /* integerify(X) mod N */
                k = rotate(mad24((((uint *) XZ)[48] & 0x7F), (uint)WORKSIZE, lclid), 2U);

                /* blkxor(X, G) */
                XZ[0] ^= G[k];
                XZ[1] ^= G[k + 1];
                XZ[2] ^= G[k + 2];
                XZ[3] ^= G[k + 3];

                /* blkmix(X) */
                if(i) {
                    XZ[0] = neoscrypt_salsa(XZ[0] ^ XZ[3]);
                    XZ[1] = neoscrypt_salsa(XZ[1] ^ XZ[0]);
                    XZ[2] = neoscrypt_salsa(XZ[2] ^ XZ[1]);
                    XZ[3] = neoscrypt_salsa(XZ[3] ^ XZ[2]);
                } else {
                    XZ[0] = neoscrypt_chacha(XZ[0] ^ XZ[3]);
                    XZ[1] = neoscrypt_chacha(XZ[1] ^ XZ[0]);
                    XZ[2] = neoscrypt_chacha(XZ[2] ^ XZ[1]);
                    XZ[3] = neoscrypt_chacha(XZ[3] ^ XZ[2]);
                }
                neoscrypt_swap64(&XZ[2], &XZ[1]);

            }

            if(i) break;

            /* Swap the buffers and repeat */
            neoscrypt_swap256(&XZ[0], &Y[0]);

        }

        /* blkxor(X, Z) */
        neoscrypt_xor256(&XZ[0], &Y[0]);

        /* 2nd FastKDF buffer initialisation */
        XZq[16] = XZq[0];
        XZq[17] = XZq[1];

#if (FASTKDF_COMPACT)
    }
#else
    bufptr = neoscrypt_fastkdf_update(XZ, Lh);
#endif

    /* FastKDF finish, mode 1 (compressing); most significant uint only */
    neoscrypt_xor4_upap(&result, &XZi[(bufptr >> 2) + 7], bufptr & 0x03);

#define NEOSCRYPT_FOUND (0xFF)
#ifdef cl_khr_global_int32_base_atomics
    #define SETFOUND(nonce) output[atomic_add(&output[NEOSCRYPT_FOUND], 1)] = nonce
#else
    #define SETFOUND(nonce) output[output[NEOSCRYPT_FOUND]++] = nonce
#endif

    if(result <= target) SETFOUND(glbid);

    return;
}
