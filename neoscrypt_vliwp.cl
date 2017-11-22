/*
 * Copyright (c) 2014-2017 John Doering <ghostlander@phoenixcoin.org>
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
 * Optimised for the AMD VLIW4 and VLIW5 architectures
 * v8a (parallel), 22-Nov-2017 */


#if (__ATI_RV770__) || (__ATI_RV730__) || (__ATI_RV710__)
/* AMD TeraScale with OpenCL / VLIW5 (all HD4000 series) */
#define OLD_VLIW 1
#endif

#if(__Cypress__) || (__Barts__) || (__Juniper__) || \
(__Turks__) || (__Caicos__) || (__Redwood__) || (__Cedar__) || \
(__BeaverCreek__) || (__WinterPark__) || (__Loveland__) || \
(__Cayman__) || (__Devastator__) || (__Scrapper__)
/* AMD TeraScale 2 / VLIW5 (all HD5000 series, most HD6000 series,
 * some HD83x0 and HD84x0 OEM cards);
 * AMD TeraScale 3 / VLIW4 (HD69x0, HD73x0, HD74x0, HD75x0, HD76x0,
 * HD83x0, HD84x0, HD85x0, HD86x0, R5 220, R5 235[X] cards and APUs) */
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#endif

#define SALSA_CHACHA_SCALAR 0
#define BLAKE2S_SCALAR 0
#define FASTKDF_SCALAR 0
#define SALSA_CHACHA_UNROLL_LEVEL 2
#define BLAKE2S_COMPACT 0


/* Use amd_bitalign() because amd_bytealign() might be broken in old drivers */

/* 32-byte memcpy() of possibly unaligned memory to 4-byte aligned memory */
void neoscrypt_copy32(void *restrict dstp, const void *restrict srcp,
  uint offset) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;

#if (OLD_VLIW)
    offset <<= 3;
    uint roffset = 32U - offset;

    dst[0] = ((uint)((ulong)src[1] << roffset) | (src[0] >> offset));
    dst[1] = ((uint)((ulong)src[2] << roffset) | (src[1] >> offset));
    dst[2] = ((uint)((ulong)src[3] << roffset) | (src[2] >> offset));
    dst[3] = ((uint)((ulong)src[4] << roffset) | (src[3] >> offset));
    dst[4] = ((uint)((ulong)src[5] << roffset) | (src[4] >> offset));
    dst[5] = ((uint)((ulong)src[6] << roffset) | (src[5] >> offset));
    dst[6] = ((uint)((ulong)src[7] << roffset) | (src[6] >> offset));
    dst[7] = ((uint)((ulong)src[8] << roffset) | (src[7] >> offset));
#else
    offset = amd_bitalign(offset, offset, 29U);

    dst[0] = amd_bitalign(src[1], src[0], offset);
    dst[1] = amd_bitalign(src[2], src[1], offset);
    dst[2] = amd_bitalign(src[3], src[2], offset);
    dst[3] = amd_bitalign(src[4], src[3], offset);
    dst[4] = amd_bitalign(src[5], src[4], offset);
    dst[5] = amd_bitalign(src[6], src[5], offset);
    dst[6] = amd_bitalign(src[7], src[6], offset);
    dst[7] = amd_bitalign(src[8], src[7], offset);
#endif
}

/* 64-byte memcpy() of possibly unaligned memory to 4-byte aligned memory */
void neoscrypt_copy64(void *restrict dstp, const void *restrict srcp,
  uint offset) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;

#if (OLD_VLIW)
    offset <<= 3;
    uint roffset = 32U - offset;

    dst[0]  = ((uint)((ulong)src[1]  << roffset) | (src[0]  >> offset));
    dst[1]  = ((uint)((ulong)src[2]  << roffset) | (src[1]  >> offset));
    dst[2]  = ((uint)((ulong)src[3]  << roffset) | (src[2]  >> offset));
    dst[3]  = ((uint)((ulong)src[4]  << roffset) | (src[3]  >> offset));
    dst[4]  = ((uint)((ulong)src[5]  << roffset) | (src[4]  >> offset));
    dst[5]  = ((uint)((ulong)src[6]  << roffset) | (src[5]  >> offset));
    dst[6]  = ((uint)((ulong)src[7]  << roffset) | (src[6]  >> offset));
    dst[7]  = ((uint)((ulong)src[8]  << roffset) | (src[7]  >> offset));
    dst[8]  = ((uint)((ulong)src[9]  << roffset) | (src[8]  >> offset));
    dst[9]  = ((uint)((ulong)src[10] << roffset) | (src[9]  >> offset));
    dst[10] = ((uint)((ulong)src[11] << roffset) | (src[10] >> offset));
    dst[11] = ((uint)((ulong)src[12] << roffset) | (src[11] >> offset));
    dst[12] = ((uint)((ulong)src[13] << roffset) | (src[12] >> offset));
    dst[13] = ((uint)((ulong)src[14] << roffset) | (src[13] >> offset));
    dst[14] = ((uint)((ulong)src[15] << roffset) | (src[14] >> offset));
    dst[15] = ((uint)((ulong)src[16] << roffset) | (src[15] >> offset));
#else
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
#endif
}

/* 32-byte XOR of possibly unaligned memory to 4-byte aligned memory */
void neoscrypt_xor32_ua(void *restrict dstp, const void *restrict srcp,
  uint offset) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;

#if (OLD_VLIW)
    offset <<= 3;
    uint roffset = 32U - offset;

    dst[0] ^= ((uint)((ulong)src[1] << roffset) | (src[0] >> offset));
    dst[1] ^= ((uint)((ulong)src[2] << roffset) | (src[1] >> offset));
    dst[2] ^= ((uint)((ulong)src[3] << roffset) | (src[2] >> offset));
    dst[3] ^= ((uint)((ulong)src[4] << roffset) | (src[3] >> offset));
    dst[4] ^= ((uint)((ulong)src[5] << roffset) | (src[4] >> offset));
    dst[5] ^= ((uint)((ulong)src[6] << roffset) | (src[5] >> offset));
    dst[6] ^= ((uint)((ulong)src[7] << roffset) | (src[6] >> offset));
    dst[7] ^= ((uint)((ulong)src[8] << roffset) | (src[7] >> offset));
#else
    offset = amd_bitalign(offset, offset, 29U);

    dst[0] ^= amd_bitalign(src[1], src[0], offset);
    dst[1] ^= amd_bitalign(src[2], src[1], offset);
    dst[2] ^= amd_bitalign(src[3], src[2], offset);
    dst[3] ^= amd_bitalign(src[4], src[3], offset);
    dst[4] ^= amd_bitalign(src[5], src[4], offset);
    dst[5] ^= amd_bitalign(src[6], src[5], offset);
    dst[6] ^= amd_bitalign(src[7], src[6], offset);
    dst[7] ^= amd_bitalign(src[8], src[7], offset);
#endif
}

/* 32-byte XOR of possibly unaligned memory to 4-byte aligned memory (iterated) */
void neoscrypt_xor32_ua_it(void *restrict dstp, const void *restrict srcp,
  uint offset, uint it) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;
    uint i;

#if (OLD_VLIW)
    offset <<= 3;
    uint roffset = 32U - offset;

    it <<= 3;
    for(i = 0; i < it; i += 8) {
        dst[i]     ^= ((uint)((ulong)src[i + 1] << roffset) | (src[i]     >> offset));
        dst[i + 1] ^= ((uint)((ulong)src[i + 2] << roffset) | (src[i + 1] >> offset));
        dst[i + 2] ^= ((uint)((ulong)src[i + 3] << roffset) | (src[i + 2] >> offset));
        dst[i + 3] ^= ((uint)((ulong)src[i + 4] << roffset) | (src[i + 3] >> offset));
        dst[i + 4] ^= ((uint)((ulong)src[i + 5] << roffset) | (src[i + 4] >> offset));
        dst[i + 5] ^= ((uint)((ulong)src[i + 6] << roffset) | (src[i + 5] >> offset));
        dst[i + 6] ^= ((uint)((ulong)src[i + 7] << roffset) | (src[i + 6] >> offset));
        dst[i + 7] ^= ((uint)((ulong)src[i + 8] << roffset) | (src[i + 7] >> offset));
    }
#else
    offset = amd_bitalign(offset, offset, 29U);

    it = amd_bitalign(it, it, 29U);

    for(i = 0; i < it; i += 8) {
        dst[i]     ^= amd_bitalign(src[i + 1], src[i],     offset);
        dst[i + 1] ^= amd_bitalign(src[i + 2], src[i + 1], offset);
        dst[i + 2] ^= amd_bitalign(src[i + 3], src[i + 2], offset);
        dst[i + 3] ^= amd_bitalign(src[i + 4], src[i + 3], offset);
        dst[i + 4] ^= amd_bitalign(src[i + 5], src[i + 4], offset);
        dst[i + 5] ^= amd_bitalign(src[i + 6], src[i + 5], offset);
        dst[i + 6] ^= amd_bitalign(src[i + 7], src[i + 6], offset);
        dst[i + 7] ^= amd_bitalign(src[i + 8], src[i + 7], offset);
    }
#endif
}

/* 32-byte XOR of 4-byte aligned memory to possibly unaligned memory */
void neoscrypt_xor32_au(void *restrict dstp, const void *restrict srcp,
  uint offset) {
    uint *dst = (uint *) dstp;
    uint *src = (uint *) srcp;
    uint roffset;

    /* OpenCL cannot shift uint by 32 to zero value */

#if (OLD_VLIW)
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
#else
    offset = amd_bitalign(offset, offset, 29U);
    roffset = 32U - offset;
    uint mask = amd_bitalign(0U, ~0U, offset);

    dst[0] ^= amd_bitalign(src[0], bitselect(0U,     src[0], mask), roffset);
    dst[1] ^= amd_bitalign(src[1], bitselect(src[0], src[1], mask), roffset);
    dst[2] ^= amd_bitalign(src[2], bitselect(src[1], src[2], mask), roffset);
    dst[3] ^= amd_bitalign(src[3], bitselect(src[2], src[3], mask), roffset);
    dst[4] ^= amd_bitalign(src[4], bitselect(src[3], src[4], mask), roffset);
    dst[5] ^= amd_bitalign(src[5], bitselect(src[4], src[5], mask), roffset);
    dst[6] ^= amd_bitalign(src[6], bitselect(src[5], src[6], mask), roffset);
    dst[7] ^= amd_bitalign(src[7], bitselect(src[6], src[7], mask), roffset);
    dst[8] ^= amd_bitalign(0U,     bitselect(src[7], 0U,     mask), roffset);
#endif
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

/* 64-byte XOR based block swapper */
void neoscrypt_swap64(void *restrict blkAp, void *restrict blkBp) {
    uint16 *blkA = (uint16 *) blkAp;
    uint16 *blkB = (uint16 *) blkBp;

    blkA[0] ^= blkB[0];
    blkB[0] ^= blkA[0];
    blkA[0] ^= blkB[0];
}

/* 256-byte XOR based block swapper */
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
#if (OLD_VLIW)
const __constant uint8 blake2s_IV4[1] = {
#else
static const __constant uint8 blake2s_IV4[1] = {
#endif
    (uint8)(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
};

#if (OLD_VLIW)
const __constant uchar blake2s_sigma[10][16] = {
#else
static const __constant uchar blake2s_sigma[10][16] = {
#endif
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


/* Salsa20/20 and ChaCha20/20 */

#define SALSA_CHACHA_CORE_SCALAR(Ys, Yc) \
    Ys.s4 ^= rotate(Ys.s0 + Ys.sc, 7U);  \
    Yc.s0 += Yc.s4; Yc.sc = rotate(Yc.sc ^ Yc.s0, 16U); \
    Ys.s8 ^= rotate(Ys.s4 + Ys.s0, 9U);  \
    Yc.s8 += Yc.sc; Yc.s4 = rotate(Yc.s4 ^ Yc.s8, 12U); \
    Ys.sc ^= rotate(Ys.s8 + Ys.s4, 13U); \
    Yc.s0 += Yc.s4; Yc.sc = rotate(Yc.sc ^ Yc.s0, 8U);  \
    Ys.s0 ^= rotate(Ys.sc + Ys.s8, 18U); \
    Yc.s8 += Yc.sc; Yc.s4 = rotate(Yc.s4 ^ Yc.s8, 7U);  \
    Ys.s9 ^= rotate(Ys.s5 + Ys.s1, 7U);  \
    Yc.s1 += Yc.s5; Yc.sd = rotate(Yc.sd ^ Yc.s1, 16U); \
    Ys.sd ^= rotate(Ys.s9 + Ys.s5, 9U);  \
    Yc.s9 += Yc.sd; Yc.s5 = rotate(Yc.s5 ^ Yc.s9, 12U); \
    Ys.s1 ^= rotate(Ys.sd + Ys.s9, 13U); \
    Yc.s1 += Yc.s5; Yc.sd = rotate(Yc.sd ^ Yc.s1, 8U);  \
    Ys.s5 ^= rotate(Ys.s1 + Ys.sd, 18U); \
    Yc.s9 += Yc.sd; Yc.s5 = rotate(Yc.s5 ^ Yc.s9, 7U);  \
    Ys.se ^= rotate(Ys.sa + Ys.s6, 7U);  \
    Yc.s2 += Yc.s6; Yc.se = rotate(Yc.se ^ Yc.s2, 16U); \
    Ys.s2 ^= rotate(Ys.se + Ys.sa, 9U);  \
    Yc.sa += Yc.se; Yc.s6 = rotate(Yc.s6 ^ Yc.sa, 12U); \
    Ys.s6 ^= rotate(Ys.s2 + Ys.se, 13U); \
    Yc.s2 += Yc.s6; Yc.se = rotate(Yc.se ^ Yc.s2, 8U);  \
    Ys.sa ^= rotate(Ys.s6 + Ys.s2, 18U); \
    Yc.sa += Yc.se; Yc.s6 = rotate(Yc.s6 ^ Yc.sa, 7U);  \
    Ys.s3 ^= rotate(Ys.sf + Ys.sb, 7U);  \
    Yc.s3 += Yc.s7; Yc.sf = rotate(Yc.sf ^ Yc.s3, 16U); \
    Ys.s7 ^= rotate(Ys.s3 + Ys.sf, 9U);  \
    Yc.sb += Yc.sf; Yc.s7 = rotate(Yc.s7 ^ Yc.sb, 12U); \
    Ys.sb ^= rotate(Ys.s7 + Ys.s3, 13U); \
    Yc.s3 += Yc.s7; Yc.sf = rotate(Yc.sf ^ Yc.s3, 8U);  \
    Ys.sf ^= rotate(Ys.sb + Ys.s7, 18U); \
    Yc.sb += Yc.sf; Yc.s7 = rotate(Yc.s7 ^ Yc.sb, 7U);  \
    Ys.s1 ^= rotate(Ys.s0 + Ys.s3, 7U);  \
    Yc.s0 += Yc.s5; Yc.sf = rotate(Yc.sf ^ Yc.s0, 16U); \
    Ys.s2 ^= rotate(Ys.s1 + Ys.s0, 9U);  \
    Yc.sa += Yc.sf; Yc.s5 = rotate(Yc.s5 ^ Yc.sa, 12U); \
    Ys.s3 ^= rotate(Ys.s2 + Ys.s1, 13U); \
    Yc.s0 += Yc.s5; Yc.sf = rotate(Yc.sf ^ Yc.s0, 8U);  \
    Ys.s0 ^= rotate(Ys.s3 + Ys.s2, 18U); \
    Yc.sa += Yc.sf; Yc.s5 = rotate(Yc.s5 ^ Yc.sa, 7U);  \
    Ys.s6 ^= rotate(Ys.s5 + Ys.s4, 7U);  \
    Yc.s1 += Yc.s6; Yc.sc = rotate(Yc.sc ^ Yc.s1, 16U); \
    Ys.s7 ^= rotate(Ys.s6 + Ys.s5, 9U);  \
    Yc.sb += Yc.sc; Yc.s6 = rotate(Yc.s6 ^ Yc.sb, 12U); \
    Ys.s4 ^= rotate(Ys.s7 + Ys.s6, 13U); \
    Yc.s1 += Yc.s6; Yc.sc = rotate(Yc.sc ^ Yc.s1, 8U);  \
    Ys.s5 ^= rotate(Ys.s4 + Ys.s7, 18U); \
    Yc.sb += Yc.sc; Yc.s6 = rotate(Yc.s6 ^ Yc.sb, 7U);  \
    Ys.sb ^= rotate(Ys.sa + Ys.s9, 7U);  \
    Yc.s2 += Yc.s7; Yc.sd = rotate(Yc.sd ^ Yc.s2, 16U); \
    Ys.s8 ^= rotate(Ys.sb + Ys.sa, 9U);  \
    Yc.s8 += Yc.sd; Yc.s7 = rotate(Yc.s7 ^ Yc.s8, 12U); \
    Ys.s9 ^= rotate(Ys.s8 + Ys.sb, 13U); \
    Yc.s2 += Yc.s7; Yc.sd = rotate(Yc.sd ^ Yc.s2, 8U);  \
    Ys.sa ^= rotate(Ys.s9 + Ys.s8, 18U); \
    Yc.s8 += Yc.sd; Yc.s7 = rotate(Yc.s7 ^ Yc.s8, 7U);  \
    Ys.sc ^= rotate(Ys.sf + Ys.se, 7U);  \
    Yc.s3 += Yc.s4; Yc.se = rotate(Yc.se ^ Yc.s3, 16U); \
    Ys.sd ^= rotate(Ys.sc + Ys.sf, 9U);  \
    Yc.s9 += Yc.se; Yc.s4 = rotate(Yc.s4 ^ Yc.s9, 12U); \
    Ys.se ^= rotate(Ys.sd + Ys.sc, 13U); \
    Yc.s3 += Yc.s4; Yc.se = rotate(Yc.se ^ Yc.s3, 8U);  \
    Ys.sf ^= rotate(Ys.se + Ys.sd, 18U); \
    Yc.s9 += Yc.se; Yc.s4 = rotate(Yc.s4 ^ Yc.s9, 7U);

#define SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c) \
    Y0s ^= rotate(Y3s + Y2s, (uint4)( 7,  7,  7,  7)); \
    Y0c += Y1c; Y3c = rotate(Y3c ^ Y0c, (uint4)(16, 16, 16, 16)); \
    Y1s ^= rotate(Y0s + Y3s, (uint4)( 9,  9,  9,  9)); \
    Y2c += Y3c; Y1c = rotate(Y1c ^ Y2c, (uint4)(12, 12, 12, 12)); \
    Y2s ^= rotate(Y1s + Y0s, (uint4)(13, 13, 13, 13)); \
    Y0c += Y1c; Y3c = rotate(Y3c ^ Y0c, (uint4)( 8,  8,  8,  8)); \
    Y3s ^= rotate(Y2s + Y1s, (uint4)(18, 18, 18, 18)); \
    Y2c += Y3c; Y1c = rotate(Y1c ^ Y2c, (uint4)( 7,  7,  7,  7)); \
    Y2s ^= rotate(Y3s.wxyz + Y0s.zwxy, (uint4)( 7,  7,  7,  7)); \
    Y0c += Y1c.yzwx; Y3c = rotate(Y3c ^ Y0c.yzwx, (uint4)(16, 16, 16, 16)); \
    Y1s ^= rotate(Y2s.wxyz + Y3s.zwxy, (uint4)( 9,  9,  9,  9)); \
    Y2c += Y3c.yzwx; Y1c = rotate(Y1c ^ Y2c.yzwx, (uint4)(12, 12, 12, 12)); \
    Y0s ^= rotate(Y1s.wxyz + Y2s.zwxy, (uint4)(13, 13, 13, 13)); \
    Y0c += Y1c.yzwx; Y3c = rotate(Y3c ^ Y0c.yzwx, (uint4)( 8,  8,  8,  8)); \
    Y3s ^= rotate(Y0s.wxyz + Y1s.zwxy, (uint4)(18, 18, 18, 18)); \
    Y2c += Y3c.yzwx; Y1c = rotate(Y1c ^ Y2c.yzwx, (uint4)( 7,  7,  7,  7));


void neoscrypt_salsa_chacha(uint16 *X) {
    uint i;

#if (SALSA_CHACHA_SCALAR)

    uint16 Ys = X[0], Yc = X[1];

#if (SALSA_CHACHA_UNROLL_LEVEL == 1)

    for(i = 0; i < 10; i++) {
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
    }

#elif (SALSA_CHACHA_UNROLL_LEVEL == 2)

    for(i = 0; i < 5; i++) {
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
    }

#elif (SALSA_CHACHA_UNROLL_LEVEL == 3)

    for(i = 0; i < 4; i++) {
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        if(i == 3) break;
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
    }

#elif (SALSA_CHACHA_UNROLL_LEVEL == 4)

    for(i = 0; i < 3; i++) {
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        if(i == 2) break;
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
     }

#else

    for(i = 0; i < 2; i++) {
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
        SALSA_CHACHA_CORE_SCALAR(Ys, Yc);
    }

#endif

    X[0] += Ys;
    X[1] += Yc;

#else /* SALSA_CHACHA_VECTOR */

    uint4 Y0s = (uint4)(X[0].s4, X[0].s9, X[0].se, X[0].s3);
    uint4 Y1s = (uint4)(X[0].s8, X[0].sd, X[0].s2, X[0].s7);
    uint4 Y2s = (uint4)(X[0].sc, X[0].s1, X[0].s6, X[0].sb);
    uint4 Y3s = (uint4)(X[0].s0, X[0].s5, X[0].sa, X[0].sf);

    uint4 Y0c = X[1].s0123;
    uint4 Y1c = X[1].s4567;
    uint4 Y2c = X[1].s89ab;
    uint4 Y3c = X[1].scdef;

#if (SALSA_CHACHA_UNROLL_LEVEL == 1)

    for(i = 0; i < 10; i++) {
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
    }

#elif (SALSA_CHACHA_UNROLL_LEVEL == 2)

    for(i = 0; i < 5; i++) {
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
    }

#elif (SALSA_CHACHA_UNROLL_LEVEL == 3)

    for(i = 0; i < 4; i++) {
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        if(i == 3) break;
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
    }

#elif (SALSA_CHACHA_UNROLL_LEVEL == 4)

    for(i = 0; i < 3; i++) {
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        if(i == 2) break;
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
     }

#else

    for(i = 0; i < 2; i++) {
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
        SALSA_CHACHA_CORE_VECTOR(Y0s, Y1s, Y2s, Y3s, Y0c, Y1c, Y2c, Y3c);
    }

#endif

    X[0] += (uint16)(Y3s.x, Y2s.y, Y1s.z, Y0s.w, Y0s.x, Y3s.y, Y2s.z, Y1s.w,
                     Y1s.x, Y0s.y, Y3s.z, Y2s.w, Y2s.x, Y1s.y, Y0s.z, Y3s.w);

    X[1] += (uint16)(Y0c, Y1c, Y2c, Y3c);

#endif
}


/* CodeXL only */
#if !(WORKSIZE)
#define WORKSIZE 128
#endif


/* FastKDF, a fast buffered key derivation function;
 * this algorithm makes extensive use of bytewise operations */

/* FastKDF (stretching) */
void neoscrypt_fastkdf_str(ulong16 *XZ) {

    uint i, bufptr, offset;

    uint4 *XZq = (uint4 *) &XZ[0];

    uchar *Aa = (uchar *) &XZq[0];
    uchar *Bb = (uchar *) &XZq[20];
    uint8 *T = (uint8 *)  &XZq[38];
    uint4 *t = (uint4 *)  &XZq[38];

    for(i = 0, bufptr = 0; i < 32; i++) {

        uint16 S;
        uint m[16];

        offset = bufptr & 0x03;
        neoscrypt_copy32(&m[0], &Bb[bufptr - offset], offset);

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

            neoscrypt_copy64(&m[0], &Aa[bufptr - offset], offset);

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

        neoscrypt_copy64(&m[0], &Aa[bufptr - offset], offset);

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

        offset = bufptr & 0x03;
        neoscrypt_xor32_au(&Bb[bufptr - offset], &T[0], offset);

        if(bufptr < 32U) {
            XZq[36] = XZq[20];
            XZq[37] = XZq[21];
            continue;
        }

        if(bufptr > 224U) {
            XZq[20] = XZq[36];
            XZq[21] = XZq[37];
        }

    }

    i = (256 - bufptr + 31) >> 5;
    neoscrypt_xor32_ua_it(&Aa[0], &Bb[bufptr - offset], offset, i);
    neoscrypt_xor32_ua_it(&Aa[i << 5], &Bb[(bufptr & 0x1FU) - offset], offset, 8U - i);

}

/* FastKDF (compressing) */
void neoscrypt_fastkdf_comp(ulong16 *XZ) {

    uint i, bufptr, offset;

    uint4 *XZq = (uint4 *) &XZ[0];

    uchar *Aa = (uchar *) &XZq[20];
    uchar *Bb = (uchar *) &XZq[0];
    uint8 *T = (uint8 *)  &XZq[18];
    uint4 *t = (uint4 *)  &XZq[18];

    for(i = 0, bufptr = 0; i < 32; i++) {

        uint16 S;
        uint m[16];

        offset = bufptr & 0x03;
        neoscrypt_copy32(&m[0], &Bb[bufptr - offset], offset);

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

            neoscrypt_copy64(&m[0], &Aa[bufptr - offset], offset);

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

        neoscrypt_copy64(&m[0], &Aa[bufptr - offset], offset);

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
        neoscrypt_xor32_au(&Bb[bufptr - offset], &T[0], offset);

        if(bufptr < 32U) {
            XZq[16] = XZq[0];
            XZq[17] = XZq[1];
            continue;
        }

        if(bufptr > 224U) {
            XZq[0] = XZq[16];
            XZq[1] = XZq[17];
        }

    }

    neoscrypt_xor32_ua(&Aa[0], &Bb[bufptr - offset], offset);

}


__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global const uint4 *restrict input, __global uint *restrict output,
  __global ulong16 *globalcache, const uint target) {
    uint j, k, l;

    uint glbid = get_global_id(0);
    uint grpid = get_group_id(0);
    __global ulong16 *G = (__global ulong16 *) &globalcache[mul24(grpid, (uint)(WORKSIZE << 9))];
    __global uint16 *Gh = (__global uint16 *) &G[0];

    uint lclid = glbid & (WORKSIZE - 1);

    ulong16 XZ[5];
    uint16 *XZh = (uint16 *) &XZ[0];
    uint4  *XZq = (uint4 *)  &XZ[0];
    uint   *XZi = (uint *)   &XZ[0];

    /* 1st FastKDF buffer initialisation */
    const uint4 mod = (uint4)(input[4].x, input[4].y, input[4].z, glbid);

    XZh[0] = XZh[5] = (uint16)(input[0], input[1], input[2], input[3]);
    XZh[1] = XZh[6] = (uint16)(mod, input[0], input[1], input[2]);
    XZh[2] = XZh[7] = (uint16)(input[3], mod, input[0], input[1]);
    XZh[3] = XZh[8] = (uint16)(input[2], input[3], mod, input[0]);
    XZq[16] = XZq[36] = input[0];
    XZq[17] = XZq[37] = input[1];
    XZq[18] = input[2];
    XZq[19] = input[3];

    /* FastKDF (stretching) */
    neoscrypt_fastkdf_str(XZ);

    /* blkcpy(Z, X) */
    XZh[6] = XZh[3];
    XZh[7] = XZh[3];
    XZh[4] = XZh[2];
    XZh[5] = XZh[2];
    XZh[2] = XZh[1];
    XZh[3] = XZh[1];
    XZh[1] = XZh[0];

    /* X = SMix(X) and Z = SMix(Z) */
    for(j = 0; j < 128; j++) {

        /* blkcpy(G, X/Z) */
        k = rotate(mad24(j, (uint)WORKSIZE, lclid), 2U);
        G[k]     = XZ[0];
        G[k + 1] = XZ[1];
        G[k + 2] = XZ[2];
        G[k + 3] = XZ[3];

        /* blkmix(X/Z) */
        XZ[0] ^= XZ[3];
        neoscrypt_salsa_chacha(&XZh[0]);
        XZ[1] ^= XZ[0];
        neoscrypt_salsa_chacha(&XZh[2]);
        XZ[2] ^= XZ[1];
        neoscrypt_salsa_chacha(&XZh[4]);
        XZ[3] ^= XZ[2];
        neoscrypt_salsa_chacha(&XZh[6]);
        XZ[1] ^= XZ[2];
        XZ[2] ^= XZ[1];
        XZ[1] ^= XZ[2];

    }

    for(j = 0; j < 128; j++) {

        /* integerify(X/Z) mod N */
        k = rotate(mad24((((uint *) XZ)[96] & 0x7F), (uint)WORKSIZE, lclid), 3U);
        l = rotate(mad24((((uint *) XZ)[112] & 0x7F), (uint)WORKSIZE, lclid), 3U);

        /* blkxor(X/Z, G) */
        XZh[0] ^= Gh[k];
        XZh[2] ^= Gh[k + 2];
        XZh[4] ^= Gh[k + 4];
        XZh[6] ^= Gh[k + 6];
        XZh[1] ^= Gh[l + 1];
        XZh[3] ^= Gh[l + 3];
        XZh[5] ^= Gh[l + 5];
        XZh[7] ^= Gh[l + 7];

        /* blkmix(X/Z) */
        XZ[0] ^= XZ[3];
        neoscrypt_salsa_chacha(&XZh[0]);
        XZ[1] ^= XZ[0];
        neoscrypt_salsa_chacha(&XZh[2]);
        XZ[2] ^= XZ[1];
        neoscrypt_salsa_chacha(&XZh[4]);
        XZ[3] ^= XZ[2];
        neoscrypt_salsa_chacha(&XZh[6]);
        XZ[1] ^= XZ[2];
        XZ[2] ^= XZ[1];
        XZ[1] ^= XZ[2];

    }

    /* blkxor(X, Z) */
    XZh[0] = XZh[0] ^ XZh[1];
    XZh[1] = XZh[2] ^ XZh[3];
    XZh[2] = XZh[4] ^ XZh[5];
    XZh[3] = XZh[6] ^ XZh[7];

    /* 2nd FastKDF buffer initialisation */
    XZq[16] = XZq[0];
    XZq[17] = XZq[1];

    XZh[5] = (uint16)(input[0], input[1], input[2], input[3]);
    XZh[6] = (uint16)(mod, input[0], input[1], input[2]);
    XZh[7] = (uint16)(input[3], mod, input[0], input[1]);
    XZh[8] = (uint16)(input[2], input[3], mod, input[0]);
    XZh[9] = XZh[5];

    /* FastKDF (compressing) */
    neoscrypt_fastkdf_comp(XZ);

#define NEOSCRYPT_FOUND (0xFF)
#ifdef cl_khr_global_int32_base_atomics
    #define SETFOUND(nonce) output[atomic_add(&output[NEOSCRYPT_FOUND], 1)] = nonce
#else
    #define SETFOUND(nonce) output[output[NEOSCRYPT_FOUND]++] = nonce
#endif

    if(XZi[87] <= target) SETFOUND(glbid);

    return;
}
