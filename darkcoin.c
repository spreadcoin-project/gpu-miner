/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz
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
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "config.h"
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#include "sph/sph_blake.h"
#include "sph/sph_bmw.h"
#include "sph/sph_groestl.h"
#include "sph/sph_jh.h"
#include "sph/sph_keccak.h"
#include "sph/sph_skein.h"
#include "sph/sph_luffa.h"
#include "sph/sph_cubehash.h"
#include "sph/sph_shavite.h"
#include "sph/sph_simd.h"
#include "sph/sph_echo.h"

#define __constant
#include "kernel/blake.cl"
#undef __constant

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
    sph_blake512_context    blake1;
    sph_bmw512_context      bmw1;
    sph_groestl512_context  groestl1;
    sph_skein512_context    skein1;
    sph_jh512_context       jh1;
    sph_keccak512_context   keccak1;
    sph_luffa512_context    luffa1;
    sph_cubehash512_context cubehash1;
    sph_shavite512_context  shavite1;
    sph_simd512_context     simd1;
    sph_echo512_context     echo1;
} Xhash_context_holder;

Xhash_context_holder base_contexts;


void init_Xhash_contexts()
{
    sph_blake512_init(&base_contexts.blake1);
    sph_bmw512_init(&base_contexts.bmw1);
    sph_groestl512_init(&base_contexts.groestl1);
    sph_skein512_init(&base_contexts.skein1);
    sph_jh512_init(&base_contexts.jh1);
    sph_keccak512_init(&base_contexts.keccak1);
    sph_luffa512_init(&base_contexts.luffa1);
    sph_cubehash512_init(&base_contexts.cubehash1);
    sph_shavite512_init(&base_contexts.shavite1);
    sph_simd512_init(&base_contexts.simd1);
    sph_echo512_init(&base_contexts.echo1);
}

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static inline void
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}
/*

*/
inline void xhash(void *state, const void *input)
{
    init_Xhash_contexts();

    Xhash_context_holder ctx;

    uint32_t hashA[16], hashB[16];
    //blake-bmw-groestl-sken-jh-meccak-luffa-cubehash-shivite-simd-echo
    memcpy(&ctx, &base_contexts, sizeof(base_contexts));

    sph_blake512 (&ctx.blake1, input, 185);
    sph_blake512_close (&ctx.blake1, hashA);

    sph_bmw512 (&ctx.bmw1, hashA, 64);
    sph_bmw512_close(&ctx.bmw1, hashB);

    sph_groestl512 (&ctx.groestl1, hashB, 64);
    sph_groestl512_close(&ctx.groestl1, hashA);

    sph_skein512 (&ctx.skein1, hashA, 64);
    sph_skein512_close(&ctx.skein1, hashB);

    sph_jh512 (&ctx.jh1, hashB, 64);
    sph_jh512_close(&ctx.jh1, hashA);

    sph_keccak512 (&ctx.keccak1, hashA, 64);
    sph_keccak512_close(&ctx.keccak1, hashB);

    sph_luffa512 (&ctx.luffa1, hashB, 64);
    sph_luffa512_close (&ctx.luffa1, hashA);

    sph_cubehash512 (&ctx.cubehash1, hashA, 64);
    sph_cubehash512_close(&ctx.cubehash1, hashB);

    sph_shavite512 (&ctx.shavite1, hashB, 64);
    sph_shavite512_close(&ctx.shavite1, hashA);

    sph_simd512 (&ctx.simd1, hashA, 64);
    sph_simd512_close(&ctx.simd1, hashB);

    sph_echo512 (&ctx.echo1, hashB, 64);
    sph_echo512_close(&ctx.echo1, hashA);

    memcpy(state, hashA, 32);
    return;

}

typedef uint64_t sph_u64;

#define DEC64BE(x) be64toh(*(uint64_t*)(x))
#define SWAP4(x) be32toh(x)

inline void xhash2(void *state, const void *input, uint32_t gid)
{
    const uint8_t* block = input;

    sph_u64 H0 = SPH_C64(0x6A09E667F3BCC908), H1 = SPH_C64(0xBB67AE8584CAA73B);
    sph_u64 H2 = SPH_C64(0x3C6EF372FE94F82B), H3 = SPH_C64(0xA54FF53A5F1D36F1);
    sph_u64 H4 = SPH_C64(0x510E527FADE682D1), H5 = SPH_C64(0x9B05688C2B3E6C1F);
    sph_u64 H6 = SPH_C64(0x1F83D9ABFB41BD6B), H7 = SPH_C64(0x5BE0CD19137E2179);
    sph_u64 S0 = 0, S1 = 0, S2 = 0, S3 = 0;
    sph_u64 T0 = SPH_C64(0xFFFFFFFFFFFFFC00) + (80 << 3), T1 = 0xFFFFFFFFFFFFFFFF;;

    T0 = 1024;
    T1 = 0;

/*    if ((T0 = SPH_T64(T0 + 1024)) < 1024)
    {
        T1 = SPH_T64(T1 + 1);
    }*/
    sph_u64 M0, M1, M2, M3, M4, M5, M6, M7;
    sph_u64 M8, M9, MA, MB, MC, MD, ME, MF;
    sph_u64 V0, V1, V2, V3, V4, V5, V6, V7;
    sph_u64 V8, V9, VA, VB, VC, VD, VE, VF;
    M0 = DEC64BE(block +   0);
    M1 = DEC64BE(block +   8);
    M2 = DEC64BE(block +  16);
    M3 = DEC64BE(block +  24);
    M4 = DEC64BE(block +  32);
    M5 = DEC64BE(block +  40);
    M6 = DEC64BE(block +  48);
    M7 = DEC64BE(block +  56);
    M8 = DEC64BE(block +  64);
    M9 = DEC64BE(block +  72);
    MA = DEC64BE(block +  80);
    MA &= 0xFFFFFFFF00000000;
    MA ^= SWAP4(gid);
    MB = DEC64BE(block +  88);
    MC = DEC64BE(block +  96);
    MD = DEC64BE(block + 104);
    ME = DEC64BE(block + 112);
    MF = DEC64BE(block + 120);

    COMPRESS64;

    T0 = 1480;
    T1 = 0;

    M0 = DEC64BE(block + 128);
    M1 = DEC64BE(block + 136);
    M2 = DEC64BE(block + 144);
    M3 = DEC64BE(block + 152);
    M4 = DEC64BE(block + 160);
    M5 = DEC64BE(block + 168);
    M6 = DEC64BE(block + 176);
    M7 = (((sph_u64)block[184]) << 56) | 0x80000000000000;
    M8 = 0;
    M9 = 0;
    MA = 0;
    MB = 0;
    MC = 0;
    MD = 1;
    ME = 0;
    MF = 1480;

    COMPRESS64;

    uint64_t h8[8];

    h8[0] = be64toh(H0);
    h8[1] = be64toh(H1);
    h8[2] = be64toh(H2);
    h8[3] = be64toh(H3);
    h8[4] = be64toh(H4);
    h8[5] = be64toh(H5);
    h8[6] = be64toh(H6);
    h8[7] = be64toh(H7);

    memcpy(state, h8, 32);
    return;
}

// Spread-FIXME: implement
void darkcoin_regenhash(struct work *work)
{
    xhash(work->hash, work->whole_block);
}

// Spread-FIXME: implement
void darkcoin_regenhash2(struct work *work)
{
    xhash2(work->hash, work->whole_block, work->header.nNonce);
}
