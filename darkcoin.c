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
#include "sha2.h"

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


void xhash(void *state, const void *input)
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
}

#include "kernel/opencl_rawsha256.cl"

uint32_t k[] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

void darkcoin_regenhash(struct work *work)
{
    uint32_t* pi32 = (const uint32_t*)&work->data.pok_header;

    for (int i = 0; i < 200000/4 + 16; i++)
        pi32[i] = bswap_32(pi32[i]);

    work->data.pok_header.nNonce = work->data.header.nNonce & ~0x3F;
    memcpy(work->data.pok_header.MinerSignature, work->data.header.MinerSignature, 65);

    sha256(&work->data.pok_header, 200000, work->data.header.hashWholeBlock);

    for (int i = 0; i < 200000/4 + 16; i++)
        pi32[i] = bswap_32(pi32[i]);

    uint32_t a = SH0;
    uint32_t b = SH1;
    uint32_t c = SH2;
    uint32_t d = SH3;
    uint32_t e = SH4;
    uint32_t f = SH5;
    uint32_t g = SH6;
    uint32_t h = SH7;
    uint32_t t, t1, t2;

    uint32_t hash[8] = {SH0, SH1, SH2, SH3, SH4, SH5, SH6, SH7};

    uint32_t high_nonce = work->data.header.nNonce & ~0x3F;

    const uint32_t* pPokData = (const uint32_t*)&work->data.pok_header;

    {
        uint32_t w[16];
        w[0] = bswap_32(high_nonce);
        int j;
        for (j = 1; j < 16; j++)
            w[j] = (pPokData[j]);
        SHA256()

     /* 	#pragma unroll
        for (int i = 0; i < 16; i++) {
            t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
            t2 = Maj(a, b, c) + Sigma0(a);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        #pragma unroll
        for (int i = 16; i < 64; i++) {
            w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
            t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
            t2 = Maj(a, b, c) + Sigma0(a);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }*/

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    int i;
    for (i = 1; i < 3126; i++)
    {
        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];
        f = hash[5];
        g = hash[6];
        h = hash[7];
        uint32_t w[16];
        int j;
        for (j = 0; j < 16; j++)
            w[j] = (pPokData[i*16 + j]);
        SHA256()

     /*	#pragma unroll
        for (int i = 0; i < 16; i++) {
            t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
            t2 = Maj(a, b, c) + Sigma0(a);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        #pragma unroll
        for (int i = 16; i < 64; i++) {
            w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
            t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
            t2 = Maj(a, b, c) + Sigma0(a);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }*/

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    uint64_t hashWholeBlock[4];
    hashWholeBlock[0] = (((uint64_t)hash[0]) << 32) | hash[1];
    hashWholeBlock[1] = (((uint64_t)hash[2]) << 32) | hash[3];
    hashWholeBlock[2] = (((uint64_t)hash[4]) << 32) | hash[5];
    hashWholeBlock[3] = (((uint64_t)hash[6]) << 32) | hash[7];




    xhash(work->hash, &work->data.header);
}
