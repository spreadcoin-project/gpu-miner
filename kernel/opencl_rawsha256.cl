/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-256
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef _RAWSHA256_H
#define _RAWSHA256_H

#include "opencl_device_info.cl"
#include "opencl_sha256.cl"

//SHA256 constants.
#define SH0      0x6a09e667U
#define SH1      0xbb67ae85U
#define SH2      0x3c6ef372U
#define SH3      0xa54ff53aU
#define SH4      0x510e527fU
#define SH5      0x9b05688cU
#define SH6      0x1f83d9abU
#define SH7      0x5be0cd19U

//Constants.
#define RAW_PLAINTEXT_LENGTH    56      /* 55 characters + 0x80 */
#define CISCO_PLAINTEXT_LENGTH  26      /* 25 characters + 0x80 */

#define BUFFER_SIZE             56      /* RAW_PLAINTEXT_LENGTH multiple of 4 */
#define CIPHERTEXT_LENGTH       64
#define BINARY_SIZE             4
#define FULL_BINARY_SIZE        32
#define BINARY_ALIGN            4
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define STEP			0
#define SEED			1024

#define KEYS_PER_CORE_CPU       65536
#define KEYS_PER_CORE_GPU       512

//Data types.
/*typedef union {
    uint8_t                     mem_08[4];
    uint16_t                    mem_16[2];
    uint32_t                    mem_32[1];
} buffer_32;

typedef struct {
    uint32_t                    v[8];           //256 bits
} sha256_hash;

typedef struct {
    uint32_t                    buflen;
    buffer_32                   buffer[16];     //512 bits
} sha256_ctx;*/
/*
#ifndef _OPENCL_COMPILER
    static const char * warn[] = {
        "pass xfer: "  ,  ", crypt: "    ,  ", result xfer: ",  ", index xfer: "
};
#endif*/

#endif  /* _RAWSHA256_H */
