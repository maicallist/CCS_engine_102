/*
 * Author Chen Gao
 * Created at 3/30/18
 *
 * This file cipher_ctx.h is part of ccs_engine.
 *
 * ccs_engine is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ccs_engine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ccs_engine.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef CCS_ENGINE_CIPHER_CTX_H
#define CCS_ENGINE_CIPHER_CTX_H

#include <stdlib.h>
#include <stdint.h>
#include <memory.h>

#include "converter.h"
#include "sm4_cipher.h"

#define CIPHER_KEY_SIZE         16

#define MASK_KEY                (1U)
#define MASK_IV                 (1U << 1)
#define MASK_AAD                (1U << 2)
#define MASK_CFX                (1U << 3)

#define memzero(loc, len) memset((loc), 0, (len))
#define clear_free(loc, len) memzero(loc, len); free(loc); (loc) = NULL

struct cipher_ctx_s
{
    /*
     * tracking memory allocation.
     * bit 1 indicates data is assigned.
     *
     *       MSB    0 0 0 0 0 0 0 0     LSB
     *              | | | | | | | |
     *              | | | | | | | - - - key
     *              | | | | | | - - - - iv
     *              | | | | | - - - - - aad
     *              | | | | - - - - - - cfx
     *              | | | - - - - - - - RESERVED
     *              | | - - - - - - - - RESERVED
     *              | - - - - - - - - - RESERVED
     *              - - - - - - - - - - RESERVED
     */
    uint8_t mmu;

    uint8_t hkey[16];

    uint8_t *iv;
    size_t len_iv;

    uint8_t *aad;
    size_t len_aad;

    uint8_t *cfx;
    size_t len_cfx;
    size_t offset_cfx;

    size_t len_tag;

    sm4_ctx_t stx;
};

typedef struct cipher_ctx_s cipher_ctx_t;

int
destroy_cipher_ctx(cipher_ctx_t *ctx);

int
cipher_ctx_set_key(cipher_ctx_t *ctx, const uint8_t *key);

int
cipher_ctx_clear_key(cipher_ctx_t *ctx);

int
cipher_ctx_set_iv(cipher_ctx_t *ctx, const uint8_t *iv);

int
cipher_ctx_free_iv(cipher_ctx_t *ctx);

int
cipher_ctx_set_aad(cipher_ctx_t *ctx, const uint8_t *aad, size_t len);

int
cipher_ctx_free_aad(cipher_ctx_t *ctx);

int
cipher_ctx_set_text(cipher_ctx_t *ctx, const uint8_t *text, size_t len);

int
cipher_ctx_free_text(cipher_ctx_t *ctx);

#endif //CCS_ENGINE_CIPHER_CTX_H
