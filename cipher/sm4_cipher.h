/*
 * Author Chen Gao
 * Created at 3/21/18
 *
 * This file sm4_cipher.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_SM4_CIPHER_H
#define CCS_ENGINE_SM4_CIPHER_H

#include <stdlib.h>
#include <stdint.h>
#include <memory.h>

typedef struct
{
    uint32_t k[36];
} sm4_ctx_t;

void
sm4_init(sm4_ctx_t *stx, const uint8_t *k8);

/**
 * encrypt one block
 * @param stx
 *      key expansion context
 * @param in
 *      plaintext
 * @param out
 *      ciphertext
 *
 */
void
encrypt_block_sm4_ecb(sm4_ctx_t *stx, uint8_t *in, uint8_t *out);

void
decrypt_block_sm4_ecb(sm4_ctx_t *stx, uint8_t *in, uint8_t *out);
#endif //CCS_ENGINE_SM4_CIPHER_H
