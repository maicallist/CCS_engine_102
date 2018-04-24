/*
 * Author Chen Gao
 * Created at 12/19/17
 *
 * This file sm3_hash.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_SM3_HASH_H
#define CCS_ENGINE_SM3_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef SM3_DIGEST_LENGTH
#define SM3_DIGEST_LENGTH 32
#endif

typedef struct
{
    uint8_t data[64];                       // 512 bit message block
    uint32_t data_len;
    uint_least64_t bit_len;
    uint32_t state[8];                      // registers
} md_ctx_t;

/**
 * initialize ctx structure to hold intermediate hash results
 *
 * @param ctx
 *      hash context
 */
void
sm3_init(md_ctx_t *ctx);

/**
 * hash one block of message
 * it may not be optimal or even possible to store entire message in memory,
 * so this method may be called repeatedly until there is no more message
 *
 * @param ctx
 *      hash context
 * @param data
 *      one block of message
 * @param length
 *      length of message
 */
void
sm3_update(md_ctx_t *ctx, const uint8_t data[], size_t length);

/**
 * pad & hash last block if message cannot fill the block, reverse hash to
 * big-endian as standard required , and store final hash to result array
 *
 * @param ctx
 *      hash context
 * @param hash
 *      final hash result
 */
void
sm3_final(md_ctx_t *ctx, uint8_t hash[]);

/**
 * wrapper for sm3_init, sm3_update and sm3_final
 *
 * @param d
 *      data to be hashed
 * @param n
 *      length of data in byte
 * @param md
 *      message digest result
 * @return
 */
void
sm3(const uint8_t *d, size_t n, uint8_t *md);

#ifdef __cplusplus
}
#endif

#endif //CCS_ENGINE_SM3_HASH_H
