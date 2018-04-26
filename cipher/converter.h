/*
 * Author Chen Gao
 * Created at 3/14/18
 *
 * This file converter.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_CONVERTER_H
#define CCS_ENGINE_CONVERTER_H

#include <stdint.h>
#include <stdlib.h>

/**
 * four 8-bit bytes to one 32-bit word
 * @param in
 *      byte to be converted
 * @return
 *      32-bit word
 */
uint32_t
u8_to_u32(const uint8_t in[4]);

/**
 * 8-bit bytes to multiple 32-bit words
 * @param in
 *      8-bit string
 * @param len_in
 *      length of [in] in byte
 * @param out
 *      32-bit word list
 * @note
 *      [out] must have sufficient space
 */
void
u8_to_u32_list(const uint8_t *in, size_t len_in, uint32_t *out);

/**
 * 8-bit string to one 64-bit word
 * @param in
 *      8-bit string
 * @return
 *      64-bit word
 */
uint64_t
u8_to_u64(const uint8_t *in);

/**
 * one 32-bit word to four 8-bit bytes
 * @param in
 *      32-bit word
 * @param out
 *      8-bit string
 */
void
u32_to_u8(uint32_t in, uint8_t out[4]);

/**
 * multiple 32-bit word to 8-bit bytes
 * @param in
 *      32-bit word
 * @param len_in32
 *      length of [in] in 32 bit word
 * @param out
 *      8-bit string
 */
void
u32_to_u8_list(uint32_t *in, size_t len_in32, uint8_t *out);

/**
 * one 64-bit word to 8-bit string
 * @param in
 *      64-bit word
 * @param out
 *      8-bit string
 */
void
u64_to_u8(uint64_t in, uint8_t *out);

#endif //CCS_ENGINE_CONVERTER_H
