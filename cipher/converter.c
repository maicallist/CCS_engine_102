/*
 * Author Chen Gao
 * Created at 3/14/18
 *
 * This file converter.c is part of ccs_engine.
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

#include "converter.h"

uint32_t
u8_to_u32(const uint8_t in[4])
{
    return in[0] << 24 | in[1] << 16 | in[2] << 8 | in[3];
}

void
u8_to_u32_list(const uint8_t *in, size_t len_in, uint32_t *out)
{
    for (; len_in; len_in -= 4, ++out, in += 4)
    {
        *out = u8_to_u32(in);
    }
}

uint64_t
u8_to_u64(const uint8_t *in)
{
    uint64_t r = (uint64_t) in[0] << 56 |
        (uint64_t) in[1] << 48 |
        (uint64_t) in[2] << 40 |
        (uint64_t) in[3] << 32 |
        (uint64_t) in[4] << 24 |
        (uint64_t) in[5] << 16 |
        (uint64_t) in[6] << 8 |
        (uint64_t) in[7];
    return r;
}

void
u32_to_u8(uint32_t in, uint8_t out[4])
{
    out[0] = (uint8_t) (in >> 24);
    out[1] = (uint8_t) (in >> 16);
    out[2] = (uint8_t) (in >> 8);
    out[3] = (uint8_t) (in);
}

void
u32_to_u8_list(uint32_t *in, size_t len_in32, uint8_t *out)
{
    for (; len_in32; --len_in32, ++in, out += 4)
    {
        u32_to_u8(*in, out);
    }
}

void
u64_to_u8(uint64_t in, uint8_t *out)
{

    out[0] = (uint8_t) (in >> 56);
    out[1] = (uint8_t) (in >> 48);
    out[2] = (uint8_t) (in >> 40);
    out[3] = (uint8_t) (in >> 32);
    out[4] = (uint8_t) (in >> 24);
    out[5] = (uint8_t) (in >> 16);
    out[6] = (uint8_t) (in >> 8);
    out[7] = (uint8_t) in;
}