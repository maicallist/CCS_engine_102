/*
 * Author Chen Gao
 * Created at 3/30/18
 *
 * This file mode_gcm.c is part of ccs_engine.
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

#include <stdint.h>
#include <stdio.h>
#include <openssl/crypto.h>

#include "mode_gcm.h"

#define R 0xe1

/**
 * increment a 128-bit counter by one
 * @param counter
 *      to be incremented
 */
static void
ctr128_inc(uint8_t *counter)
{
    uint32_t n = 16, c = 1;

    do
    {
        --n;
        c += counter[n];
        counter[n] = (uint8_t) c;
        c >>= 8;
    }
    while (n);
}

static void
right_shift(uint8_t *r, uint8_t *t)
{
    uint64_t lsb = u8_to_u64(&t[8]);
    uint64_t msb = u8_to_u64(t);

    lsb >>= 1;
    if (msb & 0x01)
        lsb |= 0x8000000000000000;
    msb >>= 1;

    u64_to_u8(msb, r);
    u64_to_u8(lsb, &r[8]);
}

/**
 * get bit from pos 0 to 127.
 * 0 being msb, 127 being lsb.
 * @param a
 *      8-bit string
 * @param i
 *      bit position
 * @return
 *      either 0 or 1
 */
static int
get_ith_bit(const uint8_t *a, int i)
{
    int index = i / 8;
    return (a[index] >> (7 - (i % 8))) & 1;
}

static void
xor_string(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
    uint64_t *a6 = (uint64_t *) a;
    uint64_t *b6 = (uint64_t *) b;
    uint64_t *r6 = (uint64_t *) r;
    *r6++ = *a6++ ^ *b6++;
    *r6 = *a6 ^ *b6;
}

/**
 * multiplication on bit vector in galois(2^128) field.
 *
 * poly = x^128 + x^7 + x^2 + x + 1
 * R = 0xe1 | 000...  128-bit
 *
 * @param r
 *      product
 * @param a
 *      operand
 * @param b
 *      operand
 */
static void
galois_mul(uint8_t *r, uint8_t *x, uint8_t *y)
{
#ifdef GALOIS_OPTZ
#else
    uint8_t z[16], v[16];
    memzero(z, 16);
    memcpy(v, x, 16);

    for (int i = 0; i < 128; ++i)
    {
        if (get_ith_bit(y, i))
        {
            xor_string(z, z, v);
        }

        if ((v[15] & 1) == 0)
        {
            right_shift(v, v);
        }
        else
        {
            right_shift(v, v);
            v[0] ^= R;
        }
    }

    memcpy(r, z, 16);
#endif
}

int
ghash(uint8_t *r,
      uint8_t *hkey,
      uint8_t *aad,
      size_t len_aad,
      uint8_t *cfx,
      size_t len_cfx)
{
    if (r == NULL || hkey == NULL)
    {
        // TODO log error
        return 0;
    }

    size_t m = 0, v = 0, n = 0, u = 0;

    if (len_aad)
    {
        m = len_aad / 16 + 1;
        v = len_aad % 16 * 8;
        if (v == 0)
        {
            v = 128;
            m--;
        }
    }

    if (len_cfx)
    {
        n = len_cfx / 16 + 1;
        u = len_cfx % 16 * 8;
        if (u == 0)
        {
            u = 128;
            n--;
        }
    }

    uint8_t x[16];
    memzero(x, 16);
    uint8_t tmp[16];

    uint8_t *ptr = aad;
    for (size_t i = 1; i < m; ++i, ptr += 16)
    {
        xor_string(x, x, ptr);
        galois_mul(x, x, hkey);
    }

    memzero(tmp, 16);
    memcpy(tmp, ptr, v / 8);
    xor_string(x, x, tmp);
    galois_mul(x, x, hkey);

    ptr = cfx;
    for (int i = 1; i < n; ++i, ptr += 16)
    {
        xor_string(x, x, ptr);
        galois_mul(x, x, hkey);
    }

    memzero(tmp, 16);
    memcpy(tmp, ptr, u / 8);
    xor_string(x, x, tmp);
    galois_mul(x, x, hkey);

    uint64_t la = len_aad * 8;
    uint64_t lc = len_cfx * 8;

    u64_to_u8(la, tmp);
    u64_to_u8(lc, &tmp[8]);

    xor_string(x, x, tmp);
    galois_mul(r, x, hkey);

    return 1;
}

int
do_encrypt_sm4_128_gcm(sm4_ctx_t *stx,
                       const uint8_t *plx,
                       uint8_t *cfx,
                       size_t len,
                       uint8_t *cfx_buf,
                       size_t cfx_offset,
                       uint8_t *iv)
{
    size_t n, u;
    n = len / 16 + 1;
    u = len % 16 * 8;

    if (u == 0)
    {
        u = 128;
        n--;
    }

    uint8_t tmp[16];
    memzero(tmp, 16);
    uint8_t *ptr_cfx = cfx_buf + cfx_offset;

#pragma omp parallel
    {
#pragma omp for
        for (int i = 1; i < n; ++i, plx += 16, ptr_cfx += 16)
#pragma omp task
        {
            ctr128_inc(iv);
            memcpy(tmp, iv, 16);
            encrypt_block_sm4_ecb(stx, tmp, tmp);
            xor_string(ptr_cfx, plx, tmp);
        }
    }

    ctr128_inc(iv);
    memcpy(tmp, iv, 16);
    encrypt_block_sm4_ecb(stx, tmp, tmp);
    xor_string(tmp, plx, tmp);
    memcpy(ptr_cfx, tmp, u / 8);

    memcpy(cfx, cfx_buf + cfx_offset, len);

    return 1;
}

int
do_decrypt_sm4_128_gcm(sm4_ctx_t *stx,
                       uint8_t *plx,
                       size_t len,
                       uint8_t *cfx_buf,
                       size_t cfx_offset,
                       uint8_t *iv)
{
    size_t n, u;
    n = len / 16 + 1;
    u = len % 16 * 8;

    if (u == 0)
    {
        u = 128;
        n--;
    }

    uint8_t tmp[16];
    memzero(tmp, 16);
    uint8_t *ptr_cfx = cfx_buf + cfx_offset;

#pragma omp parallel
    {
#pragma omp for
        for (int i = 1; i < n; ++i, plx += 16, ptr_cfx += 16)
#pragma omp task
        {
            ctr128_inc(iv);
            memcpy(tmp, iv, 16);
            encrypt_block_sm4_ecb(stx, tmp, tmp);
            xor_string(plx, ptr_cfx, tmp);
        }
    }

    ctr128_inc(iv);
    memcpy(tmp, iv, 16);
    encrypt_block_sm4_ecb(stx, tmp, tmp);
    xor_string(tmp, ptr_cfx, tmp);
    memcpy(plx, tmp, u / 8);

    return 1;
}

int
do_tag_sm4_128_gcm(uint8_t *r,
                   sm4_ctx_t *stx,
                   uint8_t *hkey,
                   uint8_t *aad,
                   size_t aadl,
                   uint8_t *cfx,
                   size_t cfxl,
                   uint8_t *oiv)
{
    uint8_t tmp[16];

    ghash(tmp, hkey, aad, aadl, cfx, cfxl);

    encrypt_block_sm4_ecb(stx, oiv, oiv);
    xor_string(tmp, tmp, oiv);

    memcpy(r, tmp, 16);
    return 1;
}

int
verify_tag_sm4_128_gcm(uint8_t *tag_in,
                       size_t tag_len,
                       sm4_ctx_t *stx,
                       uint8_t *hkey,
                       uint8_t *aad,
                       size_t aadl,
                       uint8_t *cfx,
                       size_t cfxl,
                       uint8_t *oiv)
{
    uint8_t tmp[16];
    ghash(tmp, hkey, aad, aadl, cfx, cfxl);

    encrypt_block_sm4_ecb(stx, oiv, oiv);
    xor_string(tmp, tmp, oiv);

    if (CRYPTO_memcmp(tmp, tag_in, tag_len))
        return -1;
    else
        return (int) tag_len;
}
