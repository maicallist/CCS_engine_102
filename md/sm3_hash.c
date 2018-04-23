/*
 * Author Chen Gao
 * Created at 12/19/17
 *
 * This file sm3_hash.c is part of ccs_engine.
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

#include <string.h>
#include <openssl/crypto.h>

#include "sm3_hash.h"

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define P1_63(i) ((w[i]) ^ (w[(i)+4]))

#define P0(x) ((x) ^ ROTL(x, 9) ^ ROTL(x, 17))
#define P1(x) ((x) ^ ROTL(x, 15) ^ ROTL(x, 23))
#define P1_X(i) ((w[(i)-16]) ^ (w[(i)-9]) ^ ROTL(w[(i)-3], 15))

#define T(i) (((i) < 16) ? 0x79cc4519 : 0x7a879d8a)
#define FF(x, y, z, i) (((i) < 16) ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((x) & (z)) | ((y) & (z))))
#define GG(x, y, z, i) (((i) < 16) ? ((x) ^ (y) ^ (z)) : ((x) & (y)) | (~(x) & (z)))

/**
 * hash one block of message, store intermediate result to SM3_CTX.state
 * called by update/final(depending on padding)
 *
 * @param ctx
 *      hash context
 * @param data
 *      one block of message to be hashed
 */
void
sm3_transform(md_ctx_t *ctx, const uint8_t data[])
{
    uint32_t w[68], wb[64];
    uint32_t i, j;

    // extend marker
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8)
            | (data[j + 3]);

    for (; i < 68; ++i)
        w[i] = P1(P1_X(i)) ^ ROTL(w[i - 13], 7) ^ w[i - 6];

    for (i = 0; i < 64; ++i)
        wb[i] = P1_63(i);

    // compress marker
    register uint32_t a, b, c, d, e, f, g, h;
    uint32_t ss1, ss2, tt1, tt2;
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i)
    {
        ss1 = ROTL(ROTL(a, 12) + e + ROTL(T(i), i % 32), 7);
        ss2 = ss1 ^ ROTL(a, 12);
        tt1 = FF(a, b, c, i) + d + ss2 + wb[i];
        tt2 = GG(e, f, g, i) + h + ss1 + w[i];
        d = c;
        c = ROTL(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = ROTL(f, 19);
        f = e;
        e = P0(tt2);
    }

    ctx->state[0] ^= a;
    ctx->state[1] ^= b;
    ctx->state[2] ^= c;
    ctx->state[3] ^= d;
    ctx->state[4] ^= e;
    ctx->state[5] ^= f;
    ctx->state[6] ^= g;
    ctx->state[7] ^= h;

}

void
sm3_init(md_ctx_t *ctx)
{
    memset(ctx->data, 0, 64);
    ctx->bit_len = 0;
    ctx->data_len = 0;

    ctx->state[0] = 0x7380166f;
    ctx->state[1] = 0x4914b2b9;
    ctx->state[2] = 0x172442d7;
    ctx->state[3] = 0xda8a0600;
    ctx->state[4] = 0xa96f30bc;
    ctx->state[5] = 0x163138aa;
    ctx->state[6] = 0xe38dee4d;
    ctx->state[7] = 0xb0fb0e4e;
}

void
sm3_update(md_ctx_t *ctx, const uint8_t data[], size_t length)
{
    uint32_t i;

    for (i = 0; i < length; ++i)
    {
        ctx->data[ctx->data_len++] = data[i];
        if (64 == ctx->data_len)
        {
            sm3_transform(ctx, ctx->data);
            ctx->data_len = 0;
            ctx->bit_len += 512;
        }
    }
}

void
sm3_final(md_ctx_t *ctx, uint8_t hash[])
{
    uint32_t i;
    i = ctx->data_len;
    if (i < 56)
    {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sm3_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    // pad message length as last 64 bits
    ctx->bit_len += ctx->data_len * 8;
    ctx->data[63] = ctx->bit_len;
    ctx->data[62] = ctx->bit_len >> 8;
    ctx->data[61] = ctx->bit_len >> 16;
    ctx->data[60] = ctx->bit_len >> 24;
    ctx->data[59] = ctx->bit_len >> 32;
    ctx->data[58] = ctx->bit_len >> 40;
    ctx->data[57] = ctx->bit_len >> 48;
    ctx->data[56] = ctx->bit_len >> 56;
    sm3_transform(ctx, ctx->data);

    // little-endian to big-endian
    for (i = 0; i < 4; ++i)
    {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}
