/*
 * Author Chen Gao
 * Created at 3/30/18
 *
 * This file cipher_ctx.c is part of ccs_engine.
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

#include "cipher_ctx.h"

int
destroy_cipher_ctx(cipher_ctx_t *ctx)
{
    if (!ctx)
        return 0;
    if (!ctx->mmu)
        return 1;

    if (ctx->mmu & MASK_KEY)
        cipher_ctx_clear_key(ctx);
    if (ctx->mmu & MASK_IV)
        cipher_ctx_free_iv(ctx);
    if (ctx->mmu & MASK_AAD)
        cipher_ctx_free_aad(ctx);
    if (ctx->mmu & MASK_CFX)
        cipher_ctx_free_text(ctx);

    return 1;
}

int
cipher_ctx_set_key(cipher_ctx_t *ctx, const uint8_t *key)
{
    if (!ctx || !key)
        return 0;

    sm4_init(&ctx->stx, key);
    encrypt_block_sm4_ecb(&ctx->stx, ctx->hkey, ctx->hkey);

    ctx->mmu |= MASK_KEY;

    return 1;
}

int
cipher_ctx_clear_key(cipher_ctx_t *ctx)
{
    if (!ctx)
        return 0;

    memzero(ctx->hkey, CIPHER_KEY_SIZE);
    memzero(&ctx->stx, sizeof(sm4_ctx_t));

    ctx->mmu &= ~MASK_KEY;
    return 1;
}

int
cipher_ctx_set_iv(cipher_ctx_t *ctx, const uint8_t *iv)
{
    if (!ctx || !iv)
        return 0;

    if (!ctx->iv)
    {
        ctx->iv = malloc(sizeof(uint8_t) * ctx->len_iv);
        ctx->mmu |= MASK_IV;
    }
    memcpy(ctx->iv, iv, ctx->len_iv);

    return 1;
}

int cipher_ctx_free_iv(cipher_ctx_t *ctx)
{
    if (!ctx)
        return 0;

    free(ctx->iv);
    ctx->len_iv = 12;

    ctx->mmu &= ~MASK_IV;

    return 1;
}

int
cipher_ctx_set_aad(cipher_ctx_t *ctx, const uint8_t *aad, size_t len)
{
    if (!ctx || !aad)
        return 0;

    if (ctx->aad)
        ctx->aad = realloc(ctx->aad, sizeof(uint8_t) * (ctx->len_aad + len));
    else
        ctx->aad = malloc(sizeof(uint8_t) * len);

    if (!ctx->aad)
        return 0;

    memcpy(ctx->aad + ctx->len_aad, aad, len);
    ctx->len_aad += len;

    ctx->mmu |= MASK_AAD;

    return 1;
}

int
cipher_ctx_free_aad(cipher_ctx_t *ctx)
{
    if (!ctx)
        return 0;

    free(ctx->aad);
    ctx->len_aad = 0;

    ctx->mmu &= ~MASK_AAD;

    return 1;
}

/*
 * declare space
 * copy text if provided
 */
int
cipher_ctx_set_text(cipher_ctx_t *ctx, const uint8_t *text, size_t len)
{
    if (!ctx || len < 1)
        return 0;

    if (ctx->cfx)
        ctx->cfx = realloc(ctx->cfx, sizeof(uint8_t) * (ctx->len_cfx + len));
    else
        ctx->cfx = malloc(sizeof(uint8_t) * len);

    if (!ctx->cfx)
        return 0;

    if(text)
        memcpy(ctx->cfx + ctx->len_cfx, text, len);
    ctx->len_cfx += len;

    ctx->mmu |= MASK_CFX;

    return 1;
}

int
cipher_ctx_free_text(cipher_ctx_t *ctx)
{
    if (!ctx)
        return 0;

    free(ctx->cfx);
    ctx->len_cfx = 0;
    ctx->offset_cfx = 0;

    ctx->mmu &= ~MASK_CFX;

    return 1;
}