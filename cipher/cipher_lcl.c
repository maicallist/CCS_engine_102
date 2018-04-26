/*
 * Author Chen Gao
 * Created at 3/30/18
 *
 * This file cipher_lcl.c is part of ccs_engine.
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

#include "cipher_lcl.h"

int
evp_sm4_gcm_init(EVP_CIPHER_CTX *ctx,
                 const unsigned char *key,
                 const unsigned char *iv,
                 int enc)
{
    if (!ctx)
        return 0;

    cipher_ctx_t *gctx = ctx->cipher_data;

    if (!key)
    {
        memzero(gctx, sizeof(cipher_ctx_t));
        gctx->len_iv = 12;
    }

    if (enc)
        ctx->encrypt = 1;
    else
        ctx->encrypt = 0;

    if (key && iv)
    {
        cipher_ctx_set_key(gctx, key);
        /*
         * iv length is either 12 or altered by ctrl function.
         */
        cipher_ctx_set_iv(gctx, iv);
        if (gctx->len_iv != 12)
        {
            ghash(ctx->oiv, gctx->hkey, NULL, 0, gctx->iv, gctx->len_iv);
        }
        else
        {
            memcpy(ctx->oiv, gctx->iv, 12);
            ctx->oiv[15] |= 0x1;
        }

        memcpy(ctx->iv, ctx->oiv, EVP_MAX_IV_LENGTH);
    }

    return 1;
}

int
evp_sm4_gcm_do_gcm(EVP_CIPHER_CTX *ctx,
                   unsigned char *out,
                   const unsigned char *in,
                   size_t inl)
{
    if (!ctx)
        return 0;

    if (!in && !out)
        return 0;

    cipher_ctx_t *gctx = ctx->cipher_data;

    if (in && out)
    {
        cipher_ctx_set_text(gctx, in, inl);
        if (ctx->encrypt)
            do_encrypt_sm4_128_gcm(&gctx->stx,
                                   in,
                                   out,
                                   inl,
                                   gctx->cfx,
                                   gctx->offset_cfx,
                                   ctx->iv);
        else
            do_decrypt_sm4_128_gcm(&gctx->stx,
                                   out,
                                   inl,
                                   gctx->cfx,
                                   gctx->offset_cfx,
                                   ctx->iv);

        gctx->offset_cfx = gctx->len_cfx;
        return (int) inl;
    }
    else if (!out)
    {
        cipher_ctx_set_aad(gctx, in, inl);
        return 1;
    }

    // only final is left [!in, out]
    if (!ctx->encrypt)
        return verify_tag_sm4_128_gcm(ctx->buf,
                                      gctx->len_tag,
                                      &gctx->stx,
                                      gctx->hkey,
                                      gctx->aad,
                                      gctx->len_aad,
                                      gctx->cfx,
                                      gctx->len_cfx,
                                      ctx->oiv);

    return 0;
}

int
evp_sm4_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
    destroy_cipher_ctx(ctx->cipher_data);
    return 1;
}

int
evp_sm4_gcm_set_asn1_param(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    return 1;
}

int
evp_sm4_gcm_get_asn1_param(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    return 1;
}

int
evp_sm4_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    if (!ctx)
        return 0;

    cipher_ctx_t *gctx = ctx->cipher_data;

    switch (type)
    {
        case EVP_CTRL_GCM_SET_IVLEN:
            if (arg <= 0)
                return 0;

            if (arg != gctx->len_iv)
            {
                if (gctx->iv)
                    OPENSSL_free(gctx->iv);
                gctx->iv = OPENSSL_malloc(arg);
                if (!gctx->iv)
                    return 0;
            }
            gctx->len_iv = (size_t) arg;
            gctx->mmu |= MASK_IV;
            return 1;

        case EVP_CTRL_GCM_SET_TAG:
            if (arg <= 0 || arg > 16 || ctx->encrypt)
                return 0;
            memcpy(ctx->buf, ptr, (size_t) arg);
            gctx->len_tag = (size_t) arg;

            return 1;

        case EVP_CTRL_GCM_GET_TAG:
            if (arg <= 0 || arg > 16 || !ctx->encrypt)
                return 0;
            do_tag_sm4_128_gcm(ctx->buf,
                               &gctx->stx,
                               gctx->hkey,
                               gctx->aad,
                               gctx->len_aad,
                               gctx->cfx,
                               gctx->len_cfx,
                               ctx->oiv);
            memcpy(ptr, ctx->buf, (size_t) arg);
            return 1;

        default:return 0;
    }
}
