/*
 * Author Chen Gao
 * Created at 12/19/17
 *
 * This file md_lcl.c is part of ccs_engine.
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

#include <openssl/objects.h>

#include "md_lcl.h"

static EVP_MD evp_md_sm3 =
    {
        NID_undef,              // type
        NID_undef,              // pkey type
        SM3_DIGEST_LENGTH,      // digest output length
        EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
        evp_sm3_init,
        evp_sm3_update,
        evp_sm3_final,
        evp_sm3_copy,
        evp_sm3_cleanup,
        NULL,
        NULL,
        {NID_undef, NID_undef, 0, 0, 0},
        64,                     // block size
        sizeof(md_ctx_t),       // size of ctx->md_data
        NULL
    };

EVP_MD *
EVP_sm3()
{
    return &evp_md_sm3;
}

void
evp_md_sm3_set_nid(int nid)
{
    evp_md_sm3.type = nid;
    ccs_digest_ids = nid;
}

int
evp_sm3_init(EVP_MD_CTX *ctx)
{
    //ctx->update = evp_md_sm3.update;
    sm3_init(ctx->md_data);
    return 1;
}

int
evp_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    sm3_update(ctx->md_data, data, len);
    return 1;
}

int
evp_sm3_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
    sm3_final(ctx->md_data, digest);
    return 1;
}

int
evp_sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    if (to->md_data && from->md_data)
        memcpy(to->md_data, from->md_data, sizeof(from->md_data));
    return 1;
}

int
evp_sm3_cleanup(EVP_MD_CTX *ctx)
{
    if (ctx->md_data)
        memset(ctx->md_data, 0, sizeof(md_ctx_t));
    return 1;
}
