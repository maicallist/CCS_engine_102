/*
 * Author Chen Gao
 * Created at 3/30/18
 *
 * This file cipher_lcl.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_CIPHER_LCL_H
#define CCS_ENGINE_CIPHER_LCL_H

#include <openssl/evp.h>

#include "cipher_ctx.h"
#include "mode_gcm.h"

static int sm4_cipher_ids = {NID_undef};

int
evp_sm4_gcm_init(EVP_CIPHER_CTX *ctx,
                 const unsigned char *key,
                 const unsigned char *iv,
                 int enc);

int
evp_sm4_gcm_do_gcm(EVP_CIPHER_CTX *ctx,
                   unsigned char *out,
                   const unsigned char *in,
                   size_t inl);

int
evp_sm4_gcm_cleanup(EVP_CIPHER_CTX *ctx);

int
evp_sm4_gcm_set_asn1_param(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type);

int
evp_sm4_gcm_get_asn1_param(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type);

int
evp_sm4_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static EVP_CIPHER evp_sm4_gcm_method =
    {
        NID_undef,
        1,              // allow us escape from EVP_EncryptFinal_ex()
        16,
        12,
        EVP_CIPH_GCM_MODE | EVP_CIPH_NO_PADDING | EVP_CIPH_CUSTOM_IV
            | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER,
        evp_sm4_gcm_init,
        evp_sm4_gcm_do_gcm,
        evp_sm4_gcm_cleanup,
        sizeof(cipher_ctx_t),
        evp_sm4_gcm_set_asn1_param,
        evp_sm4_gcm_get_asn1_param,
        evp_sm4_gcm_ctrl,
        NULL
    };

#endif //CCS_ENGINE_CIPHER_LCL_H
