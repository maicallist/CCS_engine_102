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

static int ccs_cipher_ids = {NID_undef};

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

EVP_CIPHER *
EVP_sm4_128_gcm();

void
evp_cipher_set_nid(int nid);

#endif //CCS_ENGINE_CIPHER_LCL_H
