/*
 * Author Chen Gao
 * Created at 12/19/17
 *
 * This file md_lcl.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_MD_LCL_H
#define CCS_ENGINE_MD_LCL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>

#include "sm3_hash.h"

int
evp_sm3_init(EVP_MD_CTX *ctx);

int
evp_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t len);

int
evp_sm3_final(EVP_MD_CTX *ctx, unsigned char *digest);

int
evp_sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);

int
evp_sm3_cleanup(EVP_MD_CTX *ctx);

static int ccs_digest_ids =
    {
        NID_undef
    };

EVP_MD *
EVP_sm3();

void
evp_md_sm3_set_nid(int nid);

#ifdef __cplusplus
}
#endif

#endif //CCS_ENGINE_MD_LCL_H
