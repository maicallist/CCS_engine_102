/*
 * Author Chen Gao
 * Created at 1/4/18
 *
 * This file sm2_ameth.c is part of ccs_engine.
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

#include <openssl/evp.h>
#include <openssl/err.h>

#include "../conf/objects.h"
#include "../err/ccs_err.h"
#include "pkey_lcl.h"

static void evp_sm2_free(EVP_PKEY *key);

int
evp_sm2_register_ameth(int nid,
                       EVP_PKEY_ASN1_METHOD **ameth,
                       const char *pemstr,
                       const char *info)
{

    *ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
    if (!*ameth)
    {
        CCSerr(CCS_F_ASN1_REGISTRATION, CCS_R_MALLOC_ERROR);
        return 0;
    }

    if (nid == OBJ_sn2nid(SN_sm2))
    {
        EVP_PKEY_asn1_set_free(*ameth, evp_sm2_free);
        EVP_PKEY_asn1_set_private(*ameth, NULL, NULL, NULL);
        EVP_PKEY_asn1_set_param(*ameth, NULL, NULL, NULL, NULL, NULL, NULL);
        EVP_PKEY_asn1_set_public(*ameth, NULL, NULL, NULL, NULL, NULL, NULL);
        EVP_PKEY_asn1_set_ctrl(*ameth, NULL);
    }
    else
    {
        CCSerr(CCS_F_ASN1_REGISTRATION, CCS_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }
    return 1;
}

static void
evp_sm2_free(EVP_PKEY *key)
{
    if (key->pkey.ec)
    {
        EC_KEY_free(key->pkey.ec);
    }
}