/*
 * Author Chen Gao
 * Created at 1/3/18
 *
 * This file pkey_lcl.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_PKEY_LCL_H
#define CCS_ENGINE_PKEY_LCL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/objects.h>

#include "sm2.h"

static int ccs_pkey_ids = {NID_undef};

/**
 * register public key functions to engine.
 *
 * @param nid
 *      id of SM2
 * @param pmeth
 *      public key function reference
 * @param flags
 *      no idea, FIXME
 * @return
 *      1 for success, 0 on error.
 */
int
evp_sm2_register_pmeth(int nid, EVP_PKEY_METHOD **pmeth, int flags);

/**
 * register sm2 asn.1 functions to engine.
 *
 * TODO ameth parameters
 * figure out the meaning of following params
 *
 * @param nid
 *      id of SM2
 * @param ameth
 *      ASN.1 function reference
 * @param pemstr
 *      FIXME
 * @param info
 *      FIXME
 * @return
 *      1 if success, 0 on error
 */
int
evp_sm2_register_ameth(int nid,
                       EVP_PKEY_ASN1_METHOD **ameth,
                       const char *pemstr,
                       const char *info);

#ifdef __cplusplus
}
#endif
#endif //CCS_ENGINE_PKEY_LCL_H
