/*
 * Author Chen Gao
 * Created at 23 Apr 2018
 *
 * This file engine.c is part of ccs_engine.
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

#include <openssl/engine.h>
#include "err/ccs_err.h"
#include "md/md_lcl.h"
#include "conf/objects.h"
#include "pkey/pkey_lcl.h"
#include "pkey/ec_param.h"

static const char *engine_id = "ccs";
static const char *engine_name = "ccs_engine";

static EVP_PKEY_METHOD *sm2_pmeth = NULL;
static EVP_PKEY_ASN1_METHOD *sm2_ameth = NULL;

static int
ccs_engine_init(ENGINE *e)
{
    CCSerr(CCS_F_RESERVED, CCS_R_RESERVED);
    return 1;
}

static int
ccs_engine_finish(ENGINE *e)
{
    return 1;
}

static int
ccs_engine_destroy(ENGINE *e)
{
    return 1;
}

static int
ccs_digest_selector(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    if (!digest)
    {
        *nids = &ccs_digest_ids;
        return 1; /* one algor available */
    }

    if (nid == OBJ_sn2nid(SN_sm3))
    {
        *digest = EVP_sm3();
        return 1;
    }

    CCSerr(CCS_F_MD_SELECT, CCS_R_UNSUPPORTED_ALGORITHM);
    *digest = NULL;

    return 0;
}

static int
evp_sm2_pkey_selector(ENGINE *e,
                      EVP_PKEY_METHOD **pmeth,
                      const int **nids,
                      int nid)
{
    if (!pmeth)
    {
        *nids = &ccs_pkey_ids;
        return 3; /* three available */
    }

    if (nid == OBJ_sn2nid(SN_sm2))
    {
        *pmeth = sm2_pmeth;
        return 1;
    }

    CCSerr(CCS_F_PKEY_SELECT, CCS_R_UNSUPPORTED_ALGORITHM);
    *pmeth = NULL;
    return 0;
}

static int
evp_sm2_asn1_selector(ENGINE *e,
                      EVP_PKEY_ASN1_METHOD **ameth,
                      const int **nids,
                      int nid)
{
    if (!ameth)
    {
        *nids = &ccs_pkey_ids;
        return 1; /* one available */
    }

    if (nid == OBJ_sn2nid(SN_sm2))
    {
        *ameth = sm2_ameth;
        return 1;
    }

    CCSerr(CCS_F_ASN1_SELECT, CCS_R_UNSUPPORTED_ALGORITHM);
    *ameth = NULL;
    return 0;
}

static int
bind(ENGINE *e, const char *d)
{
    if (!ENGINE_set_id(e, engine_id)
        || !ENGINE_set_name(e, engine_name)
        || !ENGINE_set_init_function(e, ccs_engine_init)
        || !ENGINE_set_finish_function(e, ccs_engine_finish)
        || !ENGINE_set_destroy_function(e, ccs_engine_destroy))
        return 0;

    int nid = OBJ_create(OID_sm3, SN_sm3, LN_sm3);
    evp_md_sm3_set_nid(nid);
    EVP_add_digest(EVP_sm3());

    if (!ENGINE_set_digests(e, ccs_digest_selector))
        return 0;

    ec_param_fp_t *param = ec_param_fp_set;
    nid = OBJ_create(OID_gost_cc_curve, SN_gost_cc_curve, LN_gost_cc_curve);
    param++->nid = nid;

    nid = OBJ_create(OID_sm2_test_curve, SN_sm2_test_curve, LN_sm2_test_curve);
    param++->nid = nid;

    nid = OBJ_create(OID_sm2_param_def, SN_sm2_param_def, LN_sm2_param_def);
    param->nid = nid;

    nid = OBJ_create(OID_sm2, SN_sm2, LN_sm2);
    ccs_pkey_ids = nid;

    evp_sm2_register_pmeth(nid, &sm2_pmeth, 0);
    evp_sm2_register_ameth(nid, &sm2_ameth, "SM2 AMETH", "SM2 ASN METHOD");
    if (!ENGINE_set_pkey_meths(e, evp_sm2_pkey_selector))
    {
        printf("Unable to set pkey functions.\n");
        return 0;
    }

    if (!ENGINE_set_pkey_asn1_meths(e, evp_sm2_asn1_selector))
    {
        printf("Unable to set asn1 functions.\n");
        return 0;
    }


    ERR_load_CCS_strings();

    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
