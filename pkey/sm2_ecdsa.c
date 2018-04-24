/*
 * Author Chen Gao
 * Created at 1/5/18
 *
 * This file sm2_ecdsa.c is part of ccs_engine.
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

#include <openssl/dsa.h>
#include <openssl/ecdsa.h>

#include "../err/ccs_err.h"
#include "../md/md_lcl.h"

/*
 * tbs contains Hash(za || M)
 */
// REVIEW tbs_len is useless
int
sm2_do_sign(DSA_SIG *dsa_sig,
            const unsigned char *tbs,
            size_t tbs_len,
            EC_KEY *static_key,
            EC_KEY *eph_key)
{
    int ok = 0;

    BN_CTX *bn_ctx = NULL;
    BIGNUM *kx = NULL, *r = NULL, *order = NULL, *tmp = NULL, *inv = NULL;
    const BIGNUM *kpriv = NULL, *dA = NULL;
    const EC_POINT *kpub = NULL;
    const EC_GROUP *group = NULL;

    if (dsa_sig == NULL || tbs == NULL || static_key == NULL)
        return ok;

    bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    kx = BN_CTX_get(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    order = BN_CTX_get(bn_ctx);
    tmp = BN_CTX_get(bn_ctx);
    kpriv = BN_CTX_get(bn_ctx);
    dA = BN_CTX_get(bn_ctx);
    //inv = BN_CTX_get(bn_ctx);

    //FIXME malloc check

    if (NULL == (group = EC_KEY_get0_group(eph_key)))
        goto err;

    if (NULL == (kpub = EC_KEY_get0_public_key(eph_key)))
        goto err;

    if (0 == EC_GROUP_get_order(group, order, bn_ctx))
        goto err;

    if (NULL == (kpriv = EC_KEY_get0_private_key(eph_key)))
        goto err;

    if (NULL == (dA = EC_KEY_get0_private_key(static_key)))
        goto err;

    EC_POINT_get_affine_coordinates_GFp(group, kpub, kx, NULL, bn_ctx);

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1 != EC_POINT_get_affine_coordinates_GFp(group,
                                                     kpub,
                                                     kx,
                                                     NULL,
                                                     bn_ctx))
            goto err;
    }
    else
    {
        if (1 != EC_POINT_get_affine_coordinates_GF2m(group,
                                                      kpub,
                                                      kx,
                                                      NULL,
                                                      bn_ctx))
            goto err;
    }

    if (NULL == (BN_bin2bn(tbs, SM3_DIGEST_LENGTH, r)))
        goto err;

    if (1 != BN_mod_add_quick(r, r, kx, order))
        goto err;

    if (1 != BN_add(tmp, r, kpriv))
        goto err;

    if (BN_is_zero(r) || !BN_cmp(order, tmp))
        goto err;

    if (NULL == (inv = BN_dup(dA)))
        goto err;

    if (1 != BN_add_word(inv, 1))
        goto err;

    BN_mod_inverse(inv, inv, order, bn_ctx);
    if (inv == NULL)
        goto err;

    if (1 != BN_mul(tmp, r, dA, bn_ctx))
        goto err;

    if (1 != BN_sub(tmp, kpriv, tmp))
        goto err;

    if (1 != BN_mod_mul(tmp, inv, tmp, order, bn_ctx))
        goto err;

    if (BN_is_zero(tmp))
        goto err;

    if (NULL == (dsa_sig->r = BN_dup(r)))
        goto err;

    if (NULL == (dsa_sig->s = BN_dup(tmp)))
        goto err;

    ok = 1;

    err:
    if (bn_ctx)
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }
    // inv was created by BN_dup()
    BN_free(inv);

    return ok;
}

/*
 * tbs contains H(za || M)
 */
int
sm2_do_verify(DSA_SIG *sig,
              EC_KEY *key,
              const unsigned char *tbs)

{
    int ok = 0;

    BN_CTX *bn_ctx = NULL;
    BIGNUM *tmp, *order, *e;
    const EC_GROUP *group;
    const EC_POINT *gen, *pub;
    EC_POINT *sg = NULL, *tpa = NULL;

    if (sig == NULL || key == NULL || tbs == NULL)
        goto err;

    if (NULL == (bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);
    tmp = BN_CTX_get(bn_ctx);
    order = BN_CTX_get(bn_ctx);
    e = BN_CTX_get(bn_ctx);

    if (e == NULL)
        goto err;

    if (NULL == (group = EC_KEY_get0_group(key)))
        goto err;

    if (1 != EC_GROUP_get_order(group, order, bn_ctx))
        goto err;

    if (NULL == (gen = EC_GROUP_get0_generator(group)))
        goto err;

    if (NULL == (pub = EC_KEY_get0_public_key(key)))
        goto err;

    // ---- setup complete ----

    BN_set_word(tmp, 1);
    if (-1 == BN_cmp(sig->r, tmp))
        goto err;

    if (-1 != BN_cmp(sig->r, order))
        goto err;

    if (-1 == BN_cmp(sig->s, tmp))
        goto err;

    if (-1 != BN_cmp(sig->s, order))
        goto err;

    if (1 != BN_mod_add(tmp, sig->r, sig->s, order, bn_ctx))
        goto err;

    if (1 == BN_is_zero(tmp))
        goto err;

    if (NULL == (sg = EC_POINT_new(group)))
        goto err;

    if (1 != EC_POINT_mul(group, sg, NULL, gen, sig->s, bn_ctx))
        goto err;

    if (NULL == (tpa = EC_POINT_new(group)))
        goto err;

    if (1 != EC_POINT_mul(group, tpa, NULL, pub, tmp, bn_ctx))
        goto err;

    if (1 != EC_POINT_add(group, tpa, sg, tpa, bn_ctx))
        goto err;

    if (1 != EC_POINT_get_affine_coordinates_GFp(group, tpa, tmp, NULL, bn_ctx))
        goto err;

    if (NULL == (BN_bin2bn(tbs, SM3_DIGEST_LENGTH, e)))
        goto err;

    if (1 != BN_mod_add(tmp, tmp, e, order, bn_ctx))
        goto err;

    if (0 == BN_cmp(tmp, sig->r))
        ok = 1;
    else
        ok = -1;

    err:
    EC_POINT_free(sg);
    EC_POINT_free(tpa);

    if (bn_ctx)
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }
    return ok;
}
