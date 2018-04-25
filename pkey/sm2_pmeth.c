/*
 * Author Chen Gao
 * Created at 1/3/18
 *
 * This file sm2_pmeth.c is part of ccs_engine.
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
#include <openssl/err.h>
#include <openssl/engine.h>

#include "../err/ccs_err.h"
#include "../conf/objects.h"
#include "pkey_lcl.h"
#include "sm2.h"
#include "ec_param.h"
#include "../md/sm3_hash.h"

#if DEBUG
/*
 * 83a2 : ECDH random for user A
 * 33fe : ECDH random for user B
 * 128b : ECDSA signing private key
 * 6cb2 : ECDSA random
 * 128b : ECDSA verify private key
 * 5927 : ECIES encrypt private
 * 5927 : ECIES decrypt private
 */

const char *debug_priv_key[] =
    {"83a2c9c8b96e5af70bd480b472409a9a327257f1ebb73f5b073354b248668563",
     "33fe21940342161c55619c4a0c060293d543c80af19748ce176d83477de71c80",
     "128b2fa8bd433c6c068c8d803dff79792a519a55171b1b650c23661d15897263",
     "6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f",
     "128b2fa8bd433c6c068c8d803dff79792a519a55171b1b650c23661d15897263",
     "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21",
     "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8",
     NULL};
int debug_index = 0;
#endif

// ecdh

static int
evp_sm2_init(EVP_PKEY_CTX *ctx);

static int
evp_sm2_copy(EVP_PKEY_CTX *to, EVP_PKEY_CTX *from);

static void
evp_sm2_cleanup(EVP_PKEY_CTX *ctx);

static int
evp_sm2_paramgen_init(EVP_PKEY_CTX *ctx);

static int
evp_sm2_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

static int
evp_sm2_keygen_init(EVP_PKEY_CTX *ctx);

static int
evp_sm2_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

static int
evp_sm2_encrypt_init(EVP_PKEY_CTX *ctx);

static int
evp_sm2_encrypt(EVP_PKEY_CTX *ctx,
                unsigned char *out,
                size_t *out_len,
                const unsigned char *in,
                size_t in_len);

static int
evp_sm2_decrypt_init(EVP_PKEY_CTX *ctx);

static int
evp_sm2_decrypt(EVP_PKEY_CTX *ctx,
                unsigned char *out,
                size_t *out_len,
                const unsigned char *in,
                size_t in_len);

static int
evp_sm2_derive_init(EVP_PKEY_CTX *ctx);

static int
evp_sm2_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *key_len);

static int
evp_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);

static int
evp_sm2_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value);

static int
evp_sm2_fill_params(EC_KEY *ec_key, int nid_curve);

static int
evp_sm2_compute_public(EC_KEY *ec_key);

// ecdsa

static int
evp_sm2_sign(EVP_PKEY_CTX *ctx,
             unsigned char *sig,
             size_t *sig_len,
             const unsigned char *tbs,
             size_t tbs_len);

static int
evp_sm2_verify(EVP_PKEY_CTX *ctx,
               const unsigned char *bin_sig,
               size_t sig_len,
               const unsigned char *tbs,
               size_t tbs_len);

//FIXME
//all wrapper should check pass in params

int
evp_sm2_register_pmeth(int nid, EVP_PKEY_METHOD **pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(nid, flags);

    if (!*pmeth)
    {
        CCSerr(CCS_F_PKEY_REGISTRATION, CCS_R_MALLOC_ERROR);
        return 0;
    }

    if (nid == OBJ_sn2nid(SN_sm2))
    {
        EVP_PKEY_meth_set_init(*pmeth, evp_sm2_init);
        EVP_PKEY_meth_set_copy(*pmeth, evp_sm2_copy);
        EVP_PKEY_meth_set_cleanup(*pmeth, evp_sm2_cleanup);

        EVP_PKEY_meth_set_paramgen(*pmeth,
                                   evp_sm2_paramgen_init,
                                   evp_sm2_paramgen);
        EVP_PKEY_meth_set_keygen(*pmeth, evp_sm2_keygen_init, evp_sm2_keygen);

        EVP_PKEY_meth_set_sign(*pmeth, NULL, evp_sm2_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, evp_sm2_verify);

        EVP_PKEY_meth_set_encrypt(*pmeth,
                                  evp_sm2_encrypt_init,
                                  evp_sm2_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth,
                                  evp_sm2_decrypt_init,
                                  evp_sm2_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth, evp_sm2_derive_init, evp_sm2_derive);
        EVP_PKEY_meth_set_ctrl(*pmeth, evp_sm2_ctrl, evp_sm2_ctrl_str);
        return 1;
    }

    CCSerr(CCS_F_PKEY_REGISTRATION, CCS_R_UNSUPPORTED_ALGORITHM);

    return 0;
}

static int
evp_sm2_init(EVP_PKEY_CTX *ctx)
{
    pkey_ctx_t *sm2_ctx = OPENSSL_malloc(sizeof(pkey_ctx_t));
    if (sm2_ctx == NULL)
    {
        CCSerr(CCS_F_PKEY_CTX_INIT, CCS_R_MALLOC_ERROR);
        return 0;
    }
    sm2_ctx->curve_id = OBJ_sn2nid(SN_sm2_test_curve);
    sm2_ctx->static_my_key = NULL;
    sm2_ctx->static_peer_pub = NULL;
    sm2_ctx->za = NULL;
    sm2_ctx->zb = NULL;
    EVP_PKEY_CTX_set_data(ctx, sm2_ctx);

    return 1;
}

static int
evp_sm2_copy(EVP_PKEY_CTX *to, EVP_PKEY_CTX *from)
{
    pkey_ctx_t *to_data, *from_data;

    to_data = EVP_PKEY_CTX_get_data(to);
    from_data = EVP_PKEY_CTX_get_data(from);

    if (to_data && from_data)
        *to_data = *from_data;

    return 1;
}

static void
evp_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
    pkey_ctx_t *data = EVP_PKEY_CTX_get_data(ctx);
    if (data)
    {
        OPENSSL_free(data);
        data = NULL;
    }
}

static int
evp_sm2_paramgen_init(EVP_PKEY_CTX *ctx)
{
    return 1;
}

static int
evp_sm2_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    pkey_ctx_t *data = EVP_PKEY_CTX_get_data(ctx);

    if (data->curve_id == NID_undef)
    {
        CCSerr(CCS_F_EC_PARAMETER_GEN, CCS_R_UNDEF_CURVE_ID);
        return 0;
    }

    EC_KEY *ec_key = NULL;
    ec_key = EC_KEY_new();

    if (1 != evp_sm2_fill_params(ec_key, data->curve_id))
    {
        CCSerr(CCS_F_EC_PARAMETER_GEN, CCS_R_EC_PARAMETER_ERROR);
        EC_KEY_free(ec_key);
        return 0;
    }

    if (0 == EVP_PKEY_assign(pkey, OBJ_sn2nid(SN_sm2), ec_key))
    {
        CCSerr(CCS_F_EC_PARAMETER_GEN, CCS_R_EC_PARAMETER_ERROR);
        return 0;
    }

    return 1;
}

static int
evp_sm2_keygen_init(EVP_PKEY_CTX *ctx)
{
    return 1;
}

static int
evp_sm2_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec_key;
    if (1 != evp_sm2_paramgen(ctx, pkey))
    {
        CCSerr(CCS_F_EC_KEY_GEN, CCS_R_EC_PARAMETER_ERROR);
        return 0;
    }
    ec_key = EVP_PKEY_get0(pkey);

    BIGNUM *order = BN_new(), *d = BN_new();
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_GROUP_get_order(group, order, NULL);

#if DEBUG
    const char *debug_key;
    if (NULL == (debug_key = debug_priv_key[debug_index++]))
        return 0;
    BN_hex2bn(&d, debug_key);
#else
    do
    {
        if (!BN_rand_range(d, order))
        {
            CCSerr(CCS_F_EC_KEY_GEN, CCS_R_MALLOC_ERROR);
            return 0;
        }
    }
    while (BN_is_zero(d));
#endif

    if (1 != EC_KEY_set_private_key(ec_key, d))
    {
        CCSerr(CCS_F_EC_KEY_GEN, CCS_R_PKEY_SET_ERROR);
        return 0;
    }

    BN_free(order);
    BN_clear_free(d);

    return evp_sm2_compute_public(ec_key);
}

static int
evp_sm2_encrypt_init(EVP_PKEY_CTX *ctx)
{
    return 1;
}

static int
evp_sm2_encrypt(EVP_PKEY_CTX *ctx,
                unsigned char *out,
                size_t *out_len,
                const unsigned char *in,
                size_t in_len)
{
    int ok = 0;

    if (out_len == NULL)
    {
        CCSerr(CCS_F_ECIES_ENCRYPT, CCS_R_NULL_REFERENCE);
        goto err;
    }

    pkey_ctx_t *data = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey_pub = data->static_my_key;
    EVP_PKEY *pkey_rand = EVP_PKEY_CTX_get0_pkey(ctx);

    EC_KEY *key_rand, *key_pub;
    if (NULL == (key_pub = EVP_PKEY_get0(pkey_pub)))
    {
        goto err;
    }
    key_rand = EVP_PKEY_get0(pkey_rand);

    const EC_GROUP *group = EC_KEY_get0_group(key_pub);
    BIGNUM *order;
    if (NULL == (order = BN_new()))
    {
        CCSerr(CCS_F_ECIES_ENCRYPT, CCS_R_MALLOC_ERROR);
        goto err;
    }

    if (1 != EC_GROUP_get_order(group, order, NULL))
    {
        CCSerr(CCS_F_ECIES_ENCRYPT, CCS_R_NULL_REFERENCE);
        goto err;
    }

    if (out == NULL)
    {
        /*
         * cipher consists of three elements, C1 || C3 || C2
         * C1 : a point on EC
         * C2 : message oxr a string
         * C3 : Hash
         *
         * C1 length is len(order) * 2 + 1 (compression indicator)
         * C2 length is  in_len
         * C3 length is SM3_DIGEST_LENGTH
         */
        *out_len = BN_num_bytes(order) * 2 + 1 + in_len + SM3_DIGEST_LENGTH;
        BN_free(order);
        return 1;
    }

    ok = sm2_do_encrypt(key_pub, key_rand, in, in_len, out, out_len);

    err:

    if (order)
        BN_free(order);

    return ok;
}

static int
evp_sm2_decrypt_init(EVP_PKEY_CTX *ctx)
{
    return 1;
}

static int
evp_sm2_decrypt(EVP_PKEY_CTX *ctx,
                unsigned char *out,
                size_t *out_len,
                const unsigned char *in,
                size_t in_len)
{
    int ok = 0;

    EVP_PKEY *pkey;
    EC_KEY *ec_key;

    if (out_len == NULL || in == NULL)
    {
        CCSerr(CCS_F_ECIES_DECRYPT, CCS_R_NULL_REFERENCE);
        goto err;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    ec_key = EVP_PKEY_get0(pkey);

    if (out == NULL)
    {
        BIGNUM *order = BN_new();
        const EC_GROUP *group = EC_KEY_get0_group(ec_key);
        EC_GROUP_get_order(group, order, NULL);

        *out_len = in_len - BN_num_bytes(order) * 2 - SM3_DIGEST_LENGTH - 1;
        BN_free(order);
        return 1;
    }

    sm2_do_decrypt(ec_key, in, in_len, out, out_len);

    ok = 1;

    err:

    return ok;
}

static int
evp_sm2_derive_init(EVP_PKEY_CTX *ctx)
{
    return 1;
}

static int
evp_sm2_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *key_len)
{
    if (key == NULL)
    {
        *key_len = 16;
        return 1;
    }

    pkey_ctx_t *sm2_ctx = EVP_PKEY_CTX_get_data(ctx);
    if (sm2_ctx == NULL)
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    EVP_PKEY *pkey_my_eph;
    EC_KEY *ec_key_my_eph;
    EVP_PKEY *pkey_peer_eph;
    EC_KEY *ec_key_peer_eph;
    const EC_POINT *pub_eph;
    EVP_PKEY *pkey_my_sat;
    EC_KEY *ec_key_my_sat;
    EVP_PKEY *pkey_peer_sat;
    EC_KEY *ec_key_peer_sat;
    const EC_POINT *pub_sat;

    if (NULL == (pkey_my_eph = EVP_PKEY_CTX_get0_pkey(ctx)))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (ec_key_my_eph = EVP_PKEY_get0(pkey_my_eph)))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (pkey_peer_eph = EVP_PKEY_CTX_get0_peerkey(ctx)))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (ec_key_peer_eph = EVP_PKEY_get0(pkey_peer_eph)))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (pub_eph = EC_KEY_get0_public_key(ec_key_peer_eph)))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (pkey_my_sat = sm2_ctx->static_my_key))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (ec_key_my_sat = EVP_PKEY_get0(pkey_my_sat)))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (pkey_peer_sat = sm2_ctx->static_peer_pub))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (ec_key_peer_sat = EVP_PKEY_get0(pkey_peer_sat)))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (NULL == (pub_sat = EC_KEY_get0_public_key(ec_key_peer_sat)))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_NULL_REFERENCE);
        return 0;
    }

    if (1 != sm2_compute_key(key,
                             key_len,
                             ec_key_my_eph,
                             ec_key_my_sat,
                             pub_eph,
                             pub_sat,
                             sm2_ctx->za,
                             sm2_ctx->zb,
                             sm2_kdf))
    {
        CCSerr(CCS_F_ECDH_DERIVE, CCS_R_ARITHMETIC_ERROR);
        return 0;
    }

    return 1;

}

static int
evp_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    return 1;
}

static int
evp_sm2_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    pkey_ctx_t *pctx = EVP_PKEY_CTX_get_data(ctx);
    if (!pctx)
        return 0;

    if (!strcmp(type, EVP_PKEY_SET_PEER_KEY))
        pctx->static_peer_pub = (EVP_PKEY *) value;
    else if (!strcmp(type, EVP_PKEY_SET_MY_KEY))
        pctx->static_my_key = (EVP_PKEY *) value;
    else if (!strcmp(type, EVP_PKEY_SET_ZA))
        pctx->za = (uint8_t *) value;
    else if (!strcmp(type, EVP_PKEY_SET_ZB))
        pctx->zb = (uint8_t *) value;
    else if (!strcmp(type, EVP_PKEY_SET_CURVE_BY_SN))
        pctx->curve_id = OBJ_sn2nid(value);
    else
        return 0;

    return 1;
}



// ==================== ecdh helper ====================

static int
evp_sm2_fill_params(EC_KEY *ec_key, int nid_curve)
{
    // FIXME gf2m
    ec_param_fp_t *param = ec_param_fp_set;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *a = NULL, *b = NULL, *n = NULL, *x = NULL, *y = NULL, *p = NULL,
        *h = NULL;
    BN_CTX *bn_ctx;

    int ok = 0;

    if (NULL == (bn_ctx = BN_CTX_new()))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_MALLOC_ERROR);
        goto err;
    }

    BN_CTX_start(bn_ctx);
    a = BN_CTX_get(bn_ctx);
    b = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    p = BN_CTX_get(bn_ctx);
    n = BN_CTX_get(bn_ctx);
    h = BN_CTX_get(bn_ctx);

    // FIXME malloc check

    while (param->nid != NID_undef && param->nid != nid_curve)
        param++;
    if (param->nid == NID_undef)
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_PARAMETER_ERROR);
        goto err;
    }

    if (0 == BN_hex2bn(&p, param->p))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_BN_ERROR);
        goto err;
    }

    if (0 == BN_hex2bn(&a, param->a))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_BN_ERROR);
        goto err;
    }

    if (0 == BN_hex2bn(&b, param->b))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_BN_ERROR);
        goto err;
    }

    //TODO GF2m
    if (NULL == (group = EC_GROUP_new_curve_GFp(p, a, b, bn_ctx)))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_PARAMETER_ERROR);
        goto err;
    }

    if (NULL == (point = EC_POINT_new(group)))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_MALLOC_ERROR);
        goto err;
    }

    if (0 == BN_hex2bn(&x, param->gx))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_BN_ERROR);
        goto err;
    }

    if (0 == BN_hex2bn(&y, param->gy))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_BN_ERROR);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1
            != EC_POINT_set_affine_coordinates_GFp(group, point, x, y, bn_ctx))
        {
            CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_ARITHMETIC_ERROR);
            goto err;
        }
    }
    else
    {
        if (1
            != EC_POINT_set_affine_coordinates_GF2m(group, point, x, y, bn_ctx))
        {
            CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_ARITHMETIC_ERROR);
            goto err;
        }
    }

    if (0 == BN_hex2bn(&n, param->n))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_BN_ERROR);
        goto err;
    }

    if (0 == BN_hex2bn(&h, param->h))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_BN_ERROR);
        goto err;
    }

    if (1 != EC_GROUP_set_generator(group, point, n, h))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_ARITHMETIC_ERROR);
        goto err;
    }

    EC_GROUP_set_curve_name(group, param->nid);

    if (1 != EC_KEY_set_group(ec_key, group))
    {
        CCSerr(CCS_F_EC_FILLING_PARAMETER, CCS_R_ARITHMETIC_ERROR);
        goto err;
    }

    ok = 1;

    err:
    EC_POINT_clear_free(point);
    EC_GROUP_clear_free(group);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ok;
}

static int
evp_sm2_compute_public(EC_KEY *ec_key)
{
    int ok = 0;

    const EC_GROUP *group;
    EC_POINT *pub = NULL;
    const BIGNUM *priv = NULL;
    BN_CTX *bn_ctx = NULL;

    if (NULL == (group = EC_KEY_get0_group(ec_key)))
    {
        CCSerr(CCS_F_EC_COMPUTE_PUBLIC, CCS_R_NULL_REFERENCE);
        goto err;
    }

    if (NULL == (bn_ctx = BN_CTX_new()))
    {
        CCSerr(CCS_F_EC_COMPUTE_PUBLIC, CCS_R_MALLOC_ERROR);
        goto err;
    }

    BN_CTX_start(bn_ctx);

    if (NULL == (priv = EC_KEY_get0_private_key(ec_key)))
    {
        CCSerr(CCS_F_EC_COMPUTE_PUBLIC, CCS_R_NULL_REFERENCE);
        goto err;
    }

    if (NULL == (pub = EC_POINT_new(group)))
    {
        CCSerr(CCS_F_EC_COMPUTE_PUBLIC, CCS_R_MALLOC_ERROR);
        goto err;
    }

    if (1 != EC_POINT_mul(group, pub, priv, NULL, NULL, bn_ctx))
    {
        CCSerr(CCS_F_EC_COMPUTE_PUBLIC, CCS_R_ARITHMETIC_ERROR);
        goto err;
    }

    if (1 != EC_KEY_set_public_key(ec_key, pub))
    {
        CCSerr(CCS_F_EC_COMPUTE_PUBLIC, CCS_R_PKEY_SET_ERROR);
        goto err;
    }

    ok = 1;

    err:
    EC_POINT_clear_free(pub);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ok;
}

// -------------------- ecdsa --------------------
// ecdsa

static int
evp_sm2_sign(EVP_PKEY_CTX *ctx,
             unsigned char *sig,
             size_t *sig_len,
             const unsigned char *tbs,
             size_t tbs_len)
{
    int ok = 0;

    if (sig_len == NULL)
    {
        CCSerr(CCS_F_ECDSA_DO_SIGN, CCS_R_NULL_REFERENCE);
        goto err;
    }

    DSA_SIG *unpacked_sig = NULL;
    EVP_PKEY *pkey_eph = EVP_PKEY_CTX_get0_pkey(ctx);

    BIGNUM *order = NULL;
    EC_KEY *ec_key_eph = NULL;
    const EC_GROUP *group = NULL;
    EVP_PKEY *pkey_sta = NULL;
    EC_KEY *ec_key_sta = NULL;

    ec_key_eph = EVP_PKEY_get0(pkey_eph);

    group = EC_KEY_get0_group(ec_key_eph);
    order = BN_new();
    EC_GROUP_get_order(group, order, NULL);

    if (sig == NULL)
    {
        *sig_len = (size_t) BN_num_bytes(order) * 2;
        BN_free(order);
        return 1;
    }

    pkey_ctx_t *sm2_ctx = EVP_PKEY_CTX_get_data(ctx);
    pkey_sta = sm2_ctx->static_my_key;
    ec_key_sta = EVP_PKEY_get0(pkey_sta);

    unpacked_sig = DSA_SIG_new();

    sm2_do_sign(unpacked_sig, tbs, tbs_len, ec_key_sta, ec_key_eph);

    BN_bn2bin(unpacked_sig->r, sig);
    BN_bn2bin(unpacked_sig->s, &sig[SM3_DIGEST_LENGTH]);

    ok = 1;

    err:
    DSA_SIG_free(unpacked_sig);
    BN_free(order);

    return ok;
}

static int
evp_sm2_verify(EVP_PKEY_CTX *ctx,
               const unsigned char *bin_sig,
               size_t sig_len,
               const unsigned char *tbs,
               size_t tbs_len)
{
    int ok = 0;

    DSA_SIG *sig = DSA_SIG_new();
    unsigned char bin_r[SM3_DIGEST_LENGTH];
    unsigned char bin_s[SM3_DIGEST_LENGTH];

    BIGNUM *r, *s;

    memcpy(bin_r, bin_sig, SM3_DIGEST_LENGTH);
    memcpy(bin_s, bin_sig + SM3_DIGEST_LENGTH, SM3_DIGEST_LENGTH);

    r = BN_new();
    s = BN_new();

    if (s == NULL)
    {
        CCSerr(CCS_F_ECDSA_DO_VERIFY, CCS_R_MALLOC_ERROR);
        goto err;
    }

    if (NULL == (BN_bin2bn(bin_r, SM3_DIGEST_LENGTH, r)))
    {
        CCSerr(CCS_F_ECDSA_DO_VERIFY, CCS_R_BN_ERROR);
        goto err;
    }

    if (NULL == (BN_bin2bn(bin_s, SM3_DIGEST_LENGTH, s)))
    {
        CCSerr(CCS_F_ECDSA_DO_VERIFY, CCS_R_BN_ERROR);
        goto err;
    }

    EC_KEY *key = NULL;
    EVP_PKEY *pkey;
    if (NULL == (pkey = EVP_PKEY_CTX_get0_pkey(ctx)))
    {
        CCSerr(CCS_F_ECDSA_DO_VERIFY, CCS_R_NULL_REFERENCE);
        goto err;
    }

    if (NULL == (key = EVP_PKEY_get0(pkey)))
    {
        CCSerr(CCS_F_ECDSA_DO_VERIFY, CCS_R_NULL_REFERENCE);
        goto err;
    }

    sig->r = r;
    sig->s = s;

    ok = sm2_do_verify(sig, key, tbs);

    err:
    if (sig)
    {
        DSA_SIG_free(sig);
    }
    return ok;
}
