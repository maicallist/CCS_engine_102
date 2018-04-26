/*
 * Author Chen Gao
 * Created at 1/3/18
 *
 * This file sm2_ecdh.c is part of ccs_engine.
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
 *
 */

#include <string.h>
#include <openssl/obj_mac.h>

#include "sm2.h"

int
sm2_compute_key(void *shared_key,
                size_t *shared_key_len,
                EC_KEY *my_ephemeral_key,
                EC_KEY *my_static_key,
                const EC_POINT *peer_ephemeral_pub,
                const EC_POINT *peer_static_pub,
                unsigned char *za,
                unsigned char *zb,
                void *(*KDF)(void *in,
                             size_t in_len,
                             void *out,
                             size_t *out_len))
{
    int ret = 0;

    BN_CTX *bn_ctx;
    BIGNUM *my_eph_x = NULL, *peer_eph_x = NULL, *pow2 = NULL;
    BIGNUM *ta = NULL;
    const BIGNUM *my_sat_priv, *my_eph_priv;

    BIGNUM *order = NULL;
    const EC_GROUP *group = NULL;
    EC_POINT *tmp = NULL;

    unsigned char *x = NULL, *y = NULL;
    unsigned char *in = NULL;

    if (NULL == (bn_ctx = BN_CTX_new()))
        goto err;

    BN_CTX_start(bn_ctx);
    my_eph_x = BN_CTX_get(bn_ctx);
    peer_eph_x = BN_CTX_get(bn_ctx);
    pow2 = BN_CTX_get(bn_ctx);
    ta = BN_CTX_get(bn_ctx);
    order = BN_CTX_get(bn_ctx);

    //FIXME malloc check

    if (NULL == (group = EC_KEY_get0_group(my_static_key)))
        goto err;

    if (1 != EC_GROUP_get_order(group, order, bn_ctx))
        goto err;

    if (1 != EC_POINT_is_on_curve(group, peer_ephemeral_pub, bn_ctx))
        goto err;

    //-------------------- pre-checks complete --------------------
    //-------------------- start negotiation --------------------

    /*
     * REVIEW
     * WTF
     *
     * the result is entirely depending on the order
     * I see curves like brainpool256 r1, P256 are all fine.
     * But following curve gives wrong result.
     *
     * p        C0000000000000000000000000000000000000000000000000000000000003C7
     * a        C0000000000000000000000000000000000000000000000000000000000003c4
     * b        2d06B4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c
     * gx       2
     * gy       a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c
     * order    5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85
     *
     * not sure if there are more, so pick your curve carefully.
     * although I've added a fail-safe below, these lines are required to be
     * reviewed.
     */
    int w = BN_num_bits(order);
    /* fail safe */
    if (w % 2)
        w++;
    w = w / 2 - 1;

    // calc 2^w, we borrow my_eph_x to store the base
    if (1 != BN_set_word(my_eph_x, 2))
        goto err;

    if (1 != BN_set_word(pow2, (unsigned) w))
        goto err;

    if (1 != BN_exp(pow2, my_eph_x, pow2, bn_ctx))
        goto err;

    const EC_POINT *my_eph_pub;
    if (NULL == (my_eph_pub = EC_KEY_get0_public_key(my_ephemeral_key)))
        goto err;

    /*
     * truncate x to w bits has the same effect of
     * calculating x & (2^w - 1)
     *
     * 2^w , in binary form, is "1000.......000" which consist of a 1 and w of 0,
     * total w+1 bits.            |- w times -|
     *
     * 2^w - 1 thus is "1111....11111" in binary
     *                  |- w times -|
     *
     * any number bitwise and (&) with 2^w - 1, basically means just keep
     * the LSB to the w'th bit, throw away from w+1'th bit to the MSB.
     */
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1 != EC_POINT_get_affine_coordinates_GFp(group,
                                                     my_eph_pub,
                                                     my_eph_x,
                                                     NULL,
                                                     bn_ctx))
            goto err;
    }
    else
    {
        if (1 != EC_POINT_get_affine_coordinates_GF2m(group,
                                                      my_eph_pub,
                                                      my_eph_x,
                                                      NULL,
                                                      bn_ctx))
            goto err;
    }

    if (1 != BN_mask_bits(my_eph_x, w))
        goto err;

    // store 2^w + (eph_x & (2^w - 1)) in my_eph_x
    if (1 != BN_add(my_eph_x, pow2, my_eph_x))
        goto err;

    // tA = (d + xr) mod n
    if (NULL == (my_eph_priv = EC_KEY_get0_private_key(my_ephemeral_key)))
        goto err;

    if (NULL == (my_sat_priv = EC_KEY_get0_private_key(my_static_key)))
        goto err;

    if (1 != BN_mod_mul(ta, my_eph_x, my_eph_priv, order, bn_ctx))
        goto err;

    if (1 != BN_mod_add(ta, ta, my_sat_priv, order, bn_ctx))
        goto err;

    // peer side x_
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1 != EC_POINT_get_affine_coordinates_GFp(group,
                                                     peer_ephemeral_pub,
                                                     peer_eph_x,
                                                     NULL,
                                                     bn_ctx))
            goto err;
    }
    else
    {
        if (1 != EC_POINT_get_affine_coordinates_GF2m(group,
                                                      peer_ephemeral_pub,
                                                      peer_eph_x,
                                                      NULL,
                                                      bn_ctx))
            goto err;
    }

    if (1 != BN_mask_bits(peer_eph_x, w))
        goto err;

    if (1 != BN_add(peer_eph_x, pow2, peer_eph_x))
        goto err;

    // (Pb + x Rb)
    if (NULL == (tmp = EC_POINT_new(group)))
        goto err;

    if (1 != EC_POINT_mul(group,
                          tmp,
                          NULL,
                          peer_ephemeral_pub,
                          peer_eph_x,
                          bn_ctx))
        goto err;

    if (1 != EC_POINT_add(group, tmp, tmp, peer_static_pub, bn_ctx))
        goto err;

    // pow2 is no longer needed, we can use it to store cofactor now.
    if (1 != EC_GROUP_get_cofactor(group, pow2, bn_ctx))
        goto err;

    // [h tA]
    if (1 != BN_mul(ta, pow2, ta, bn_ctx))
        goto err;

    // [h tA] (Pb + x Rb)
    if (1 != EC_POINT_mul(group, tmp, NULL, tmp, ta, bn_ctx))
        goto err;

    // -------------------- post-checks --------------------
    if (EC_POINT_is_at_infinity(group, tmp))
        goto err;

    // X and Y of shared point
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1 != EC_POINT_get_affine_coordinates_GFp(group,
                                                     tmp,
                                                     pow2,
                                                     ta,
                                                     bn_ctx))
            goto err;
    }
    else
    {
        if (1 != EC_POINT_get_affine_coordinates_GF2m(group,
                                                      tmp,
                                                      pow2,
                                                      ta,
                                                      bn_ctx))
            goto err;
    }

    // -------------------- concatenate kdf input --------------------
    size_t a_len = strnlen((char *) za, INT_MAX);
    size_t b_len = strnlen((char *) zb, INT_MAX);

    size_t len = (size_t) BN_num_bytes(pow2);

    x = OPENSSL_malloc(len + 1);
    y = OPENSSL_malloc(len + 1);
    x[len] = '\0';
    y[len] = '\0';

    BN_bn2bin(pow2, x);
    BN_bn2bin(ta, y);

    size_t max = len * 2 + a_len + b_len + 1;
    in = OPENSSL_malloc(sizeof(unsigned char) * max);
    in[max - 1] = '\0';
    memcpy(in, x, len);
    memcpy(in + len, y, len);
    memcpy(in + len + len, za, a_len);
    memcpy(in + len + len + a_len, zb, b_len);

    // cuz we add null terminator when we calculate max
    size_t *retp = KDF(in, max - 1, shared_key, shared_key_len);
    if (retp == NULL)
        goto err;

    ret = 1;

    err:
    OPENSSL_free(in);
    OPENSSL_free(x);
    OPENSSL_free(y);
    EC_POINT_clear_free(tmp);

    if (bn_ctx)
        BN_CTX_end(bn_ctx);
    if (bn_ctx)
        BN_CTX_free(bn_ctx);

    return ret;
}