/*
 * Author Chen Gao
 * Created at 1/11/18
 *
 * This file sm2_enc.c is part of ccs_engine.
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
#include <openssl/obj_mac.h>

#include "sm2.h"
#include "../md/sm3_hash.h"

/**
 * check if buffer is all 0
 * @param buf
 *      buffer to be checked
 * @return
 *      1 if buffer contains data, 0 if buffer is all empty
 */
int
check_empty_buffer(unsigned char *buf, size_t len);

/*
 * REVIEW cipher_len is useless
 */
int
sm2_do_encrypt(EC_KEY *key_pub,
               EC_KEY *key_rand,
               const unsigned char *msg,
               size_t msg_len,
               unsigned char *cipher,
               size_t *cipher_len)
{
    int ok = 0;

    BN_CTX *bn_ctx;
    BIGNUM *h, *x2, *y2;
    const BIGNUM *k_rand;
    const EC_GROUP *group;
    const EC_POINT *c1, *pub;
    EC_POINT *tmp = NULL;

    //hash input
    unsigned char *c3_origin = NULL;
    // kdf input and output
    unsigned char *in = NULL;
    unsigned char *out = NULL;

    if (NULL == (bn_ctx = BN_CTX_new()))
        goto err;
    BN_CTX_start(bn_ctx);
    h = BN_CTX_get(bn_ctx);
    x2 = BN_CTX_get(bn_ctx);
    y2 = BN_CTX_get(bn_ctx);

    //FIXME check malloc error

    if (NULL == (group = EC_KEY_get0_group(key_pub)))
        goto err;

    if (1 != EC_GROUP_get_cofactor(group, h, bn_ctx))
        goto err;

    if (NULL == (c1 = EC_KEY_get0_public_key(key_rand)))
        goto err;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1
            != EC_POINT_get_affine_coordinates_GFp(group, c1, x2, y2, bn_ctx))
            goto err;
    }
    else
    {
        if (1
            != EC_POINT_get_affine_coordinates_GF2m(group, c1, x2, y2, bn_ctx))
            goto err;
    }

    //FIXME deal with compressed case
    cipher[0] = 0x04;
    int len = BN_num_bytes(x2);
    if (len != BN_bn2bin(x2, cipher + 1))
        goto err;

    if (len != BN_bn2bin(y2, cipher + 1 + len))
        goto err;

    /* As of here, C1 is in place */

    if (NULL == (pub = EC_KEY_get0_public_key(key_pub)))
        goto err;

    if (NULL == (tmp = EC_POINT_new(group)))
        goto err;

    if (1 != EC_POINT_mul(group, tmp, NULL, pub, h, bn_ctx))
        goto err;

    if (1 == EC_POINT_is_at_infinity(group, tmp))
        goto err;

    if (NULL == (k_rand = EC_KEY_get0_private_key(key_rand)))
        goto err;

    if (1 != EC_POINT_mul(group, tmp, NULL, pub, k_rand, bn_ctx))
        goto err;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1
            != EC_POINT_get_affine_coordinates_GFp(group, tmp, x2, y2, bn_ctx))
            goto err;
    }
    else
    {
        if (1
            != EC_POINT_get_affine_coordinates_GF2m(group, tmp, x2, y2, bn_ctx))
            goto err;
    }

    // FIXME just in case, removable
    len = BN_num_bytes(x2);

    if (NULL == (c3_origin = OPENSSL_malloc(len * 2 + msg_len + 1)))
        goto err;

    if (len != BN_bn2bin(x2, c3_origin))
        goto err;

    memcpy(c3_origin + len, msg, msg_len);

    if (len != BN_bn2bin(y2, c3_origin + len + msg_len))
        goto err;

    sm3(c3_origin, len * 2 + msg_len, cipher + 1 + len * 2);

    /* As of here, C3 is in place */

    if (NULL == (in = OPENSSL_malloc(len * 2 + 1)))
        goto err;

    if (len != BN_bn2bin(x2, in))
        goto err;

    if (len != BN_bn2bin(y2, in + len))
        goto err;

    if (NULL == (out = OPENSSL_malloc(msg_len + 1)))
        goto err;

    //FIXME unhandled return value
    sm2_kdf(in, (size_t) len * 2, out, &msg_len);

    if (0 == check_empty_buffer(out, msg_len))
        goto err;

    for (int i = 0; i < msg_len; ++i)
    {
        cipher[1 + len * 2 + SM3_DIGEST_LENGTH + i] = out[i] ^ msg[i];
    }

    ok = 1;

    err:
    OPENSSL_free(c3_origin);
    OPENSSL_free(in);
    OPENSSL_free(out);

    if (tmp)
        EC_POINT_free(tmp);

    if (bn_ctx)
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    return ok;
}

int
sm2_do_decrypt(EC_KEY *ec_key,
               const unsigned char *cipher,
               size_t cipher_len,
               unsigned char *plaintext,
               size_t *plaintext_len)
{
    int ok = 0;

    BN_CTX *bn_ctx;
    BIGNUM *order, *x, *y;
    const BIGNUM *priv;
    const EC_GROUP *group;
    EC_POINT *c1 = NULL, *tmp = NULL;

    const unsigned char *ptr_cipher = &cipher[1];

    unsigned char *kdf_in = NULL, *kdf_out = NULL, *hash_in = NULL,
        *hash_out = NULL;

    bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    order = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);

    group = EC_KEY_get0_group(ec_key);
    EC_GROUP_get_order(group, order, bn_ctx);

    if (cipher[0] != 0x04)
        goto err;

    int len_pt = BN_num_bytes(order);

    BN_bin2bn(ptr_cipher, len_pt, x);
    ptr_cipher += len_pt;
    BN_bin2bn(ptr_cipher, len_pt, y);
    ptr_cipher += len_pt;               // points to C3 now

    unsigned char c3[SM3_DIGEST_LENGTH];
    memcpy(c3, ptr_cipher, SM3_DIGEST_LENGTH);
    ptr_cipher += SM3_DIGEST_LENGTH;    // points to C2 now

    *plaintext_len = cipher_len - len_pt * 2 - SM3_DIGEST_LENGTH - 1;
    memcpy(plaintext, ptr_cipher, *plaintext_len);

    c1 = EC_POINT_new(group);
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1 != EC_POINT_set_affine_coordinates_GFp(group, c1, x, y, bn_ctx))
            goto err;
    }
    else
    {
        if (1 != EC_POINT_set_affine_coordinates_GF2m(group, c1, x, y, bn_ctx))
            goto err;
    }

    if (1 != EC_POINT_is_on_curve(group, c1, bn_ctx))
        goto err;

    tmp = EC_POINT_new(group);
    EC_GROUP_get_cofactor(group, x, bn_ctx);
    EC_POINT_mul(group, tmp, NULL, c1, x, bn_ctx);

    if (1 == EC_POINT_is_at_infinity(group, tmp))
        goto err;

    priv = EC_KEY_get0_private_key(ec_key);

    if (1 != EC_POINT_mul(group, tmp, NULL, c1, priv, bn_ctx))
        goto err;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field)
    {
        if (1 != EC_POINT_get_affine_coordinates_GFp(group, tmp, x, y, bn_ctx))
            goto err;
    }
    else
    {
        if (1 != EC_POINT_get_affine_coordinates_GF2m(group, tmp, x, y, bn_ctx))
            goto err;
    }

    kdf_in = OPENSSL_malloc(len_pt * 2);
    kdf_out = OPENSSL_malloc(*plaintext_len);

    BN_bn2bin(x, kdf_in);
    BN_bn2bin(y, kdf_in + len_pt);

    sm2_kdf(kdf_in, (size_t)len_pt * 2, kdf_out, plaintext_len);

    if (0 == check_empty_buffer(kdf_out, *plaintext_len))
        goto err;

    for (int i = 0; i < *plaintext_len; ++i)
    {
        plaintext[i] ^= kdf_out[i];
    }

    hash_in = OPENSSL_malloc(len_pt * 2 + *plaintext_len);
    BN_bn2bin(x, hash_in);
    memcpy(hash_in + len_pt, plaintext, *plaintext_len);
    BN_bn2bin(y, hash_in + len_pt + *plaintext_len);

    hash_out = OPENSSL_malloc(SM3_DIGEST_LENGTH);
    sm3(hash_in, *plaintext_len + len_pt * 2, hash_out);

    if (0 != CRYPTO_memcmp(c3, hash_out, SM3_DIGEST_LENGTH))
        goto err;

    ok = 1;

    err:
    OPENSSL_free(hash_out);
    OPENSSL_free(hash_in);
    OPENSSL_free(kdf_out);
    OPENSSL_free(kdf_in);
    EC_POINT_free(tmp);
    EC_POINT_free(c1);

    if (bn_ctx)
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    return ok;
}

// FIXME naive check for empty buffer
int
check_empty_buffer(unsigned char *buf, size_t len)
{
    return CRYPTO_memcmp(buf, buf + 1, len - 1) ? 1 : 0;
}