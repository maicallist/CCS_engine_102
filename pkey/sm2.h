/*
 * Author Chen Gao
 * Created at 1/3/18
 *
 * This file sm2.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_SM2_H
#define CCS_ENGINE_SM2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>

#include "../err/ccs_err.h"

typedef struct
{
    int curve_id;
    EVP_PKEY *static_peer_pub;
    EVP_PKEY *static_my_key;
    unsigned char *za;
    unsigned char *zb;
} pkey_ctx_t;

/**
 * implementation of ecdh function (excluding kdf) specified in SM2 standard.
 *
 * @param shared_key
 *      store derived key data
 * @param shared_key_len
 *      store derived key length in byte
 * @param my_ephemeral_key
 *      one time key pair
 * @param my_static_key
 *      long term key pair
 * @param peer_ephemeral_pub
 *      one time public key of peer
 * @param peer_static_pub
 *      long term public key of peer
 * @param za
 *      identity hash of Party A
 * @param zb
 *      identity hash of Party B
 * @param KDF
 *      pointer to key derivation function impl
 *
 * @return
 *      1 if success, 0 if fail
 *
 * @attention
 *      1. shared_key & shared_key_len must be malloc'ed before calling this function.
 */
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
                             size_t *out_len));

/**
 * implementation of key derivation function specified in SM2 standard.
 *
 * @param in
 *      concatenation of shared point(x, y), identity hash from A and B
 *      x || y || zA || zB || '\0'
 * @param in_len
 *      length of (x || y || zA || zB) in byte
 * @param out
 *      store derived key
 * @param out_len
 *      length of the derived key in byte
 *
 * @return
 *      pointer to the length of the derived key if success,
 *      NULL if fail.
 *
 * @attention
 *      1. [in, out, out_len] must be malloc'ed before calling kdf function.
 *      2. if [out_len] is 0, kdf sets out_len to minimum key length 16 (128 bit).
 */
//FIXME return pointer?
void *
sm2_kdf(void *in, size_t in_len, void *out, size_t *out_len);

/**
 * sign hashed data
 * @param sig
 *      signing result
 * @param tbs
 *      data to be signed, H(za || M)
 * @param tbs_len
 *      data length in byte
 * @param static_key
 *      static signing key
 * @param eph_key
 *      ephemeral signing key
 * @return
 *      1 if success, 0 if error
 */
int
sm2_do_sign(DSA_SIG *sig,
            const unsigned char *tbs,
            size_t tbs_len,
            EC_KEY *static_key,
            EC_KEY *eph_key);

/**
 * verify digital signature
 *
 * @param sig
 *      contains r, s
 * @param key
 *      contains group, public key
 * @param tbs
 *      signed hashed data
 * @return
 *      1 if success, 0 if error, -1 if signature is invalid
 */
int
sm2_do_verify(DSA_SIG *sig, EC_KEY *key, const unsigned char *tbs);

/**
 * encrypt data
 *
 * @param key_pub
 *      static ec key
 * @param key_rand
 *      random ec key, one time use
 * @param msg
 *      data to be encrypted
 * @param msg_len
 *      data length in byte
 * @param cipher
 *      encrypted data
 * @param cipher_len
 *      length of encrypted data in byte
 * @return
 *      1 if success, 0 if error
 */
int
sm2_do_encrypt(EC_KEY *key_pub,
               EC_KEY *key_rand,
               const unsigned char *msg,
               size_t msg_len,
               unsigned char *cipher,
               size_t *cipher_len);

/**
 * decrypt data
 * @param ec_key
 *      receiver's private key
 * @param cipher
 *      encrypted data
 * @param cipher_len
 *      length of [cipher] in byte
 * @param plaintext
 *      decrypted data
 * @param plaintext_len
 *      length of [plaintext] in byte
 * @return
 *      1 if success, 0 on error
 */
int
sm2_do_decrypt(EC_KEY *ec_key,
               const unsigned char *cipher,
               size_t cipher_len,
               unsigned char *plaintext,
               size_t *plaintext_len);
#ifdef __cplusplus
}
#endif

#endif //CCS_ENGINE_SM2_H
