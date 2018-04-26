#include <stdio.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <memory.h>
#include "pkey/sm2.h"
#include "conf/objects.h"

#define KRED                "\x1B[31m"
#define KGRN                "\x1B[32m"
#define RST                 "\x1B[0m"
#define PASS                printf("%stest passed.%s\n\n", KGRN, RST)
#define FAIL                printf("%stest failed.%s\n\n", KRED, RST)

#define ENGINE_ID           "ccs"
#define ERROR_HANDLING      printf \
                            ("an error has occurred in %s(), at %s line %d.\n",\
                            __FUNCTION__, __FILE__, __LINE__)

#define CASE                test++;pass
#define DEBUG 1

static ENGINE *engine;

int
load_engine();

int
test_md(int caseno);

int
test_ecdh();

int
test_signing();

int
test_verify();

int
test_asym_enc();

int
test_asym_dec();

int
test_cipher_enc1();
int
test_cipher_enc2();
int
test_cipher_enc3();
int
test_cipher_enc4();
int
test_cipher_enc5();
int
test_cipher_enc6();
int
test_cipher_enc7();

int
test_cipher_dec2();
int
test_cipher_dec3();
int
test_cipher_dec4();
int
test_cipher_dec5();
int
test_cipher_dec6();
int
test_cipher_dec7();
int
test_cipher_dec8();

void
engine_cleanup();

int
main()
{
    printf("We're using OpenSSL version %s.\n", OPENSSL_VERSION_TEXT);

    int test = 0, pass = 0;

    CASE += load_engine();

    printf("Following error is generated for testing...\n");
    ERR_print_errors_fp(stderr);
    printf("\n");

    CASE += test_md(1);
    CASE += test_md(2);

    CASE += test_ecdh();
    CASE += test_signing();
    CASE += test_verify();
    CASE += test_asym_enc();
    CASE += test_asym_dec();

    CASE += test_cipher_enc1();
    CASE += test_cipher_enc2();
    CASE += test_cipher_enc3();
    CASE += test_cipher_enc4();
    CASE += test_cipher_enc5();
    CASE += test_cipher_enc6();
    CASE += test_cipher_enc7();

    CASE += test_cipher_dec2();
    CASE += test_cipher_dec3();
    CASE += test_cipher_dec4();
    CASE += test_cipher_dec5();
    CASE += test_cipher_dec6();
    CASE += test_cipher_dec7();
    CASE += test_cipher_dec8();

    engine_cleanup();

    printf("Test Summary:\nTotal: %d, Passed: %d, Failed: %d\n",
           test,
           pass,
           test - pass);
    return 0;
}

int
load_engine()
{
    OpenSSL_add_all_algorithms();
    ERR_load_CRYPTO_strings();

    /*
     * use the app name we defined in config file global section which is 'ccs'.
     * if you send NULL, OpenSSL will look for default app name 'openssl_conf'.
     */
    OPENSSL_load_builtin_modules();
    ENGINE_load_builtin_engines();
    CONF_modules_load_file(NULL, ENGINE_ID, 0);

    ENGINE_load_dynamic();
    engine = ENGINE_by_id(ENGINE_ID);

    if (!engine)
    {
        ERROR_HANDLING;
        FAIL;
        return 0;
    }

    int init = ENGINE_init(engine);

    # if DEBUG
    printf("engine id: %s\nengine name: %s\ninit result: %d\n",
           ENGINE_get_id(engine),
           ENGINE_get_name(engine),
           init);
    #endif

    if (init)
        PASS;
    else
        FAIL;
    return init;
}

int
test_md(int caseno)
{
    size_t len;
    char *sptr;
    unsigned char *eptr;

    if (caseno == 1)
    {
        printf("begin md test case 1...\n");
        char str[] = "abc";
        unsigned char expect[] =
            {0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4,
                0x6b, 0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c,
                0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8,
                0xe0};
        len = strlen(str);
        sptr = str;
        eptr = expect;
    }
    else if (caseno == 2)
    {
        printf("begin md test case 2...\n");
        char str[] =
            {0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
                0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61,
                0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
                0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61,
                0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
                0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61,
                0x62, 0x63, 0x64};
        unsigned char expect[] =
            {0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48,
                0x89, 0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38,
                0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57,
                0x32};
        len = 64;
        sptr = str;
        eptr = expect;
    }
    else
    {
        FAIL;
        return 0;
    }

    unsigned char *digest = OPENSSL_malloc(sizeof(unsigned char) * 32);
    unsigned int digest_size = 0;

    EVP_MD_CTX *evp_md_ctx;
    evp_md_ctx = EVP_MD_CTX_create();

    EVP_DigestInit_ex(evp_md_ctx, EVP_get_digestbyname("sm3-256"), engine);
    EVP_DigestUpdate(evp_md_ctx, sptr, len);
    EVP_DigestFinal(evp_md_ctx, digest, &digest_size);

    printf("digest result:\n");
    for (int i = 0; i < digest_size; ++i)
    {
        printf("%02x", digest[i]);
        if (!((i + 1) % 4))
            printf(" ");
    }
    printf("\n");

    int pass = CRYPTO_memcmp(digest, eptr, 32);
    if (pass)
        FAIL;
    else
        PASS;

    /* finalize */
    EVP_MD_CTX_destroy(evp_md_ctx);
    OPENSSL_free(digest);

    return (pass) ? 0 : 1;
}

int
test_ecdh()
{
    // REVIEW following line seems have no effect
    //ENGINE_set_default_pkey_meths(engine);
    ENGINE_set_default_pkey_asn1_meths(engine);

    EVP_PKEY_CTX *pctx, *kctx, *ctx;
    unsigned char *secret;
    size_t secret_len = 0;
    EVP_PKEY *pkey = NULL, *peer = NULL;

    int sm2_id = OBJ_sn2nid("sm2");

    if (NULL == (kctx = EVP_PKEY_CTX_new_id(sm2_id, engine)))
        return 0;

    /*
     * REVIEW reference to library header
     * test program need to reference additional header other than .so
     */

    if (1 != EVP_PKEY_keygen_init(kctx))
        return 0;

    if (1 != EVP_PKEY_keygen(kctx, &pkey))
        return 0;

    pctx = EVP_PKEY_CTX_new_id(sm2_id, engine);

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &peer);

    // start derive
    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, engine)))
        return 0;

    // my static
    EC_KEY *sta_key = EC_KEY_new();
    EC_KEY_set_group(sta_key, EC_KEY_get0_group(EVP_PKEY_get0(pkey)));
    BIGNUM *m_sta = BN_new();
    const char *m_sta_hex =
        "6fcba2ef9ae0ab902bc3bde3ff915d44ba4cc78f88e2f8e7f8996d3b8cceedee";
    BN_hex2bn(&m_sta, m_sta_hex);
    EC_KEY_set_private_key(sta_key, m_sta);
    const char *m_sta_x_hex =
        "3099093bf3c137d8fcbbcdf4a2ae50f3b0f216c3122d79425fe03a45dbfe1655";
    const char *m_sta_y_hex =
        "3df79e8dac1cf0ecbaa2f2b49d51a4b387f2efaf482339086a27a8e05baed98b";
    BIGNUM *m_sta_x = BN_new();
    BN_hex2bn(&m_sta_x, m_sta_x_hex);
    BIGNUM *m_sta_y = BN_new();
    BN_hex2bn(&m_sta_y, m_sta_y_hex);
    EC_KEY_set_public_key_affine_coordinates(sta_key, m_sta_x, m_sta_y);
    EVP_PKEY *sta = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(sta, sta_key);
    EC_KEY_free(sta_key);
    BN_free(m_sta);
    BN_free(m_sta_x);
    BN_free(m_sta_y);

    //peer static
    EC_KEY *sta_peer = EC_KEY_new();
    EC_KEY_set_group(sta_peer, EC_KEY_get0_group(EVP_PKEY_get0(pkey)));
    const char *p_sta_x_hex =
        "245493d446c38d8cc0f118374690e7df633a8a4bfb3329b5ece604b2b4f37f43";
    const char *p_sta_y_hex =
        "53c0869f4b9e17773de68fec45e14904e0dea45bf6cecf9918c85ea047c60a4c";
    BIGNUM *p_sta_x = BN_new();
    BN_hex2bn(&p_sta_x, p_sta_x_hex);
    BIGNUM *p_sta_y = BN_new();
    BN_hex2bn(&p_sta_y, p_sta_y_hex);
    EC_KEY_set_public_key_affine_coordinates(sta_peer, p_sta_x, p_sta_y);
    EVP_PKEY *sta_p = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(sta_p, sta_peer);
    EC_KEY_free(sta_peer);
    BN_free(p_sta_x);
    BN_free(p_sta_y);

    unsigned char uza[] =
        {0xe4, 0xd1, 0xd0, 0xc3, 0xca, 0x4c, 0x7f, 0x11, 0xbc, 0x8f, 0xf8, 0xcb,
            0x3f, 0x4c, 0x02, 0xa7, 0x8f, 0x10, 0x8f, 0xa0, 0x98, 0xe5, 0x1a,
            0x66, 0x84, 0x87, 0x24, 0x0f, 0x75, 0xe2, 0x0f, 0x31};
    unsigned char uzb[] =
        {0x6b, 0x4b, 0x6d, 0x0e, 0x27, 0x66, 0x91, 0xbd, 0x4a, 0x11, 0xbf, 0x72,
            0xf4, 0xfb, 0x50, 0x1a, 0xe3, 0x09, 0xfd, 0xac, 0xb7, 0x2f, 0xa6,
            0xcc, 0x33, 0x6e, 0x66, 0x56, 0x11, 0x9a, 0xbd, 0x67};

    unsigned char *pa = OPENSSL_malloc(33);
    unsigned char *pb = OPENSSL_malloc(33);
    memset(pa, '\0', 33);
    memcpy(pa, uza, 32);
    memset(pb, '\0', 33);
    memcpy(pb, uzb, 32);

    EVP_PKEY_CTX_ctrl_str(ctx, EVP_PKEY_SET_PEER_KEY, (char *) sta_p);
    EVP_PKEY_CTX_ctrl_str(ctx, EVP_PKEY_SET_MY_KEY, (char *) sta);
    EVP_PKEY_CTX_ctrl_str(ctx, EVP_PKEY_SET_ZA, (char *) pa);
    EVP_PKEY_CTX_ctrl_str(ctx, EVP_PKEY_SET_ZB, (char *) pb);

    #if 0
    pkey_ctx_t *data = EVP_PKEY_CTX_get_data(ctx);
    data->static_peer_pub = sta_p;
    data->static_my_key = sta;
    data->za = pa;
    data->zb = pb;
    #endif

    EVP_PKEY_derive_init(ctx);

    EVP_PKEY_derive_set_peer(ctx, peer);

    EVP_PKEY_derive(ctx, NULL, &secret_len);

    secret = OPENSSL_malloc(secret_len);

    EVP_PKEY_derive(ctx, secret, &secret_len);

    printf("-----\nderived key is ");
    for (int i = 0; i < secret_len; ++i)
        printf("%02x", secret[i]);
    printf("\n");

    unsigned char expect_key[] =
        {0x55, 0xb0, 0xac, 0x62, 0xa6, 0xb9, 0x27, 0xba, 0x23, 0x70, 0x38, 0x32,
            0xc8, 0x53, 0xde, 0xd4};

    int pass = CRYPTO_memcmp(expect_key, secret, 16);
    if (pass)
        FAIL;
    else
        PASS;

    OPENSSL_free(secret);
    OPENSSL_free(pa);
    OPENSSL_free(pb);

    EVP_PKEY_free(sta_p);
    EVP_PKEY_free(sta);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);

    return (pass) ? 0 : 1;
}

int
test_signing()
{
    // za || M
    unsigned char msg[] =
        {0xf4, 0xa3, 0x84, 0x89, 0xe3, 0x2b, 0x45, 0xb6, 0xf8, 0x76, 0xe3, 0xac,
            0x21, 0x68, 0xca, 0x39, 0x23, 0x62, 0xdc, 0x8f, 0x23, 0x45, 0x9c,
            0x1d, 0x11, 0x46, 0xfc, 0x3d, 0xbf, 0xb7, 0xbc, 0x9a, 0x6d, 0x65,
            0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x64, 0x69, 0x67, 0x65, 0x73,
            0x74};

    EVP_MD_CTX *evp_md_ctx;
    evp_md_ctx = EVP_MD_CTX_create();

    EVP_PKEY_CTX *ctx_sign_sta;
    int sm2_id = OBJ_sn2nid("sm2");
    ctx_sign_sta = EVP_PKEY_CTX_new_id(sm2_id, engine);
    EVP_PKEY *signing_sta = NULL;

    EVP_PKEY_keygen_init(ctx_sign_sta);
    EVP_PKEY_keygen(ctx_sign_sta, &signing_sta);

    EVP_PKEY_CTX *ctx_sign_eph;
    ctx_sign_eph = EVP_PKEY_CTX_new(signing_sta, engine);
    EVP_PKEY *signing_eph = NULL;

    EVP_PKEY_keygen_init(ctx_sign_eph);
    EVP_PKEY_keygen(ctx_sign_eph, &signing_eph);

    //evp_md_ctx->pctx = ctx_sign_sta;
    if (1 != EVP_DigestSignInit(evp_md_ctx,
                                NULL,
                                EVP_get_digestbynid(OBJ_sn2nid("sm3-256")),
                                engine,
                                signing_eph))
        return 0;

    EVP_PKEY_CTX *evp_created_ctx = evp_md_ctx->pctx;
    EVP_PKEY_CTX_ctrl_str(evp_created_ctx,
                          EVP_PKEY_SET_MY_KEY,
                          (char *) signing_sta);
    #if 0
    pkey_ctx_t *created = EVP_PKEY_CTX_get_data(evp_created_ctx);
    created->static_my_key = signing_sta;
    #endif

    if (1 != EVP_DigestSignUpdate(evp_md_ctx, msg, sizeof(msg)))
        return 0;

    unsigned char *sig = OPENSSL_malloc(sizeof(unsigned char) * 65);
    sig[64] = '\0';
    size_t sig_len = 4;

    //FIXME unhandled return value
    EVP_DigestSignFinal(evp_md_ctx, NULL, &sig_len);

    if (1 != EVP_DigestSignFinal(evp_md_ctx, sig, &sig_len))
        return 0;

    printf("-----\nsignature %zd \n", sig_len);
    for (int i = 0; i < sig_len; ++i)
    {
        printf("%02x", sig[i]);
        if (!((i + 1) % 4))
            printf(" ");
    }
    printf("\n");

    unsigned char expect[] =
        {0x40, 0xf1, 0xec, 0x59, 0xf7, 0x93, 0xd9, 0xf4, 0x9e, 0x09, 0xdc, 0xef,
            0x49, 0x13, 0x0d, 0x41, 0x94, 0xf7, 0x9f, 0xb1, 0xee, 0xd2, 0xca,
            0xa5,
            0x5b, 0xac, 0xdb, 0x49, 0xc4, 0xe7, 0x55, 0xd1, 0x6f, 0xc6, 0xda,
            0xc3,
            0x2c, 0x5d, 0x5c, 0xf1, 0x0c, 0x77, 0xdf, 0xb2, 0x0f, 0x7c, 0x2e,
            0xb6,
            0x67, 0xa4, 0x57, 0x87, 0x2f, 0xb0, 0x9e, 0xc5, 0x63, 0x27, 0xa6,
            0x7e,
            0xc7, 0xde, 0xeb, 0xe7};

    int pass = 0;
    pass = CRYPTO_memcmp(expect, sig, 64);
    if (pass)
        FAIL;
    else
        PASS;

    EVP_PKEY_free(signing_eph);
    EVP_PKEY_free(signing_sta);
    EVP_PKEY_CTX_free(ctx_sign_eph);
    EVP_PKEY_CTX_free(ctx_sign_sta);
    EVP_MD_CTX_destroy(evp_md_ctx);
    OPENSSL_free(sig);

    return (pass) ? 0 : 1;
}

int
test_verify()
{
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_create();

    EVP_PKEY_CTX *pkey_ctx;
    int sm2_id = OBJ_sn2nid("sm2");
    pkey_ctx = EVP_PKEY_CTX_new_id(sm2_id, engine);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen_init(pkey_ctx);
    EVP_PKEY_keygen(pkey_ctx, &pkey);

    EVP_DigestVerifyInit(md_ctx,
                         NULL,
                         EVP_get_digestbynid(OBJ_sn2nid("sm3-256")),
                         engine,
                         pkey);

    unsigned char msg[] =
        {0xf4, 0xa3, 0x84, 0x89, 0xe3, 0x2b, 0x45, 0xb6, 0xf8, 0x76, 0xe3, 0xac,
            0x21, 0x68, 0xca, 0x39, 0x23, 0x62, 0xdc, 0x8f, 0x23, 0x45, 0x9c,
            0x1d, 0x11, 0x46, 0xfc, 0x3d, 0xbf, 0xb7, 0xbc, 0x9a, 0x6d, 0x65,
            0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x64, 0x69, 0x67, 0x65, 0x73,
            0x74};

    EVP_DigestVerifyUpdate(md_ctx, msg, sizeof(msg));

    unsigned char sig[] =
        {0x40, 0xf1, 0xec, 0x59, 0xf7, 0x93, 0xd9, 0xf4, 0x9e, 0x09, 0xdc, 0xef,
            0x49, 0x13, 0x0d, 0x41, 0x94, 0xf7, 0x9f, 0xb1, 0xee, 0xd2, 0xca,
            0xa5, 0x5b, 0xac, 0xdb, 0x49, 0xc4, 0xe7, 0x55, 0xd1, 0x6f, 0xc6,
            0xda, 0xc3, 0x2c, 0x5d, 0x5c, 0xf1, 0x0c, 0x77, 0xdf, 0xb2, 0x0f,
            0x7c, 0x2e, 0xb6, 0x67, 0xa4, 0x57, 0x87, 0x2f, 0xb0, 0x9e, 0xc5,
            0x63, 0x27, 0xa6, 0x7e, 0xc7, 0xde, 0xeb, 0xe7};

    printf("signature verify ");
    int pass = 0;
    if (1 == (pass = EVP_DigestVerifyFinal(md_ctx, sig, 64)))
        PASS;
    else
        FAIL;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_destroy(md_ctx);

    return (pass) ? 1 : 0;
}

int
test_asym_enc()
{
    int pass = 1;

    BN_CTX *bn_ctx;
    EVP_PKEY_CTX *pkey_ctx, *tctx;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn_priv_sta, *bn_px, *bn_py;
    EC_KEY *ec_sta;
    EVP_PKEY *pkey_sta = NULL;
    size_t out_len;
    unsigned char *out = NULL;

    bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    bn_priv_sta = BN_CTX_get(bn_ctx);
    bn_px = BN_CTX_get(bn_ctx);
    bn_py = BN_CTX_get(bn_ctx);

    int sm2_id = OBJ_sn2nid("sm2");

    tctx = EVP_PKEY_CTX_new_id(sm2_id, engine);
    pkey_ctx_t *data = EVP_PKEY_CTX_get_data(tctx);
    data->curve_id = OBJ_sn2nid("sm2_curve");

    EVP_PKEY_keygen_init(tctx);
    EVP_PKEY_keygen(tctx, &pkey);

    pkey_ctx = EVP_PKEY_CTX_new(pkey, engine);
    EVP_PKEY *rand = EVP_PKEY_CTX_get0_pkey(pkey_ctx);

    unsigned char priv_sta[] =
        {0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a,
            0xc6, 0xd3, 0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5,
            0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8};
    unsigned char px_sta[] =
        {0x09, 0xf9, 0xdf, 0x31, 0x1e, 0x54, 0x21, 0xa1, 0x50, 0xdd, 0x7d, 0x16,
            0x1e, 0x4b, 0xc5, 0xc6, 0x72, 0x17, 0x9f, 0xad, 0x18, 0x33, 0xfc,
            0x07, 0x6b, 0xb0, 0x8f, 0xf3, 0x56, 0xf3, 0x50, 0x20};
    unsigned char py_sta[] =
        {0xcc, 0xea, 0x49, 0x0c, 0xe2, 0x67, 0x75, 0xa5, 0x2d, 0xc6, 0xea, 0x71,
            0x8c, 0xc1, 0xaa, 0x60, 0x0a, 0xed, 0x05, 0xfb, 0xf3, 0x5e, 0x08,
            0x4a, 0x66, 0x32, 0xf6, 0x07, 0x2d, 0xa9, 0xad, 0x13};

    BN_bin2bn(priv_sta, 32, bn_priv_sta);
    BN_bin2bn(px_sta, 32, bn_px);
    BN_bin2bn(py_sta, 32, bn_py);

    ec_sta = EC_KEY_new();
    if (1 != EC_KEY_set_group(ec_sta, EC_KEY_get0_group(EVP_PKEY_get0(pkey))))
        goto err;

    if (1 != EC_KEY_set_private_key(ec_sta, bn_priv_sta))
        goto err;

    if (0 == EC_KEY_set_public_key_affine_coordinates(ec_sta, bn_px, bn_py))
        goto err;

    pkey_sta = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey_sta, ec_sta);
    EC_KEY_free(ec_sta);

    EVP_PKEY_CTX_ctrl_str(pkey_ctx, EVP_PKEY_SET_MY_KEY, (char *) pkey_sta);
    #if 0
    data = EVP_PKEY_CTX_get_data(pkey_ctx);
    data->static_my_key = pkey_sta;
    #endif

    unsigned char msg[] =
        {0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
            0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64};

    EVP_PKEY_encrypt_init(pkey_ctx);
    EVP_PKEY_encrypt(pkey_ctx, NULL, &out_len, msg, 19);

    out = OPENSSL_malloc(out_len);
    if (1 != EVP_PKEY_encrypt(pkey_ctx, out, &out_len, msg, 19))
        goto err;

    unsigned char expect[] =
        {0x04, 0x04, 0xeb, 0xfc, 0x71, 0x8e, 0x8d, 0x17, 0x98, 0x62, 0x04, 0x32,
            0x26, 0x8e, 0x77, 0xfe, 0xb6, 0x41, 0x5e, 0x2e, 0xde, 0x0e, 0x07,
            0x3c, 0x0f, 0x4f, 0x64, 0x0e, 0xcd, 0x2e, 0x14, 0x9a, 0x73, 0xe8,
            0x58, 0xf9, 0xd8, 0x1e, 0x54, 0x30, 0xa5, 0x7b, 0x36, 0xda, 0xab,
            0x8f, 0x95, 0x0a, 0x3c, 0x64, 0xe6, 0xee, 0x6a, 0x63, 0x09, 0x4d,
            0x99, 0x28, 0x3a, 0xff, 0x76, 0x7e, 0x12, 0x4d, 0xf0, 0x59, 0x98,
            0x3c, 0x18, 0xf8, 0x09, 0xe2, 0x62, 0x92, 0x3c, 0x53, 0xae, 0xc2,
            0x95, 0xd3, 0x03, 0x83, 0xb5, 0x4e, 0x39, 0xd6, 0x09, 0xd1, 0x60,
            0xaf, 0xcb, 0x19, 0x08, 0xd0, 0xbd, 0x87, 0x66, 0x21, 0x88, 0x6c,
            0xa9, 0x89, 0xca, 0x9c, 0x7d, 0x58, 0x08, 0x73, 0x07, 0xca, 0x93,
            0x09, 0x2d, 0x65, 0x1e, 0xfa};

    pass = CRYPTO_memcmp(expect, out, sizeof(expect));
    printf("asymmetric encryption ");
    if (pass)
        FAIL;
    else
        PASS;

    err:
    OPENSSL_free(out);
    EVP_PKEY_free(pkey_sta);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_CTX_free(tctx);

    if (bn_ctx)
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }
    return (pass) ? 0 : 1;
}

int
test_asym_dec()
{
    BN_CTX *bn_ctx;

    bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);

    EVP_PKEY_CTX *tctx, *ctx;
    EVP_PKEY *pkey = NULL;

    tctx = EVP_PKEY_CTX_new_id(OBJ_sn2nid("sm2"), engine);
    pkey_ctx_t *data = EVP_PKEY_CTX_get_data(tctx);
    data->curve_id = OBJ_sn2nid("sm2_curve");

    EVP_PKEY_keygen_init(tctx);
    EVP_PKEY_keygen(tctx, &pkey);

    ctx = EVP_PKEY_CTX_new(pkey, engine);

    unsigned char cipher[] =
        {0x04, 0x04, 0xeb, 0xfc, 0x71, 0x8e, 0x8d, 0x17, 0x98, 0x62, 0x04, 0x32,
            0x26, 0x8e, 0x77, 0xfe, 0xb6, 0x41, 0x5e, 0x2e, 0xde, 0x0e, 0x07,
            0x3c, 0x0f, 0x4f, 0x64, 0x0e, 0xcd, 0x2e, 0x14, 0x9a, 0x73, 0xe8,
            0x58, 0xf9, 0xd8, 0x1e, 0x54, 0x30, 0xa5, 0x7b, 0x36, 0xda, 0xab,
            0x8f, 0x95, 0x0a, 0x3c, 0x64, 0xe6, 0xee, 0x6a, 0x63, 0x09, 0x4d,
            0x99, 0x28, 0x3a, 0xff, 0x76, 0x7e, 0x12, 0x4d, 0xf0, 0x59, 0x98,
            0x3c, 0x18, 0xf8, 0x09, 0xe2, 0x62, 0x92, 0x3c, 0x53, 0xae, 0xc2,
            0x95, 0xd3, 0x03, 0x83, 0xb5, 0x4e, 0x39, 0xd6, 0x09, 0xd1, 0x60,
            0xaf, 0xcb, 0x19, 0x08, 0xd0, 0xbd, 0x87, 0x66, 0x21, 0x88, 0x6c,
            0xa9, 0x89, 0xca, 0x9c, 0x7d, 0x58, 0x08, 0x73, 0x07, 0xca, 0x93,
            0x09, 0x2d, 0x65, 0x1e, 0xfa};

    EVP_PKEY_decrypt_init(ctx);

    size_t out_len = 0;
    EVP_PKEY_decrypt(ctx, NULL, &out_len, cipher, sizeof(cipher));

    unsigned char *plaintext = OPENSSL_malloc(out_len);

    EVP_PKEY_decrypt(ctx, plaintext, &out_len, cipher, sizeof(cipher));

    unsigned char expect[] =
        {0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
            0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64};

    int pass = CRYPTO_memcmp(plaintext, expect, sizeof(expect));

    printf("asymmetric decryption ");
    if (pass)
        FAIL;
    else
        PASS;

    OPENSSL_free(plaintext);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(tctx);
    if (bn_ctx)
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    return (pass) ? 0 : 1;
}

int
test_cipher_enc1()
{
    uint8_t k1[16];
    memset(k1, 0, 16);

    uint8_t v1[12];
    memset(v1, 0, 12);

    uint8_t t1[16];
    memset(t1, 0, 16);

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx,
                                EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                                engine,
                                NULL,
                                NULL))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, k1, v1))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, 0))
        return 0;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, NULL, &len))
        return 0;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, t1))
        return 0;

    for (int i = 0; i < 16; ++i)
        printf("%02x", t1[i]);
    printf("\n");

    printf("cipher length is %d.\n\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    printf("cipher enc 1\n");
    PASS;
    return 1;
}

int
test_cipher_enc2()
{
    uint8_t k2[16];
    memset(k2, 0, 16);

    uint8_t iv2[12];
    memset(iv2, 0, 16);

    uint8_t p2[16];
    memset(p2, 0, 16);

    uint8_t c2[16];
    memset(c2, 0, 16);

    uint8_t t2[16];
    memset(t2, 0, 16);

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx,
                                EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                                engine,
                                NULL,
                                NULL))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, k2, iv2))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, c2, &len, p2, sizeof(p2)))
        return 0;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, c2 + len, &len))
        return 0;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, t2))
        return 0;

    for (int i = 0; i < 16; ++i)
        printf("%02x", c2[i]);
    printf("\n");

    for (int i = 0; i < 16; ++i)
        printf("%02x", t2[i]);
    printf("\n");

    printf("cipher length is %d.\n\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    printf("cipher enc 2\n");
    PASS;
    return 1;
}

int
test_cipher_enc3()
{
    uint8_t k3[16] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv3[12] =
        {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8,
            0x88};
    uint8_t p3[64] =
        {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
            0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7,
            0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c,
            0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
            0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55};

    uint8_t c3[64];
    memset(c3, 0, 64);

    uint8_t t3[16];
    memset(t3, 0, 16);

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx,
                                EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                                engine,
                                NULL,
                                NULL))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, k3, iv3))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, c3, &len, p3, sizeof(p3)))
        return 0;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, c3 + len, &len))
        return 0;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, t3))
        return 0;

    for (int i = 0; i < 64; ++i)
        printf("%02x", c3[i]);
    printf("\n");

    for (int i = 0; i < 16; ++i)
        printf("%02x", t3[i]);
    printf("\n");

    printf("cipher length is %d.\n\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    printf("cipher enc 3\n");
    PASS;
    return 1;
}

int
test_cipher_enc4()
{
    uint8_t k4[16] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv4[12] =
        {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8,
            0x88};
    uint8_t p4[60] =
        {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
            0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7,
            0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c,
            0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
            0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39};
    uint8_t a4[20] =
        {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
            0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t c4[60];
    memset(c4, 0, 60);

    uint8_t t4[16];
    memset(t4, 0, 16);

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx,
                                EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                                engine,
                                NULL,
                                NULL))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, k4, iv4))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, a4, sizeof(a4)))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, c4, &len, p4, sizeof(p4)))
        return 0;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, c4 + len, &len))
        return 0;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, t4))
        return 0;

    for (int i = 0; i < 60; ++i)
        printf("%02x", c4[i]);
    printf("\n");

    for (int i = 0; i < 16; ++i)
        printf("%02x", t4[i]);
    printf("\n");

    printf("cipher length is %d.\n\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    printf("cipher enc 4\n");
    PASS;
    return 1;
}

int
test_cipher_enc5()
{
    uint8_t k5[16] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv5[8] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad};
    uint8_t p5[60] =
        {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
            0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7,
            0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c,
            0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
            0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39};
    uint8_t a5[20] =
        {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
            0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t c5[60];
    memset(c5, 0, 60);

    uint8_t t5[16];
    memset(t5, 0, 16);

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx,
                                EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                                engine,
                                NULL,
                                NULL))
        return 0;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 8, NULL))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, k5, iv5))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, a5, sizeof(a5)))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, c5, &len, p5, sizeof(p5)))
        return 0;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, c5 + len, &len))
        return 0;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, t5))
        return 0;

    for (int i = 0; i < 60; ++i)
        printf("%02x", c5[i]);
    printf("\n");

    for (int i = 0; i < 16; ++i)
        printf("%02x", t5[i]);
    printf("\n");

    printf("cipher length is %d.\n\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    printf("cipher enc 5\n");
    PASS;
    return 1;
}

int
test_cipher_enc6()
{
    uint8_t k6[] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv6[60] =
        {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a,
            0xff, 0x52, 0x69, 0xaa, 0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d,
            0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28, 0xc3, 0xc0,
            0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a,
            0x6b, 0x52, 0x54, 0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
            0xa6, 0x37, 0xb3, 0x9b};
    uint8_t p6[60] =
        {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
            0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7,
            0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c,
            0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
            0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39};
    uint8_t a6[20] =
        {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
            0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t c6[60];
    memset(c6, 0, 60);

    uint8_t t6[16];
    memset(t6, 0, 16);

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx,
                                EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                                engine,
                                NULL,
                                NULL))
        return 0;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 60, NULL))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, k6, iv6))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, a6, sizeof(a6)))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, c6, &len, p6, sizeof(p6)))
        return 0;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, c6 + len, &len))
        return 0;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, t6))
        return 0;

    for (int i = 0; i < 60; ++i)
        printf("%02x", c6[i]);
    printf("\n");

    for (int i = 0; i < 16; ++i)
        printf("%02x", t6[i]);
    printf("\n");

    printf("cipher length is %d.\n\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    printf("cipher enc 6\n");
    PASS;
    return 1;
}

int
test_cipher_enc7()
{
    uint8_t k7[] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv7[60] =
        {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a,
            0xff, 0x52, 0x69, 0xaa, 0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d,
            0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28, 0xc3, 0xc0,
            0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a,
            0x6b, 0x52, 0x54, 0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
            0xa6, 0x37, 0xb3, 0x9b};
    uint8_t p71[16] =
        {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
            0xaf, 0xf5, 0x26, 0x9a};
    uint8_t p72[16] =
        {0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72};
    uint8_t p73[28] =
        {0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24,
            0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6,
            0x57, 0xba, 0x63, 0x7b, 0x39};

    uint8_t a71[10] =
        {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed};
    uint8_t
        a72[10] = {0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t c7[60];
    memset(c7, 0, 60);

    uint8_t t7[16];
    memset(t7, 0, 16);

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx,
                                EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                                engine,
                                NULL,
                                NULL))
        return 0;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 60, NULL))
        return 0;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, k7, iv7))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, a71, sizeof(a71)))
        return 0;
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, a72, sizeof(a72)))
        return 0;

    if (1 != EVP_EncryptUpdate(ctx, c7, &len, p71, sizeof(p71)))
        return 0;
    ciphertext_len = len;

    if (1
        != EVP_EncryptUpdate(ctx, c7 + ciphertext_len, &len, p72, sizeof(p72)))
        return 0;
    ciphertext_len += len;

    if (1
        != EVP_EncryptUpdate(ctx, c7 + ciphertext_len, &len, p73, sizeof(p73)))
        return 0;
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, c7 + len, &len))
        return 0;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, t7))
        return 0;

    for (int i = 0; i < 60; ++i)
        printf("%02x", c7[i]);
    printf("\n");

    for (int i = 0; i < 16; ++i)
        printf("%02x", t7[i]);
    printf("\n");

    printf("cipher length is %d.\n\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    printf("cipher enc 7\n");
    PASS;
    return 1;
}

int
test_cipher_dec2()
{
    uint8_t k2d[] =
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,};
    uint8_t c2d[16] =
        {0x7d, 0xe2, 0xaa, 0x7f, 0x11, 0x10, 0x18, 0x82, 0x18, 0x06, 0x3b, 0xe1,
            0xbf, 0xeb, 0x6d, 0x89};
    uint8_t t2d[] =
        {0xb8, 0x51, 0xb5, 0xf3, 0x94, 0x93, 0x75, 0x2b, 0xe5, 0x08, 0xf1, 0xbb,
            0x44, 0x82, 0xc5, 0x57};
    uint8_t iv2d[12] =
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,};

    uint8_t p2d[16];
    memset(p2d, 0, 16);

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (!EVP_DecryptInit_ex(ctx,
                            EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                            engine,
                            NULL,
                            NULL))
        return 0;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, k2d, iv2d))
        return 0;

    if (!EVP_DecryptUpdate(ctx, p2d, &len, c2d, 16))
        return 0;
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, t2d))
        return 0;

    ret = EVP_DecryptFinal_ex(ctx, p2d + len, &len);

    for (int i = 0; i < 16; ++i)
        printf("%02x", p2d[i]);
    printf("\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if (ret)
        PASS;
    else
        FAIL;

    return ret;
}

int
test_cipher_dec3()
{
    uint8_t k3d[] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t c3d[64] =
        {0xe4, 0x11, 0x0f, 0xf1, 0xc1, 0x41, 0x97, 0xe6, 0x76, 0x21, 0x6a, 0x33,
            0x83, 0x10, 0x41, 0xeb, 0x09, 0x58, 0x00, 0x11, 0x7b, 0xdc, 0x3f,
            0x75, 0x1a, 0x49, 0x6e, 0xfc, 0xf2, 0xbb, 0xdf, 0xdb, 0x3a, 0x2e,
            0x13, 0xfd, 0xc5, 0xc1, 0x9d, 0x07, 0x1a, 0xe5, 0x48, 0x3f, 0xed,
            0xde, 0x98, 0x5d, 0x3f, 0x2d, 0x5b, 0x4e, 0xee, 0x0b, 0xb6, 0xdf,
            0xe3, 0x63, 0x36, 0x83, 0x23, 0xf7, 0x5b, 0x80};
    uint8_t t3d[] =
        {0x7d, 0xfe, 0x77, 0xef, 0x71, 0xb1, 0x5e, 0xc9, 0x52, 0x6b, 0x09, 0xab,
            0x84, 0x28, 0x4b, 0x8a};
    uint8_t iv3d[] =
        {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8,
            0x88};

    uint8_t p3d[64];
    memset(p3d, 0, 64);

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (!EVP_DecryptInit_ex(ctx,
                            EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                            engine,
                            NULL,
                            NULL))
        return 0;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, k3d, iv3d))
        return 0;

    if (!EVP_DecryptUpdate(ctx, p3d, &len, c3d, 64))
        return 0;
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, t3d))
        return 0;

    ret = EVP_DecryptFinal_ex(ctx, p3d, &len);

    for (int i = 0; i < plaintext_len; ++i)
        printf("%02x", p3d[i]);
    printf("\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if (ret)
        PASS;
    else
        FAIL;

    return ret;
}

int
test_cipher_dec4()
{
    uint8_t k4d[] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t c4d[60] =
        {0xe4, 0x11, 0x0f, 0xf1, 0xc1, 0x41, 0x97, 0xe6, 0x76, 0x21, 0x6a, 0x33,
            0x83, 0x10, 0x41, 0xeb, 0x09, 0x58, 0x00, 0x11, 0x7b, 0xdc, 0x3f,
            0x75, 0x1a, 0x49, 0x6e, 0xfc, 0xf2, 0xbb, 0xdf, 0xdb, 0x3a, 0x2e,
            0x13, 0xfd, 0xc5, 0xc1, 0x9d, 0x07, 0x1a, 0xe5, 0x48, 0x3f, 0xed,
            0xde, 0x98, 0x5d, 0x3f, 0x2d, 0x5b, 0x4e, 0xee, 0x0b, 0xb6, 0xdf,
            0xe3, 0x63, 0x36, 0x83};
    uint8_t t4d[16] =
        {0x89, 0xf6, 0xba, 0x35, 0xb8, 0x18, 0xd3, 0xcc, 0x38, 0x6c, 0x05, 0xb3,
            0x8a, 0xcb, 0xc9, 0xde};
    uint8_t iv4d[12] =
        {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8,
            0x88};
    uint8_t a4d[20] =
        {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
            0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t p4d[60];
    memset(p4d, 0, 60);

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (!EVP_DecryptInit_ex(ctx,
                            EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                            engine,
                            NULL,
                            NULL))
        return 0;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, k4d, iv4d))
        return 0;

    if (!EVP_DecryptUpdate(ctx, NULL, &len, a4d, sizeof(a4d)))
        return 0;

    if (!EVP_DecryptUpdate(ctx, p4d, &len, c4d, 60))
        return 0;
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, t4d))
        return 0;

    ret = EVP_DecryptFinal_ex(ctx, p4d, &len);

    for (int i = 0; i < plaintext_len; ++i)
        printf("%02x", p4d[i]);
    printf("\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if (ret)
        PASS;
    else
        FAIL;

    return ret;
}

int
test_cipher_dec5()
{
    uint8_t k5d[] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv5d[8] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad};
    uint8_t c5d[60] =
        {0x47, 0xe6, 0xba, 0xb5, 0xc2, 0xf2, 0x93, 0xcd, 0x8a, 0x8b, 0x18, 0xd6,
            0xfd, 0xef, 0x1b, 0xbd, 0x14, 0xae, 0xa6, 0xe2, 0x6a, 0x3d, 0xe8,
            0xc5, 0x68, 0xbf, 0x7a, 0x5a, 0x35, 0xe8, 0x64, 0xb4, 0xfc, 0x7f,
            0x3c, 0x5a, 0x48, 0x90, 0xde, 0xee, 0xc6, 0xcb, 0x8d, 0x40, 0x9e,
            0x30, 0xa3, 0xb7, 0x61, 0x9a, 0x3f, 0x61, 0x17, 0xbf, 0x5f, 0x70,
            0x4f, 0xd7, 0xfe, 0xe4};
    uint8_t t5d[] =
        {0x39, 0xe8, 0x7b, 0x47, 0x3b, 0xa4, 0xc9, 0x2b, 0x58, 0xe0, 0x97, 0x0e,
            0x12, 0x49, 0x2c, 0x0e};
    uint8_t a5d[] =
        {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
            0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t p5d[60];
    memset(p5d, 0, 60);

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (!EVP_DecryptInit_ex(ctx,
                            EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                            engine,
                            NULL,
                            NULL))
        return 0;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 8, NULL))
        return 0;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, k5d, iv5d))
        return 0;

    if (!EVP_DecryptUpdate(ctx, NULL, &len, a5d, sizeof(a5d)))
        return 0;

    if (!EVP_DecryptUpdate(ctx, p5d, &len, c5d, 60))
        return 0;
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, t5d))
        return 0;

    ret = EVP_DecryptFinal_ex(ctx, p5d, &len);

    for (int i = 0; i < plaintext_len; ++i)
        printf("%02x", p5d[i]);
    printf("\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if (ret)
        PASS;
    else
        FAIL;

    return ret;
}

int
test_cipher_dec6()
{
    uint8_t k6d[] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv6d[60] =
        {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a,
            0xff, 0x52, 0x69, 0xaa, 0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d,
            0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28, 0xc3, 0xc0,
            0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a,
            0x6b, 0x52, 0x54, 0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
            0xa6, 0x37, 0xb3, 0x9b};
    uint8_t c6d[60] =
        {0x9a, 0x05, 0xc6, 0x8e, 0x20, 0x8a, 0x75, 0x51, 0x31, 0x51, 0x7d, 0x0a,
            0xe2, 0xf2, 0xeb, 0x82, 0x1f, 0x4b, 0x14, 0x12, 0x24, 0xd2, 0xb9,
            0xf8, 0x73, 0xc6, 0x4a, 0xd0, 0x85, 0x41, 0x76, 0xdb, 0xef, 0x27,
            0xae, 0x96, 0xfd, 0x90, 0x40, 0x9f, 0x4e, 0xe2, 0x02, 0xba, 0x6e,
            0x04, 0xd7, 0x34, 0x5b, 0x55, 0x14, 0x86, 0x65, 0x02, 0xdd, 0x68,
            0x8a, 0x06, 0xb2, 0xba};
    uint8_t t6d[] =
        {0x4f, 0x78, 0xdf, 0x5d, 0x96, 0xdf, 0x6d, 0xd6, 0x4e, 0x8c, 0xd8, 0x25,
            0x1c, 0xc6, 0x7d, 0x31};
    uint8_t a6d[] =
        {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
            0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t p6d[60];
    memset(p6d, 0, 60);

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (!EVP_DecryptInit_ex(ctx,
                            EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                            engine,
                            NULL,
                            NULL))
        return 0;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 60, NULL))
        return 0;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, k6d, iv6d))
        return 0;

    if (!EVP_DecryptUpdate(ctx, NULL, &len, a6d, sizeof(a6d)))
        return 0;

    if (!EVP_DecryptUpdate(ctx, p6d, &len, c6d, 60))
        return 0;
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, t6d))
        return 0;

    ret = EVP_DecryptFinal_ex(ctx, p6d, &len);

    for (int i = 0; i < plaintext_len; ++i)
        printf("%02x", p6d[i]);
    printf("\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if (ret)
        PASS;
    else
        FAIL;

    return ret;
}

int
test_cipher_dec7()
{
    uint8_t k7d[] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv7d[60] =
        {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a,
            0xff, 0x52, 0x69, 0xaa, 0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d,
            0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28, 0xc3, 0xc0,
            0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a,
            0x6b, 0x52, 0x54, 0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
            0xa6, 0x37, 0xb3, 0x9b};
    uint8_t c7d1[16] =
        {0x9a, 0x05, 0xc6, 0x8e, 0x20, 0x8a, 0x75, 0x51, 0x31, 0x51, 0x7d, 0x0a,
            0xe2, 0xf2, 0xeb, 0x82};
    uint8_t c7d2[32] =
        {0x1f, 0x4b, 0x14, 0x12, 0x24, 0xd2, 0xb9, 0xf8, 0x73, 0xc6, 0x4a, 0xd0,
            0x85, 0x41, 0x76, 0xdb, 0xef, 0x27, 0xae, 0x96, 0xfd, 0x90, 0x40,
            0x9f,
            0x4e, 0xe2, 0x02, 0xba, 0x6e, 0x04, 0xd7, 0x34};
    uint8_t c7d3[] =
        {0x5b, 0x55, 0x14, 0x86, 0x65, 0x02, 0xdd, 0x68, 0x8a, 0x06, 0xb2,
            0xba};

    uint8_t t7d[] =
        {0x4f, 0x78, 0xdf, 0x5d, 0x96, 0xdf, 0x6d, 0xd6, 0x4e, 0x8c, 0xd8, 0x25,
            0x1c, 0xc6, 0x7d, 0x31};
    uint8_t
        a7d1[10] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed};
    uint8_t
        a7d2[10] = {0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t p7d[60];
    memset(p7d, 0, 60);

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (!EVP_DecryptInit_ex(ctx,
                            EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                            engine,
                            NULL,
                            NULL))
        return 0;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 60, NULL))
        return 0;

    if (!
        EVP_DecryptInit_ex(ctx, NULL, NULL, k7d, iv7d))
        return 0;

    if (!
        EVP_DecryptUpdate(ctx, NULL, &len, a7d1, sizeof(a7d1)))
        return 0;
    if (!
        EVP_DecryptUpdate(ctx, NULL, &len, a7d2, sizeof(a7d2)))
        return 0;

    if (!EVP_DecryptUpdate(ctx, p7d, &len, c7d1, sizeof(c7d1)))
        return 0;
    plaintext_len = len;

    if (!EVP_DecryptUpdate(ctx, p7d + plaintext_len, &len, c7d2, sizeof(c7d2)))
        return 0;
    plaintext_len += len;

    if (!EVP_DecryptUpdate(ctx, p7d + plaintext_len, &len, c7d3, sizeof(c7d3)))
        return 0;
    plaintext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, t7d))
        return 0;

    ret = EVP_DecryptFinal_ex(ctx, p7d, &len);

    for (int i = 0; i < plaintext_len; ++i)
        printf("%02x", p7d[i]);
    printf("\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if (ret)
        PASS;
    else
        FAIL;

    return ret;
}

int
test_cipher_dec8()
{
    uint8_t k7d[] =
        {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08};
    uint8_t iv7d[60] =
        {0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5, 0x55, 0x90, 0x9c, 0x5a,
            0xff, 0x52, 0x69, 0xaa, 0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d,
            0xa1, 0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28, 0xc3, 0xc0,
            0xc9, 0x51, 0x56, 0x80, 0x95, 0x39, 0xfc, 0xf0, 0xe2, 0x42, 0x9a,
            0x6b, 0x52, 0x54, 0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
            0xa6, 0x37, 0xb3,
            0x9b};
    uint8_t c7d1[16] =
        {0x9a, 0x05, 0xc6, 0x8e, 0x20, 0x8a, 0x75, 0x51, 0x31, 0x51, 0x7d, 0x0a,
            0xe2, 0xf2, 0xeb, 0x82};
    uint8_t c7d2[32] =
        {0x1f, 0x4b, 0x14, 0x12, 0x24, 0xd2, 0xb9, 0xf8, 0x73, 0xc6, 0x4a, 0xd0,
            0x85, 0x41, 0x76, 0xdb, 0xef, 0x27, 0xae, 0x96, 0xfd, 0x90, 0x40,
            0x9f,
            0x4e, 0xe2, 0x02, 0xba, 0x6e, 0x04, 0xd7, 0x34};
    uint8_t c7d3[] =
        {0x5b, 0x55, 0x14, 0x86, 0x65, 0x02, 0xdd, 0x68, 0x8a, 0x06, 0xb2,
            0xba};

    // this case in meant to fail tag verification
    uint8_t t7d[] =
        {0x00, 0x78, 0xdf, 0x5d, 0x96, 0xdf, 0x6d, 0xd6, 0x4e, 0x8c, 0xd8, 0x25,
            0x1c, 0xc6, 0x7d, 0x31};
    uint8_t
        a7d1[10] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed};
    uint8_t
        a7d2[10] = {0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    uint8_t p7d[60];
    memset(p7d, 0, 60);

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (!EVP_DecryptInit_ex(ctx,
                            EVP_get_cipherbynid(OBJ_sn2nid(SN_sm4_gcm)),
                            engine,
                            NULL,
                            NULL))
        return 0;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 60, NULL))
        return 0;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, k7d, iv7d))
        return 0;

    if (!EVP_DecryptUpdate(ctx, NULL, &len, a7d1, sizeof(a7d1)))
        return 0;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, a7d2, sizeof(a7d2)))
        return 0;

    if (!EVP_DecryptUpdate(ctx, p7d, &len, c7d1, sizeof(c7d1)))
        return 0;
    plaintext_len = len;

    if (!EVP_DecryptUpdate(ctx, p7d + plaintext_len, &len, c7d2, sizeof(c7d2)))
        return 0;
    plaintext_len += len;

    if (!EVP_DecryptUpdate(ctx, p7d + plaintext_len, &len, c7d3, sizeof(c7d3)))
        return 0;
    plaintext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, t7d))
        return 0;

    ret = EVP_DecryptFinal_ex(ctx, p7d, &len);

    for (int i = 0; i < plaintext_len; ++i)
        printf("%02x", p7d[i]);
    printf("\n");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if (ret)
        FAIL;
    else
        PASS;

    return (ret) ? 0 : 1;
}

void
engine_cleanup()
{
    ENGINE_finish(engine);
    ENGINE_free(engine);

    FIPS_mode_set(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();       // on each thread
    ERR_remove_thread_state(NULL);      // on each thread
    ERR_free_strings();
}