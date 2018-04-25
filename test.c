#include <stdio.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <memory.h>
#include "pkey/sm2.h"

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

void test_ecdh();

void test_signing();

void test_verify();

void test_asym_enc();

void test_asym_dec();

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

    test_ecdh();
    test_signing();
    test_verify();
    test_asym_enc();
    test_asym_dec();

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

void
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
    {
        return;
    }

    /*
     * REVIEW reference to library header
     * test program need to reference additional header other than .so
     */

    if (1 != EVP_PKEY_keygen_init(kctx))
    {
        printf("2222\n");
        return;
    }

    if (1 != EVP_PKEY_keygen(kctx, &pkey))
    {
        printf("3333\n");
        ERR_print_errors_fp(stdout);
        return;
    }

    EC_KEY *key = EVP_PKEY_get0(pkey);
    printf("myyy generated private is ");
    BN_print_fp(stdout, EC_KEY_get0_private_key(key));
    printf("\n");

    pctx = EVP_PKEY_CTX_new_id(sm2_id, engine);
#if 0
    sm2_keyx_ctx_t *data2 = OPENSSL_malloc(sizeof(sm2_keyx_ctx_t));
    data2->curve_id = OBJ_sn2nid(SN_sm2_curve);
    data2->static_my_key = NULL;
    data2->static_peer_pub = NULL;
    data2->za = NULL;
    data2->zb = NULL;
    EVP_PKEY_CTX_set_data(pctx, data2);
#endif
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &peer);
    key = EVP_PKEY_get0(peer);
    printf("peer generated private is ");
    BN_print_fp(stdout, EC_KEY_get0_private_key(key));
    printf("\n");


    // start derive
    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, engine)))
    {
        ERR_print_errors_fp(stdout);
        return;
    }
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

#if 0
    sm2_keyx_ctx_t *data3 = OPENSSL_malloc(sizeof(sm2_keyx_ctx_t));
    data3->curve_id = OBJ_sn2nid(SN_sm2_curve);
    data3->static_peer_pub = sta_p;
    data3->static_my_key = sta;
    data3->za = pa;
    data3->zb = pb;
    //memcpy(data3->za, uza, 32);
    //memcpy(data3->zb, uzb, 32);
    EVP_PKEY_CTX_set_data(ctx, data3);
#endif
    pkey_ctx_t *data = EVP_PKEY_CTX_get_data(ctx);
    data->static_peer_pub = sta_p;
    data->static_my_key = sta;
    data->za = pa;
    data->zb = pb;

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
}

void
test_signing()
{
    printf("\n");
    //char *msg = "message digest";

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

    //const char *ecdsa_priv_hex = "128b2fa8bd433c6c068c8d803dff7979a2519a55171b1b650c23661d15897263";
    //const char *ecdsa_x_hex = "0ae4c7798aa0F119471bee11825bE46202BB79E2a5844495E97C04FF4df2548a";
    //const char *ecdsa_y_hex = "7c0240f88f1cd4e16352a73c17b7f16f07353e53a176d684a9fe0c6bb798e857";

    EVP_PKEY_keygen_init(ctx_sign_sta);
    EVP_PKEY_keygen(ctx_sign_sta, &signing_sta);

    EVP_PKEY_CTX *ctx_sign_eph;
    ctx_sign_eph = EVP_PKEY_CTX_new(signing_sta, engine);
    EVP_PKEY *signing_eph = NULL;

    //SM2_CTX *data5 = EVP_PKEY_CTX_get_data(ctx_sign_eph);
    //data5->static_my_key = signing_sta;

    EVP_PKEY_keygen_init(ctx_sign_eph);
    EVP_PKEY_keygen(ctx_sign_eph, &signing_eph);

    printf("expecting ctx is %p\n", ctx_sign_eph);

    //evp_md_ctx->pctx = ctx_sign_sta;
    int err = 0;
    if (1 != (
        err = EVP_DigestSignInit(evp_md_ctx,
                                 NULL,
                                 EVP_get_digestbynid(OBJ_sn2nid("sm3-256")),
                                 engine,
                                 signing_eph)))
    {
        printf("sign init fail with %d\n", err);
        ERR_print_errors_fp(stdout);
    }

    EVP_PKEY_CTX *evp_created_ctx = evp_md_ctx->pctx;
    pkey_ctx_t *created = EVP_PKEY_CTX_get_data(evp_created_ctx);
    created->static_my_key = signing_sta;

    if (1 != EVP_DigestSignUpdate(evp_md_ctx, msg, sizeof(msg)))
    {
        printf("sign update fail\n");
    }

    unsigned char *sig = OPENSSL_malloc(sizeof(unsigned char) * 65);
    sig[64] = '\0';
    size_t sig_len = 4;

    //FIXME unhandled return value
    EVP_DigestSignFinal(evp_md_ctx, NULL, &sig_len);
    printf("workout len is %zd\n", sig_len);

    if (1 != EVP_DigestSignFinal(evp_md_ctx, sig, &sig_len))
    {
        printf("sign final fail\n");
    }

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
            0x49, 0x13, 0x0d, 0x41, 0x94, 0xf7, 0x9f, 0xb1, 0xee, 0xd2, 0xca, 0xa5,
            0x5b, 0xac, 0xdb, 0x49, 0xc4, 0xe7, 0x55, 0xd1, 0x6f, 0xc6, 0xda, 0xc3,
            0x2c, 0x5d, 0x5c, 0xf1, 0x0c, 0x77, 0xdf, 0xb2, 0x0f, 0x7c, 0x2e, 0xb6,
            0x67, 0xa4, 0x57, 0x87, 0x2f, 0xb0, 0x9e, 0xc5, 0x63, 0x27, 0xa6, 0x7e,
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
}

void
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
            0x21, 0x68, 0xca, 0x39, 0x23, 0x62, 0xdc, 0x8f, 0x23, 0x45, 0x9c, 0x1d,
            0x11, 0x46, 0xfc, 0x3d, 0xbf, 0xb7, 0xbc, 0x9a, 0x6d, 0x65, 0x73, 0x73,
            0x61, 0x67, 0x65, 0x20, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74};

    EVP_DigestVerifyUpdate(md_ctx, msg, sizeof(msg));

    unsigned char sig[] =
        {0x40, 0xf1, 0xec, 0x59, 0xf7, 0x93, 0xd9, 0xf4, 0x9e, 0x09, 0xdc, 0xef,
            0x49, 0x13, 0x0d, 0x41, 0x94, 0xf7, 0x9f, 0xb1, 0xee, 0xd2, 0xca, 0xa5,
            0x5b, 0xac, 0xdb, 0x49, 0xc4, 0xe7, 0x55, 0xd1, 0x6f, 0xc6, 0xda, 0xc3,
            0x2c, 0x5d, 0x5c, 0xf1, 0x0c, 0x77, 0xdf, 0xb2, 0x0f, 0x7c, 0x2e, 0xb6,
            0x67, 0xa4, 0x57, 0x87, 0x2f, 0xb0, 0x9e, 0xc5, 0x63, 0x27, 0xa6, 0x7e,
            0xc7, 0xde, 0xeb, 0xe7};

    printf("signature verify ");
    if (1 == EVP_DigestVerifyFinal(md_ctx, sig, 64))
        PASS;
    else
        FAIL;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_MD_CTX_destroy(md_ctx);
}

void
test_asym_enc()
{
    BN_CTX *bn_ctx;
    EVP_PKEY_CTX *pkey_ctx, *tctx;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn_priv_sta, *bn_px, *bn_py;
    EC_KEY *ec_sta;
    EVP_PKEY *pkey_sta;
    size_t out_len;
    unsigned char *out;

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
    EC_KEY *ecr = EVP_PKEY_get0(rand);

    unsigned char priv_sta[] =
        {0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a,
            0xc6, 0xd3, 0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a,
            0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8};
    unsigned char px_sta[] =
        {0x09, 0xf9, 0xdf, 0x31, 0x1e, 0x54, 0x21, 0xa1, 0x50, 0xdd, 0x7d, 0x16,
            0x1e, 0x4b, 0xc5, 0xc6, 0x72, 0x17, 0x9f, 0xad, 0x18, 0x33, 0xfc, 0x07,
            0x6b, 0xb0, 0x8f, 0xf3, 0x56, 0xf3, 0x50, 0x20};
    unsigned char py_sta[] =
        {0xcc, 0xea, 0x49, 0x0c, 0xe2, 0x67, 0x75, 0xa5, 0x2d, 0xc6, 0xea, 0x71,
            0x8c, 0xc1, 0xaa, 0x60, 0x0a, 0xed, 0x05, 0xfb, 0xf3, 0x5e, 0x08, 0x4a,
            0x66, 0x32, 0xf6, 0x07, 0x2d, 0xa9, 0xad, 0x13};

    BN_bin2bn(priv_sta, 32, bn_priv_sta);
    BN_bin2bn(px_sta, 32, bn_px);
    BN_bin2bn(py_sta, 32, bn_py);

    ec_sta = EC_KEY_new();
    if (1 != EC_KEY_set_group(ec_sta, EC_KEY_get0_group(EVP_PKEY_get0(pkey))))
    {
        return;
    }

    if (1 != EC_KEY_set_private_key(ec_sta, bn_priv_sta))
    {
        return;
    }

    if (0 == EC_KEY_set_public_key_affine_coordinates(ec_sta, bn_px, bn_py))
    {
        return;
    }

    pkey_sta = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey_sta, ec_sta);
    EC_KEY_free(ec_sta);


    /*
     * finally fixed wrong generated ec_point
     * cuz standard uses a different curve
     */

    data = EVP_PKEY_CTX_get_data(pkey_ctx);
    data->static_my_key = pkey_sta;

    unsigned char msg[] =
        {0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
            0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64};

    EVP_PKEY_encrypt_init(pkey_ctx);
    EVP_PKEY_encrypt(pkey_ctx, NULL, &out_len, msg, 19);

    out = OPENSSL_malloc(out_len);
    if (1 != EVP_PKEY_encrypt(pkey_ctx, out, &out_len, msg, 19))
    {
        goto err;
    }

    unsigned char expect[] =
        {0x04, 0x04, 0xeb, 0xfc, 0x71, 0x8e, 0x8d, 0x17, 0x98, 0x62, 0x04, 0x32,
            0x26, 0x8e, 0x77, 0xfe, 0xb6, 0x41, 0x5e, 0x2e, 0xde, 0x0e, 0x07, 0x3c,
            0x0f, 0x4f, 0x64, 0x0e, 0xcd, 0x2e, 0x14, 0x9a, 0x73, 0xe8, 0x58, 0xf9,
            0xd8, 0x1e, 0x54, 0x30, 0xa5, 0x7b, 0x36, 0xda, 0xab, 0x8f, 0x95, 0x0a,
            0x3c, 0x64, 0xe6, 0xee, 0x6a, 0x63, 0x09, 0x4d, 0x99, 0x28, 0x3a, 0xff,
            0x76, 0x7e, 0x12, 0x4d, 0xf0, 0x59, 0x98, 0x3c, 0x18, 0xf8, 0x09, 0xe2,
            0x62, 0x92, 0x3c, 0x53, 0xae, 0xc2, 0x95, 0xd3, 0x03, 0x83, 0xb5, 0x4e,
            0x39, 0xd6, 0x09, 0xd1, 0x60, 0xaf, 0xcb, 0x19, 0x08, 0xd0, 0xbd, 0x87,
            0x66, 0x21, 0x88, 0x6c, 0xa9, 0x89, 0xca, 0x9c, 0x7d, 0x58, 0x08, 0x73,
            0x07, 0xca, 0x93, 0x09, 0x2d, 0x65, 0x1e, 0xfa};

    int pass = CRYPTO_memcmp(expect, out, sizeof(expect));
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

}

void
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
    data = EVP_PKEY_CTX_get_data(ctx);
    data->curve_id = OBJ_sn2nid("sm2_curve");

    //EVP_PKEY_keygen_init(ctx);
    //EVP_PKEY_keygen(ctx, &pkey);

    unsigned char cipher[] =
        {0x04, 0x04, 0xeb, 0xfc, 0x71, 0x8e, 0x8d, 0x17, 0x98, 0x62, 0x04, 0x32,
            0x26, 0x8e, 0x77, 0xfe, 0xb6, 0x41, 0x5e, 0x2e, 0xde, 0x0e, 0x07, 0x3c,
            0x0f, 0x4f, 0x64, 0x0e, 0xcd, 0x2e, 0x14, 0x9a, 0x73, 0xe8, 0x58, 0xf9,
            0xd8, 0x1e, 0x54, 0x30, 0xa5, 0x7b, 0x36, 0xda, 0xab, 0x8f, 0x95, 0x0a,
            0x3c, 0x64, 0xe6, 0xee, 0x6a, 0x63, 0x09, 0x4d, 0x99, 0x28, 0x3a, 0xff,
            0x76, 0x7e, 0x12, 0x4d, 0xf0, 0x59, 0x98, 0x3c, 0x18, 0xf8, 0x09, 0xe2,
            0x62, 0x92, 0x3c, 0x53, 0xae, 0xc2, 0x95, 0xd3, 0x03, 0x83, 0xb5, 0x4e,
            0x39, 0xd6, 0x09, 0xd1, 0x60, 0xaf, 0xcb, 0x19, 0x08, 0xd0, 0xbd, 0x87,
            0x66, 0x21, 0x88, 0x6c, 0xa9, 0x89, 0xca, 0x9c, 0x7d, 0x58, 0x08, 0x73,
            0x07, 0xca, 0x93, 0x09, 0x2d, 0x65, 0x1e, 0xfa};


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

    err:
    OPENSSL_free(plaintext);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(tctx);
    if (bn_ctx)
    {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }
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