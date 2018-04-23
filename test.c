#include <stdio.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <memory.h>

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
                0x6b,
                0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2,
                0xf7,
                0xa2,
                0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0};
        len = strlen(str);
        sptr = str;
        eptr = expect;
    }
    else if (caseno == 2)
    {
        printf("begin md test case 2...\n");
        char str[] =
            {0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
                0x64,
                0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
                0x63,
                0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61,
                0x62,
                0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                0x61,
                0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
                0x64,
                0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64};
        unsigned char expect[] =
            {0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48,
                0x89,
                0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e,
                0x57,
                0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};
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