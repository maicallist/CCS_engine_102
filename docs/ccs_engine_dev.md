# OpenSSL Engine Development Tutorial

>Author Chen Gao  
>Date 15 Dec 2017  

## Fast-Travel

* [Disclaimer]                  (#disclaimer)
* [Motivation]                  (#motivation)
* [Pre-Checks]                  (#pre-checks)
* [Demo Environment]            (#demo_environment)
* [Related Resources]           (#related_resources)
* [Loading Engine]              (#loading_engine)
    * [Engine Code]             (#engine_code)
    * [OpenSSL Config]          (#openssl_config)
    * [Test Program]            (#test_program)
    * [Makefile]                (#makefile)
    * [Error Handling]          (#error_handling)
    * [Test Error]              (#test_error)
* [Digest]                      (#digest)
    * [OID and NID]             (#oid_and_nid)
    * [Test Message Digest]     (#test_message_digest)  
* [ECDH]                        (#ecdh)
    * [Make Your Life Easier]   (#make_life)
    * [GOST Engine]             (#ccgost)
    * [SM2 ECDH]                (#sm2_ecdh)
* [Completing Public key]       (#pkey)
* [Cipher]                      (#cipher)
* [Journey Ends Here]           (#bye)

## <a name = "disclaimer"></a> Disclaimer

**I am no expert of OpenSSL, I'm not even good at C, I was tasked to create an engine, that's all. I don't take any responsibility and I am not liable for any damage caused through use of this tutorial or source code or anything related to my work, be it indirect, special, incidental or consequential damages (including but not limited to damages for loss of business, loss of profits, interruption or the like). If you have any questions regarding the terms of use outlined here, please do not hesitate to throw this tutorial to your bin.**

**Also I have to warn you, with 95% confidence, writing your own crypto code is likely a mistake, like I'm making one right now, especially wrong when your code is not reviewed by public. You may produce code in good quality from developer prospective, but hardly achieve the same from cryptographer prospective. I'm not a cryptographer, thus, I can only make sure the code in this tutorial works, but I cannot guarantee you that it is secure.**

## <a name="motivation"></a>Motivation
Why do we need an OpenSSL engine? The answer is, you don't, in most of cases. OpenSSL provides a wide range of algorithms which should satisfy you needs of normal business.   
But still you have reached to this tutorial, so I suppose you really need an algorithm not yet provided by OpenSSL. That's why we need an OpenSSL engine so the new algorithms can be dynamically loaded into OpenSSL, providing the algorithm you want through **high level OpenSSL API**.  

The API is an important thing. I've seen some examples people claim that they made an engine. But the truth is, they just steal some code from OpenSSL library. Their algorithm cannot be access through **OpenSSL EVP interface**. If you don't know what EVP is, it's a high level api that hides all cryptographic details from users. It's a fool-proof api, or intends to be one. That's the goal you should aim for, hiding your custom algorithms behind OpenSSL EVP interface, so users won't make any stupid mistakes. They always do, no offense, we all do. Thus, exposing you low level error prone api would be a bad idea. 

## <a name="goal"></a> Goal
Through this tutorial, we are going to insert following algorithms

* SM2 - EC based cryptosystem
* SM3 - message digest
* SM4 - feistel cipher

*Note* all algorithms above are available from OpenSSL 1.1.1.  
*Note* No algorithms above are optimized for performance.

## <a name="pre-checks"></a> Pre-Checks
Probe an customized engine into OpenSSL is only allowed after version **0.9.7**.  
You can verify your OpenSSL version by running command in terminal:  
` openssl version` to ensure your version is correct. 

Or better yet, run ` openssl engine `  

If you see something like:  

```
-----
(dynamic) Dynamic engine loading support  
```

in command line output, then you are good to go.

##### NOTE
There are some features, at least one place, only supported after OpenSSL **1.0.1d**, they will be mentioned in relevant sections. If you have to use an older version, you may need to work out those part on your own.

## <a name="demo_environment"></a> Demo Environment

* VMWare Fusion 8.5.7
* CentOS Linux release 7.4.1708
* OpenSSL 1.0.2o 27 Mar 2018
* Clang 3.4.2
* GNU Make 3.82

For debugging purpose, we compiled OpenSSL from source code with `-d shared` option, and **OPENSSLDIR** is located at `/usr/local/ssl`.

If you are using OpenSSL already installed on your system, make sure you also have OpenSSL dev kit installed.

```
sudo yum install openssl-devel
sudo apt-get install libssl-dev

etc..
```
 
If you are running demo with OpenSSL other than version 1.0.2, you might need to fix some errors.  
Other systems may vary.

## <a name="related_resources"></a> Related Resources
There are general resources available on OpenSSL wiki.  

Constantly consulting [OpenSSL 1.0.2 Documentation](https://www.openssl.org/docs/man1.0.2/crypto/), [Creating an OpenSSL Engine](https://wiki.openssl.org/index.php/Creating_an_OpenSSL_Engine_to_use_indigenous_ECDH_ECDSA_and_HASH_Algorithms) and [Library Initialization](https://wiki.openssl.org/index.php/Library_Initialization).  
OpenSSL Wiki is not an exemplar of good documentation, so read it carefully, or you might miss clues to solve your problems.

If there are resources targeting specific issue, they will be introduced in corresponding sections. 

## <a name="loading_engine"></a> Loading Engine
There are **two** things you need to get an engine to actually work.  

* your engine code, obviously.  
* OpenSSL configuration file.

There are tutorials available online, like [here](https://www.openssl.org/blog/blog/2015/10/08/engine-building-lesson-1-a-minimum-useless-engine/) and [here](https://www.sinodun.com/2009/02/developing-an-engine-for-openssl/). Also there is an in-depth tutorial from [OpenSSL Wiki](https://wiki.openssl.org/index.php/Creating_an_OpenSSL_Engine_to_use_indigenous_ECDH_ECDSA_and_HASH_Algorithms), although the wiki tutorial misses steps and produces leaky code, still it's **very important** you read through it. Demo is also developed based on this OpenSSL wiki tutorial.

First link explained well, but it focuses on users who want to use command line rather than program, thus it mentions nothing about config file. It uses 
```
openssl engine -t -c path/to/your/engine/so/file
```  
to tell OpenSSL where to find your custom engine.

To do this in code, you need to change OpenSSL config file which is mentioned in the second link.  

For the sake of redundancy in case links become invalid, this section will repeat what's in the tutorials, if your have read the linked tutorials, skip following two topics.

### <a name="engine_code"></a> Engine Code 
A minimal engine requires few things from OpenSSL.  
First, compatibility check.  

```
// engine.c
#include <openssl/engine.h>

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

Second, bind the engine.

```
// engine.c
#include <openssl/engine.h>  

static int
bind(ENGINE *e, const char *d)
{
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

Third, assign engine id and name, assign engine init, finish and destroy functions.

```
// engine.c

#include <openssl/engine.h>

static const char *engine_id = "ccs";
static const char *engine_name = "ccs_engine";

static int
ccs_engine_init(ENGINE *e)
{
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
bind(ENGINE *e, const char *d)
{
    if (!ENGINE_set_id(e, engine_id)
        || !ENGINE_set_name(e, engine_name)
        || !ENGINE_set_init_function(e, ccs_engine_init)
        || !ENGINE_set_finish_function(e, ccs_engine_finish)
        || !ENGINE_set_destroy_function(e, ccs_engine_destroy))
        return 0;

    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

Fourth, Compile.

```
cc -fPIC -o engine.o -c engine.c
cc -shared -o libccs.so -lcrypto -L/usr/local/ssl/lib engine.o

```
Now run command again  
```
openssl engine -t -c /path/to/your/libccs.so
```  
If, in output, you observe

```
-----
(/path/to/your/libccs.so) ccs_engine
Loaded: (ccs) ccs_engine
     [ available ]

```
Then you are done for this step.

### <a name = "openssl_config"></a> OpenSSL Config
Although our engine is loaded, but we have to tell OpenSSL where to look for the engine every time we use it. It would be good if we can skip this step. To do this, you need to put your engine information in OpenSSL config file.

The config file is located at **OPENSSLDIR**, make a backup.

In config file **global section**, add a new line

```
openssl_conf = ccs_def
```
> If you don't know where is global section, that is the section from file line #1 to the first [something].  
> If you haven't change anything inside, the first [something] is at line #22 [ new oids ].  
> Anything before line #22 is global section. 

**openssl\_conf** is the default app name, later in your code, if you don't assign an app name, OpenSSL, by default, will look for openssl\_conf.  
You are free to name it something else, as we will do so later. openssl\_def directs to openssl\_def section in config file, which we will create now.

Add following to the end of the file

```
# These are settings for OpenSSL Engine CCS
[ccs_def]
engines = engine_section

[engine_section]
ccs = ccs_engine

[ccs_engine]
engine_id = ccs
dynamic_path = /path/to/libccs.so
init = 1

[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

```

Now run OpenSSL engine again **without** telling OpenSSL where to look for your engine

```
openssl engine
```
If output looks like 

```
-----
(rdrand) Intel RDRAND engine
(dynamic) Dynamic engine loading support
(ccs) ccs_engine           <- bingo
```
Then we are all set.

### <a name = "test_program"></a> Test Program
All we have done above are through OpenSSL command line tool.   
But our final goal is to use the engine in code.

Before we proceed, we now change the default app name in config to something else.

```
# global section
# ccs is the app name, directs to ccs_app section in file.

ccs = ccs_def

# in ccs_app section, nothing changed except the [section name]

[ccs_def]
engines = engine_section

[engine_section]
ccs = ccs_engine

[ccs_engine]
engine_id = ccs
dynamic_path = /path/to/your/engine/so/file
init = 0

[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

```
Now, when we want to load our engine, we have tell OpenSSL the app name in config file is **ccs**.  
Next, use code to find our engine.

```
// test.c

#include <stdio.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#define KRED                "\x1B[31m"
#define KGRN                "\x1B[32m"
#define RST                 "\x1B[0m"
#define PASS                printf("%stest passed.%s\n\n", KGRN, RST)
#define FAIL                printf("%stest failed.%s\n\n", KRED, RST)

#define ENGINE_ID           "ccs"
#define ERROR_HANDLING      printf("an error has occurred in %s(), at %s line %d.\n", __FUNCTION__, __FILE__, __LINE__)

#define DEBUG 1

static ENGINE *engine;

int
load_engine();

void
engine_cleanup();

int
main()
{
    printf("We're using OpenSSL version %s.\n", OPENSSL_VERSION_TEXT);

    int tests = 0, pass = 0;

    tests++;
    pass += load_engine();

    engine_cleanup();

    printf("Test Summary:\nTotal: %d, Passed: %d, Failed: %d\n",
           tests,
           pass,
           tests - pass);
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

void engine_cleanup()
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
```
The cleanup section in above code is required to cleanup a library, read [Engine](https://wiki.openssl.org/index.php/Library_Initialization#Engines) and [Cleanup](https://wiki.openssl.org/index.php/Library_Initialization#Cleanup) in wiki.

### <a name = "makefile"></a>Makefile
Our test program is complete, it's time to run it. We already have the shared library needs to be compiled each time, now we need to add the test program to compilation list. It is foreseeable we gonna have more files to compile, so it might be a good idea to create a Makefile.

```
// Makefile

CC 		= clang -g
LIB		= bin/libccs.so
RUN		= test

DEP_pack	= bin/pack.o
DEP_engine	= bin/engine.o

SRC_engine	= engine.c
SRC_run		= test.c

FLAG_dep	= -fPIC
FLAG_ld		= -lcrypto -L/usr/local/ssl/lib

dir :
	mkdir -p bin

$(LIB) : $(DEP_pack)
	$(CC) -shared -o $@ $<

$(DEP_pack) : $(DEP_engine)
	ld -r -o $@ $?

$(DEP_engine) : $(SRC_engine)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(RUN) : $(SRC_run)
	$(CC) $(FLAG_ld) -o $@ $<

run : dir $(LIB) $(RUN)

all : clean dir $(LIB) $(RUN)

clean :
	rm -rf bin test
```

Compile with ` make all`, and run test program with ```./test ```   
On success, you should see your engine id and name are printed on screen, as well as the error we want, with correct lib name(ccs_engine), function name and reason description.  

```
We're using OpenSSL version OpenSSL 1.0.2k  26 Jan 2017.
engine id: ccs
engine name: ccs_engine
init result: 1
test passed.

Test Summary:
Total: 1, Passed: 1, Failed: 0

```
Check with valgrind or equivalent to make sure there is no leak.

### <a name = "error_handling"></a> Error Handling

OpenSSL has an internal error queue to log and report errors, containing function identifier and reason identifier. You can define your own function & reason codes, but that would take a lot of effort to keep tracking codes you have used. 

OpenSSL provides a useful tool ```mkerr.pl``` in util folder, it scans your source code file, automatically index all ```#define``` that matches following pattern:   
```
[A-Za-z0-9]+_(F|R)_[A-Za-z0-9]+
```

F stands for functions, and R stands for reasons. You can have a look OpenSSL header files, generated codes looks like this:

```
/* Error codes for the ECDSA functions. */

/* Function codes. */
# define ECDSA_F_ECDSA_CHECK                              104
# define ECDSA_F_ECDSA_DATA_NEW_METHOD                    100
# define ECDSA_F_ECDSA_DO_SIGN                            101
# define ECDSA_F_ECDSA_DO_VERIFY                          102
# define ECDSA_F_ECDSA_METHOD_NEW                         105
# define ECDSA_F_ECDSA_SIGN_SETUP                         103

/* Reason codes. */
# define ECDSA_R_BAD_SIGNATURE                            100
# define ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE              101
# define ECDSA_R_ERR_EC_LIB                               102
# define ECDSA_R_MISSING_PARAMETERS                       103
# define ECDSA_R_NEED_NEW_SETUP_VALUES                    106
# define ECDSA_R_NON_FIPS_METHOD                          107
# define ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED          104
# define ECDSA_R_SIGNATURE_MALLOC_FAILED                  105

```

First, we need a config file for this script. 
This config will tell script what are the names of generated files.

```
// ccs.ec

L   ERR     NONE                NONE
L   CCS     ../err/ccs_err.h    ../err/ccs_err.c
```

Second, put new error codes in your source file.

```
// engine.c

#define CCS_F_RESERVED
#define CCS_R_RESERVED
```

Third, run the script

```
bash_prompt > perl mkerr.pl -conf /path/to/ccs.ec -reindex -write /path/to/engine.c
```

-----
_##warning##_

I know nothing about perl, I found out how to use this script by trail and error, so look through `mkerr.pl` yourself.

----
Now two files ccs\_err.h and ccs\_err.c should be generated. You may need to fix some obvious errors caused by the script. One thing you will notice is, the generated code references our lib as `ERR_LIB_CCS`, but this is never defined. You can have a look at OpenSSL `/crypto/err/err.h`, it contains many defined libs, up to 128.  I don't want to touch OpenSSL source file, so we have to make our own.

```
// ccs_err.h

/*
 * FIXME LIB ID
 * ERR_LIB_CCS is not auto generated, and may conflict with further version.
 */
#define ERR_LIB_CCS            255

#define CCSerr(f, r) ERR_PUT_error(ERR_LIB_CCS, (f), (r), __FILE__, __LINE__)

```
OpenSSL provides a way of getting lib id at runtime by using `ERR_get_next_error_library()`, but this requires us replace ERR\_LIB\_CCS with a variable. Since we are going to call this script later to update more codes. Right now let's just leave it. 

One last thing, every function and reason can be displayed either as number (like 100), or as text. To make error output more readable, we can load error string so OpenSSL will display error text when encounter errors.

```
// engine.c

static int
bind(ENGINE *e, const char *d)
{
    if (!ENGINE_set_id(e, engine_id)
        || !ENGINE_set_name(e, engine_name)
        || !ENGINE_set_init_function(e, ccs_engine_init)
        || !ENGINE_set_finish_function(e, ccs_engine_finish)
        || !ENGINE_set_destroy_function(e, ccs_engine_destroy))
        return 0;

    ERR_load_CCS_strings();

    return 1;
}
```

### <a name = "test_error"></a> Test Error
To test our error handling, we can deliberately raise an error.

```
// engine.c

static int
ccs_engine_init(ENGINE *e)
{
    CCSerr(CCS_F_RESERVED, CCS_R_RESERVED);
    return 14;
}
```
```
// test.c

int
main()
{
    printf("We're using OpenSSL version %s.\n", OPENSSL_VERSION_TEXT);

    int tests = 0, pass = 0;

    tests++;
    pass += load_engine();

    printf("Following error is generated for testing...\n");
    ERR_print_errors_fp(stderr);
    printf("\n");

    engine_cleanup();
    // .. //
}
```

In output, if we observe something like:

```
// .. //

Following error is generated for testing...
139730363631296:error:FF064064:lib(255):func(100):reason(100):engine.c:30:

// .. //
```
Then we did it.

## <a name="digest"></a> Digest

Our engine is up and running, it's time we start our business. First, we are going to insert a message digest algorithm SM3 into OpenSSL.

OpenSSL defines a struct in ```evp.h``` to hold message digest algorithm information, called```EVP_MD_CTX```.

```
struct env_md_ctx_st {
    const EVP_MD *digest;       /* functions related to the algorithm */
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;              /* store you algorithm-specific data */
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */ ;
```

And the algorithm itself in referenced by ```EVP_MD```struct, which has following structure.

```
struct env_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    /* FIXME: prototype these some day */
    int (*sign) (int type, const unsigned char *m, unsigned int m_length,
                 unsigned char *sigret, unsigned int *siglen, void *key);
    int (*verify) (int type, const unsigned char *m, unsigned int m_length,
                   const unsigned char *sigbuf, unsigned int siglen,
                   void *key);
    int required_pkey_type[5];  /* EVP_PKEY_xxx */
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */ ;
```

We need to create our own EVP_MD, fill in SM3 algorithm content.

```
// md_lcl.c

static EVP_MD evp_md_sm3 =
    {
    NID_undef,                          // type, nid
    NID_undef,                          // pkey type
    32,                                 // digest output length
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    evp_sm3_init,
    evp_sm3_update,
    evp_sm3_final,
    evp_sm3_copy,
    evp_sm3_cleanup,
    NULL,                               // <- unknown
    NULL,                               // <- unknown
    {NID_undef, NID_undef, 0, 0, 0}
    64,                                 // block size
    sizeof(sm3_ctx_t),                  // size of md_data
    NULL
    };
```

The usage of some elements in EVP_MD is still unknown, but from name (\*sign & \*verify) we can easily guess that they are part of signature scheme. We'll find out them when we create ECDSA algorithm.  
In order to make this struct accessible, we need a accessor in `md_lcl.h`.

```
// md_lcl.h

EVP_MD *
EVP_sm3();

// md_lcl.c
EVP_MD *
EVP_sm3()
{
    return &evp_md_sm3;
}
```


Also we need to finish the functions we just registered in EVP_MD.

```
// md_lcl.h

int
evp_sm3_init(EVP_MD_CTX *ctx)
{
    sm3_init(ctx->md_data);
    return 1;
}

int
evp_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    sm3_update(ctx->md_data, data, len);
    return 1;
}

int
evp_sm3_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
    sm3_final(ctx->md_data, digest);
    return 1;
}

int
evp_sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    if (to->md_data && from->md_data)
        memcpy(to->md_data, from->md_data, sizeof(from->md_data));
    return 1;
}

int
evp_sm3_cleanup(EVP_MD_CTX *ctx)
{
    if (ctx->md_data)
        memset(ctx->md_data, 0, sizeof(ctx->md_data));
    return 1;
}
```

It's quite clear that all five functions in ```md_lcl.c``` are just wrappers, the actual functions are defined and implemented in ```sm3_hash.c```, SM3 algorithm details are outside the scope of this document. 

-----
To help you understand better, we have following project structure.

```
project
    |
    -- engine.c         // engine that loads wrapped functions to perform SM3 hash
    |
    -- md/
        |
        -- md_lcl.*     // engine function wrappers
        |
        -- sm3_hash.*   // SM3 specific functions
        
```

SM3 operates on a struct called ```md_ctx_t``` defined in ```sm3_hash.*```.   
At runtime, this struct is referenced by ```void *md_data``` pointer in ```EVP_MD_CTX```.   
Also SM3 functions implemented in ```sm3_hash.* ``` is referenced by ```EVP_MD *digest``` field in ```EVP_MD_CTX```.

-----

Above function wrappers have link to correct SM3 functions, and all wrappers are registered in EVP\_MD struct we created for SM3. Now we only need to tell EVP interface how to select our algorithm.

```
// md_lcl.h

static int ccs_digest_ids =
    {
        NID_undef
    };
``` 

```
// engine.c

static int
ccs_digest_selector(ENGINE *e,
                        const EVP_MD **digest,
                        const int **nids,
                        int nid)
{
    if (!digest)
    {
        *nids = &ccs_digest_ids;
        return 1; /* one algor available */
    }

    if (nid == ??)
    {
        *digest = EVP_sm3();
        return 1;
    }

    CCSerr(CCS_F_MD_SELECT, CCS_R_UNSUPPORTED_ALGORITHM);
    *digest = NULL;

    return 0;
}
```
**Note** we have define one new function and one new reason.  
run `mkerr` script on `engine.c` to update error codes (do not reindex).

```
bash_prompt > perl mkerr.pl -conf /path/to/ccs.ec -write /path/to/engine.c
```


### <a name = "oid_and_nid"></a> OID and NID

We now need to revisit three lines of code we write before.

```
// engine.c

if (nid == ??)                  // we just wrote this line

// md_lcl.h

static int ccs_digest_ids =
    {
        NID_undef               // and this line too
    };

// md_lcl.c

static EVP_MD evp_md_sm3 =
    {
    NID_undef,                  // this line we wrote while ago, nid
    NID_undef,                          
    32,                                 
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    evp_sm3_init,
    evp_sm3_update,
    evp_sm3_final,
    evp_sm3_copy,
    evp_sm3_cleanup,
    NULL,                               
    NULL,                               
    {NID_undef, NID_undef, 0, 0, 0}
    64,                                 
    sizeof(sm3_ctx_t),                    
    NULL
    };
```

You may already have the idea that we are going to fill in a ```NID``` for SM3, OpenSSL uses this ID to locate various objects, including algorithm struct. So, it has to be unique.

A naive solution would be change type NID_undef to a int, a very large int, say 99999. Even it works this time, but it may conflict with future versions, Or maybe conflict with someone has the same idea and created some other engines. A nice way of doing this would be assign the NID dynamically.

The [tutorial](https://wiki.openssl.org/index.php/Creating_an_OpenSSL_Engine_to_use_indigenous_ECDH_ECDSA_and_HASH_Algorithms) from OpenSSL wiki failed to mention this. It cheated by stealing NID from SHA256. But we got some information from [OpenSSL Mailing List](https://mta.openssl.org/pipermail/openssl-dev/2016-December/008931.html)

Here I qoute:

```
********************
levitte> xoloki> > May I suggest you have a look at the GOST engine?  It does implement
levitte> xoloki> > the algorithm entirely in the engine.  The only things added in the
levitte> xoloki> > OpenSSL code are the OIDs (not strictly necessary) and the TLS
levitte> xoloki> > ciphersuites (I don't think that can be done dynamically at all, at
levitte> xoloki> > least yet).
levitte> xoloki> 
levitte> xoloki> How are the OIDs not necessary?  What about the NIDs?
levitte> 
levitte> It's not stricly necessary to add them statically in the libcrypto
levitte> code.  They can be added dynamically by the engine by calling
levitte> OBJ_create() with the correct arguments.

Applications will then have to find out the nid by calling
OBJ_txt2nid, OBJ_sn2nid or OBJ_ln2nid, depending on the data they
have.  Note: this can already be done for the built in OIDs.

Cheers,
Richard

-- 
```

Our objective is clear, use **OBJ_create()** and one of three **OBJ_sth2nid** to create a new NID for SM3. 

In a separate header file, I define following

```
// conf/objects.h

// OID, Long name, Short name of SM3

#define OID_sm3             "1.2.156.10197.1.401.1"
#define SN_sm3              "sm3-256"
#define LN_sm3              "sm3-256"
```
OID has its own meaning, 2.16.156 is assigned to China, you can check up on [this website](http://www.alvestrand.no/objectid/).

Now that we have what we need to know, it's time to create NID for SM3, bind it with our engine and register it to internal table so EVP interface can find it.

```
// engine.c

static int
bind(ENGINE *e, const char *d)
{
    int ret = 0;
    
    // .. // 
    
    int nid = OBJ_create(OID_sm3, SN_sm3, LN_sm3);
    evp_md_sm3_set_nid(nid);
    EVP_add_digest(EVP_sm3());

    if (!ENGINE_set_digests(e, ccs_digest_selector))
        return 0;
        
    // .. //
}
```
***Don't forgot*** to change the ```if (nid == ??)``` to ```if (nid == OBJ_sn2nid(SN_sm3))```.

### <a name = "test_message_digest"></a> Test Message Digest

```
// test.c

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
```

Also update our Makefile

```
// Makefile

DEP_pack_md	= bin/pack_md.o
DEP_sm3		= bin/sm3.o
DEP_md_link	= bin/md_lcl.o

SRC_md_link	= md/md_lcl.c
SRC_sm3		= md/sm3_hash.c

// .. //

$(DEP_pack) : $(DEP_engine) $(DEP_err) $(DEP_pack_md)
	ld -r -o $@ $?
	
$(DEP_pack_md) : $(DEP_sm3) $(DEP_md_link)
	ld -r -o $@ $?

$(DEP_sm3) : $(SRC_sm3)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_md_link) : $(SRC_md_link)
	$(CC) $(FLAG_dep) -o $@ -c $<
	
// .. //
```

Compile and run by

```
make all
./test
```


The message digest of "abc" should be 

```
-----
66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0
```

And the message digest of "....", anyway, look for two green <font color=green>```test passed```</font> in md test section.

Again, check with Valgrind.

## <a name = "ecdh"></a> ECDH
Since we have a working digest algorithm, we can move to the next step, creating a key exchange algorithm. SM2 key exchange algorithm is based on Elliptic curve, so we are going to work on OpenSSL ECDH. 

### <a name = "make_life"></a> Make Your Life Easier 
Inserting a public key algorithm is not as easy as message digest, it requires a lot of work. However, [OpenSSL wiki](https://wiki.openssl.org/index.php/Creating_an_OpenSSL_Engine_to_use_indigenous_ECDH_ECDSA_and_HASH_Algorithms#ECDH) shows us a work around.

I'm not going to repeat what's in the wiki's ECDH section. The ***point*** is you access your ECDH method through either ```ECDH_compute_key()``` like the wiki does it, or my preferred way, through [EVP interface](https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman#Using_ECDH_in_OpenSSL) ```EVP_PKEY_derive()``` which calls ```ECDH_compute_key()```. The problem we have here is, the compute key function is defined in OpenSSL, if your key exchange algorithm fits the function signature, you can code it this way, save you a lot of time.

```
// function signatures
 
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                     EC_KEY *ecdh, void *(*KDF) (const void *in, size_t inlen,
                                                 void *out, size_t *outlen));
```

Unfortunately, SM2 doesn't fit in ```ECDH_compute_key()```. To complete SM2 key exchange process, the algorithm requires two key pairs from one party, and two public keys from the other party, as well as identification hash from both. We can do some dirty tricks by manipulating ```void *out``` parameter, but it gets ugly. 

So, if your key exchange is a simple one, congratulations, have a look at the [OpenSSL wiki](https://wiki.openssl.org/index.php/Creating_an_OpenSSL_Engine_to_use_indigenous_ECDH_ECDSA_and_HASH_Algorithms#ECDH), finish your ECDH and skip to ECDSA section. ***Remember***, [EVP interface](https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman#Using_ECDH_in_OpenSSL)  is preferred.

Otherwise, keep reading.

### <a name = "ccgost"></a> GOST Engine

Before we start, we have to take a detour and verify few details. To complete a public key system in OpenSSL, I recommend you have a look at Russian Gost Engine comes with OpenSSL bundle. You can find the source code [here](https://chromium.googlesource.com/chromium/deps/openssl/+/480da75abf485e7e2a6be5acc0f71842368792c0/openssl/engines/ccgost/README.gost).  

In this section, we are going to explore gost source code. 

In particularly, we are interested in   
```gost_params.*``` defines elliptic curve parameters.  
```gost2001.c```   defines key exchange setup.  
```gost2001_keyx.c``` defines key exchange details.   
```gost_pmeth.c``` and ```gost_ameth.c``` defines functions required by OpenSSL public key system.

```gost_pmeth.c``` is the main file we need to consult with, you can see it defines a lot of functions, which are consistent with a struct called ```EVP_PKEY_METHOD```.
This struct is defined in ```evp.locl.h``` in OpenSSL, and it's a long list.

```
struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int (*init) (EVP_PKEY_CTX *ctx);
    int (*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    void (*cleanup) (EVP_PKEY_CTX *ctx);
    int (*paramgen_init) (EVP_PKEY_CTX *ctx);
    int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*keygen_init) (EVP_PKEY_CTX *ctx);
    int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*sign_init) (EVP_PKEY_CTX *ctx);
    int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                 const unsigned char *tbs, size_t tbslen);
    int (*verify_init) (EVP_PKEY_CTX *ctx);
    int (*verify) (EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);
    int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
    int (*verify_recover) (EVP_PKEY_CTX *ctx,
                           unsigned char *rout, size_t *routlen,
                           const unsigned char *sig, size_t siglen);
    int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                    EVP_MD_CTX *mctx);
    int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVP_MD_CTX *mctx);
    int (*encrypt_init) (EVP_PKEY_CTX *ctx);
    int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*decrypt_init) (EVP_PKEY_CTX *ctx);
    int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen);
    int (*derive_init) (EVP_PKEY_CTX *ctx);
    int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
} /* EVP_PKEY_METHOD */ ;

``` 

You can have good guesses based on the name of those function pointers. To complete ECDH part, we only need to care about **derive_init()** and **derive()**, for now.

From following two code blocks, we can see how gost negotiate a key.
```derive_init``` does absolutely nothing, ```derive``` retrieves two key pairs from ```EVP_PKEY_CTX```struct and subsequently calls ```VKO_compute_key```function to arrive at derived secret.

```
static int pkey_gost_derive_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}
```

```
/*
 * EVP_PKEY_METHOD callback derive. Implements VKO R 34.10-2001
 * algorithm
 */
int pkey_gost2001_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{

	## do some setup and retrieve two key pairs

	if (key == NULL) {
		*keylen = 32;
		return 32;
	}	
	
	*keylen=VKO_compute_key(key, 32, EC_KEY_get0_public_key(EVP_PKEY_get0(peer_key)),
		(EC_KEY *)EVP_PKEY_get0(my_key),data->shared_ukm);
	return 1;	
}
```

```
/* Implementation of CryptoPro VKO 34.10-2001 algorithm */
static int VKO_compute_key(unsigned char *shared_key,size_t shared_key_size,const EC_POINT *pub_key,EC_KEY *priv_key,const unsigned char *ukm)
{
    ## calculating points on curve.
    ## return 32 refers key length.
	
	return 32;
}

```

Finally, after all functions are finished, we still need to notify OpenSSL by following function.

```
int register_pmeth_gost(int id, EVP_PKEY_METHOD **pmeth,int flags)
	{
	*pmeth = EVP_PKEY_meth_new(id, flags);
	if (!*pmeth) return 0;

	switch (id)
		{
		case NID_id_GostR3410_94:
			don't care about other algorithm;
			break;
		case NID_id_GostR3410_2001:
			EVP_PKEY_meth_set_ctrl(*pmeth,pkey_gost_ctrl, pkey_gost_ctrl01_str);
			EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost01_cp_sign);
			EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost01_cp_verify);

			EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost01cp_keygen);

			EVP_PKEY_meth_set_encrypt(*pmeth,
				pkey_gost_encrypt_init, pkey_GOST01cp_encrypt);
			EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_GOST01cp_decrypt);
			EVP_PKEY_meth_set_derive(*pmeth,
				pkey_gost_derive_init, pkey_gost2001_derive);
			EVP_PKEY_meth_set_paramgen(*pmeth, pkey_gost_paramgen_init,pkey_gost01_paramgen);	
			break;
		case NID_id_Gost28147_89_MAC:
			don't care about other algorithm;
		default: /*Unsupported method*/
			return 0;
		}
	EVP_PKEY_meth_set_init(*pmeth, pkey_gost_init);
	EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_cleanup);

	EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_copy);
	/*FIXME derive etc...*/
	
	return 1;
	}

```


### <a name = "sm2_ecdh"></a> SM2 ECDH

Buckle Up, this is gonna be a long ride.

Similar to message digest, SM2 ECDH code is implemented in
`sm2.h`, `sm2_ecdh.c` and `sm2_kdf.c`. Details are outside the scope of this note.

All elliptic curve related parameters are stored in `sm2_param.*`.

```
// param.h

typedef struct
{
    int nid;
    char *a;
    char *b;
    char *gx;
    char *gy;
    char *p;        // prime
    char *n;        // order
    char *h;        // cofactor
} ec_param_fp_t;

extern ec_param_fp_t ec_param_fp_set[];
```

```
// param.c

ec_param_fp_t ec_param_fp_set [] =
    {
        /* gost R3410 2001 CC */
        {
            /* id */
            NID_undef,
            /* a */
            "C0000000000000000000000000000000000000000000000000000000000003c4",
            /* b */
            "2d06B4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c",
            /* gx */
            "2",
            /* gy */
            "a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c",
            /* p */
            "C0000000000000000000000000000000000000000000000000000000000003C7",
            /* n */
            "5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85",
            /* h */
            "1"
        },
        /* sm2 test vector */
        {
            NID_undef,
            "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
            "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
            "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
            "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
            "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
            "1"
        },
        /* curve from sm2 parameter definition */
        {
            NID_undef,
            "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
            "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
            "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
            "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62A474002df32e52139f0a0",
            "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
            "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
            "1"
        },
        /* Last Case */
        {
            0, NULL, NULL, NULL, NULL, NULL, NULL
        }
    };
```

As you can see, we defined all of parameters above have NID_undef which we will dynamically assign NID to them.

Next, defining all methods required in `EVP_PKEY_METHOD`  and `EVP_PKEY_ASN1_METHOD`.

I haven't figure out what's with these ASN.1 functions, but I know they are related to certificate or pkcs12 formatting. We don't need them yet, so we leave some NULLs here.

```
// sm2_ameth.c

#include <openssl/evp.h>

#include "../conf/objects.h"
#include "../err/ccs_err.h"
#include "pkey_lcl.h"

int
evp_sm2_register_ameth(int nid,
                       EVP_PKEY_ASN1_METHOD **ameth,
                       const char *pemstr,
                       const char *info)
{

    *ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
    if (!*ameth)
    {
        CCSerr(CCS_F_ASN1_REGISTRATION, CCS_R_MALLOC_ERROR);
        return 0;
    }

    if (nid == OBJ_sn2nid(SN_sm2))
    {
        EVP_PKEY_asn1_set_free(*ameth, evp_sm2_free);
        EVP_PKEY_asn1_set_private(*ameth, NULL, NULL, NULL);
        EVP_PKEY_asn1_set_param(*ameth, NULL, NULL, NULL, NULL, NULL, NULL);
        EVP_PKEY_asn1_set_public(*ameth, NULL, NULL, NULL, NULL, NULL, NULL);
        EVP_PKEY_asn1_set_ctrl(*ameth, NULL);
    }
    else
    {
        CCSerr(CCS_F_ASN1_REGISTRATION, CCS_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }
    return 1;
}

static void
evp_sm2_free(EVP_PKEY *key)
{
    if (key->pkey.ec)
    {
        EC_KEY_free(key->pkey.ec);
    }
}
```


```
// sm2_pmeth.c

This is really a long list, see source code.
Complete all list below except (just return 1;)
    encrypt
    decrypt
    sign
    verify

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

```
The only special function we need to talk about is `EVP_PKEY_meth_set_ctrl`. When we working with EVP, our algorithm may require additional information not specified by EVP, we can use `ctrl` to update these information.

For example, we can `ctrl` to update information to `pkey_ctx_t` which
is sm2 internal context.  

```
//conf/objects.h

#define EVP_PKEY_SET_PEER_KEY       "evp-pkey-set-peer-key"
#define EVP_PKEY_SET_MY_KEY         "evp-pkey-set-my-key"
#define EVP_PKEY_SET_ZA             "evp-pkey-set-za"
#define EVP_PKEY_SET_ZB             "evp-pkey-set-zb"
#define EVP_PKEY_SET_CURVE_BY_SN    "evp-pkey-set-curve-id"

// sm2_pmeth.c

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
```

We have defined some new error codes in `sm2_pmeth.c`, update them to `ccs_err.*` by run script

```
perl mkerr.pl -conf ccs.ec -write ../pkey/sm2_pmeth.c
```

Next, in link control logic, we expose two method registration functions, so the engine knows where to find SM2 functions.

```
// pkey_lcl.h

#include <openssl/objects.h>

#include "sm2.h"

static int sm2_pkey_ids = {NID_undef};

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

```

Finally, the engine, add new algorithm selectors and register SM2 functions.

```
// engine.c

static int
ccs_pkey_selector(ENGINE *e,
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
ccs_asn1_selector(ENGINE *e,
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
    int ret = 0;
    
    // ... //
    
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
    evp_sm2_register_ameth(nid, &sm2_ameth, "", "");
    if (!ENGINE_set_digests(e, ccs_digest_selector)
        || !ENGINE_set_pkey_meths(e, ccs_pkey_selector)
        || !ENGINE_set_pkey_asn1_meths(e, ccs_asn1_selector))
        return 0;
        
    // .. //
}
```

Test

```
// test.c

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
    
```

Also update Makefile and run.  
*Note* we need to send `DEBUG` flag when compiling pmeth for tests.

```
// Makefile

$(DEP_pmeth) : $(SRC_pmeth)
        $(CC) $(FLAG_dep) -DDEBUG -o $@ -c $<
```

On success (DEBUG 1), your output should look like

```
-----
derived key is 55b0ac62a6b927ba23703832c853ded4
test passed.

```

Note if you set DEBUG 0, ecdh test always fails cuz it meant to test the key pairs provided on Standard document, DEBUG 0 generates random ephemeral keys.

Check with valgrind.

## <a name="pkey"></a> Completing Public Key

Do the same as ECDH, complete `encrypt`, `decrypt`, `sign`, `verify`.

We left ASN.1 part, if you ever need them, feel free to do them yourself.

Update error code, Makefile, check with valgrind.

## <a name="cipher"></a> Cipher

With the experience of inserting message digest algorithm, there is no any trouble for us to insert a new cipher.

Work with `EVP_CIPHER` and `EVP_CIPHER_CTX` and do the same as digest section.

**Note**  
In Source code, we defines our `GCM` operation mode, if you gonna need some fancy modes, do it similar to what's in the source code. However, if you only need normal modes (eg. cbc128, ctr128, gcm128, xts128), have a look at openssl/crypto/modes.h, they are already provided. 

As for how to use provided modes, consult other ciphers in OpenSSL(eg. openssl/crypto/camellia/cmll_ctr.c).

## <a name="bye"></a> Journey Ends Here

Although we only inserted few example algorithm, with little effort, you can load any algorithm like ring signature or threshold cryptosystem.

Again, I'm not good at this, neither OpenSSL nor C.  
Gather useful information from here and ***Do it yourself***.

PS.  
Don't forget to fix that static err lib code. 