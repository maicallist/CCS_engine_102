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
* [Message Digest Algorithm]    (#message_digest_algorithm)
    * [OID and NID]             (#oid_and_nid)
    * [Test Message Digest]     (#test_message_digest)  
* [ECDH]                        (#ecdh)
    * [Make Your Life Easier]   (#make_life)
    * [GOST Engine]             (#ccgost)
    * [SM2 ECDH]                (#sm2_ecdh)
* [ECDSA]                       (#ecdsa)
* [ECIES]                       (#ecies)
* [Cipher]                      (#cipher)

## <a name = "disclaimer"></a> Disclaimer

**I am no expert of OpenSSL, I'm not even good at C, I was tasked to create an engine, that's all. I don't take any responsibility and I am not liable for any damage caused through use of this tutorial or source code or anything related to my work, be it indirect, special, incidental or consequential damages (including but not limited to damages for loss of business, loss of profits, interruption or the like). If you have any questions regarding the terms of use outlined here, please do not hesitate to throw this tutorial to your bin.**

**Also I have to warn you, with 95% confidence, writing your own crypto code is likely a mistake, like I'm making one right now, especially wrong when your code is not reviewed by public. You may produce code in good quality from developer prospective, but hardly achieve the same from cryptographer prospective. I'm not a cryptographer, thus, I can only make sure the code in this tutorial works, but I cannot guarantee you that it is secure.**

## <a name="motivation"></a>Motivation
Why do we need an OpenSSL engine? The answer is, you don't, in most of cases. OpenSSL provides a wide range of algorithms which should satisfy you needs of normal business.   
But still you have reached to this tutorial, so I suppose you really need an algorithm not yet provided by OpenSSL. That's why we need an OpenSSL engine so the new algorithms can be dynamically loaded into OpenSSL, providing the algorithm you want through **high level OpenSSL API**.  

The API is an important thing. I've seen some examples people claim that they made an engine. But the truth is, they just steal some code from OpenSSL library. Their algorithm cannot be access through **OpenSSL EVP interface**. If you don't know what EVP is, it's a high level api that hides all cryptographic details from users. It's a fool-proof api, or intends to be one. That's the goal you should aim for, hiding your custom algorithms behind OpenSSL EVP interface, so users won't make any stupid mistakes. They always do, no offense, we all do. Thus, exposing you low level error prone api would be a bad idea. 


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