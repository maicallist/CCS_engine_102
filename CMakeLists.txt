cmake_minimum_required(VERSION 3.10)
project(ccs_engine C)

set(CMAKE_C_STANDARD 11)

add_executable(ccs_engine test.c engine.c err/ccs_err.h err/ccs_err.c conf/objects.h
        md/sm3_hash.h md/sm3_hash.c md/md_lcl.h md/md_lcl.c
        pkey/ec_param.h pkey/ec_param.c pkey/sm2.h pkey/sm2_ecdsa.c pkey/sm2_ecdh.c
        pkey/sm2_enc.c pkey/sm2_kdf.c pkey/sm2_ameth.c pkey/sm2_pmeth.c pkey/pkey_lcl.h
        cipher/cipher_ctx.h cipher/cipher_ctx.c cipher/converter.h cipher/converter.c
        cipher/cipher_lcl.h cipher/cipher_lcl.c cipher/sm4_cipher.h cipher/sm4_cipher.c
        cipher/mode_gcm.h cipher/mode_gcm.c)