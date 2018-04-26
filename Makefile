CC 		= clang -g
LIB		= bin/libccs.so
RUN		= test

DEP_pack	= bin/pack.o
DEP_engine	= bin/engine.o
DEP_err		= bin/err.o
DEP_pack_md	= bin/pack_md.o
DEP_sm3		= bin/sm3.o
DEP_md_link	= bin/md_lcl.o
DEP_pack_pkey	= bin/pkey.o
DEP_param	= bin/param.o
DEP_ecdh	= bin/ecdh.o
DEP_ecdsa	= bin/ecdsa.o
DEP_enc		= bin/ecies.o
DEP_kdf		= bin/kdf.o
DEP_ameth	= bin/ameth.o
DEP_pmeth	= bin/pmeth.o
DEP_pack_cipher = bin/cipher.o
DEP_ciph_link 	= bin/cipher_lcl.o
DEP_ciph_ctx	= bin/cipher_ctx.o
DEP_conv	= bin/conv.o
DEP_gcm		= bin/gcm.o
DEP_sm4		= bin/sm4.o

SRC_sm4		= cipher/sm4_cipher.c
SRC_gcm		= cipher/mode_gcm.c
SRC_conv	= cipher/converter.c
SRC_ciph_ctx	= cipher/cipher_ctx.c
SRC_ciph_link	= cipher/cipher_lcl.c
SRC_pmeth	= pkey/sm2_pmeth.c
SRC_ameth	= pkey/sm2_ameth.c
SRC_kdf		= pkey/sm2_kdf.c
SRC_enc		= pkey/sm2_enc.c
SRC_ecdsa	= pkey/sm2_ecdsa.c
SRC_ecdh	= pkey/sm2_ecdh.c
SRC_param	= pkey/ec_param.c
SRC_md_link	= md/md_lcl.c
SRC_sm3		= md/sm3_hash.c
SRC_err		= err/ccs_err.c
SRC_engine	= engine.c
SRC_run		= test.c

FLAG_dep	= -fPIC
FLAG_ld		= -lcrypto -L/usr/local/ssl/lib

dir :
	mkdir -p bin

$(LIB) : $(DEP_pack)
	$(CC) -shared -o $@ $<

$(DEP_pack) : $(DEP_engine) $(DEP_err) $(DEP_pack_md) $(DEP_pack_pkey) $(DEP_pack_cipher)
	ld -r -o $@ $?

$(DEP_engine) : $(SRC_engine)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_err) : $(SRC_err)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_pack_cipher) : $(DEP_ciph_ctx) $(DEP_conv) $(DEP_gcm) $(DEP_sm4) $(DEP_ciph_link)
	ld -r -o $@ $?

$(DEP_ciph_link) : $(SRC_ciph_link)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_ciph_ctx) : $(SRC_ciph_ctx)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_conv) : $(SRC_conv)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_sm4) : $(SRC_sm4)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_gcm) : $(SRC_gcm)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_pack_pkey) : $(DEP_ameth) $(DEP_pmeth) $(DEP_kdf) $(DEP_enc) $(DEP_ecdsa) $(DEP_ecdh) $(DEP_param)
	ld -r -o $@ $?

$(DEP_ameth) : $(SRC_ameth)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_pmeth) : $(SRC_pmeth)
	$(CC) $(FLAG_dep) -DDEBUG -o $@ -c $<

$(DEP_kdf) : $(SRC_kdf)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_enc) : $(SRC_enc)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_ecdsa) : $(SRC_ecdsa)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_ecdh) : $(SRC_ecdh)
	$(CC) $(FLAG_dep) -o $@ -c $<
	
$(DEP_param) : $(SRC_param)
	$(CC) $(FLAG_dep) -o $@ -c $<
 
$(DEP_pack_md) : $(DEP_sm3) $(DEP_md_link)
	ld -r -o $@ $?

$(DEP_sm3) : $(SRC_sm3)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_md_link) : $(SRC_md_link)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(RUN) : $(SRC_run)
	$(CC) $(FLAG_ld) -o $@ $<

run : dir $(LIB) $(RUN)

all : clean dir $(LIB) $(RUN)

clean :
	rm -rf bin test
