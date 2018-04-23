CC 		= clang -g
LIB		= bin/libccs.so
RUN		= test

DEP_pack	= bin/pack.o
DEP_engine	= bin/engine.o
DEP_err		= bin/err.o
DEP_pack_md	= bin/pack_md.o
DEP_sm3		= bin/sm3.o
DEP_md_link	= bin/md_lcl.o

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

$(DEP_pack) : $(DEP_engine) $(DEP_err) $(DEP_pack_md)
	ld -r -o $@ $?

$(DEP_engine) : $(SRC_engine)
	$(CC) $(FLAG_dep) -o $@ -c $<

$(DEP_err) : $(SRC_err)
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
