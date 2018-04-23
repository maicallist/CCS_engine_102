cmake_minimum_required(VERSION 3.10)
project(ccs_engine C)

set(CMAKE_C_STANDARD 11)

add_executable(ccs_engine test.c engine.c err/ccs_err.h err/ccs_err.c conf/objects.h
        md/sm3_hash.h md/sm3_hash.c md/md_lcl.h md/md_lcl.c)