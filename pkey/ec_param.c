/*
 * Author Chen Gao
 * Created at 1/3/18
 *
 * This file sm2_param.c is part of ccs_engine.
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

#include <openssl/objects.h>

#include "ec_param.h"

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
