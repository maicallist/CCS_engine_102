/*
 * Author Chen Gao
 * Created at 12/19/17
 *
 * This file object.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_OBJECT_H
#define CCS_ENGINE_OBJECT_H

#define OID_sm3             "1.2.156.10197.1.401.1"
#define SN_sm3              "sm3-256"
#define LN_sm3              "sm3-256"

#define OID_sm2             "1.2.156.10197.301"
#define LN_sm2              "sm2"
#define SN_sm2              "sm2"

#define OID_sm4_gcm         "1.2.156.10197.104.1"
#define LN_sm4_gcm          "sm4-128-gcm"
#define SN_sm4_gcm          "sm4-128-gcm"

/*
 * this standard is a total chaos, I find two sets of 256 bit curve
 * parameter, none of them has identification or anything.
 */
#define OID_sm2_test_curve  "1.2.156.10197.301.9"
#define LN_sm2_test_curve   "sm2_test_curve"
#define SN_sm2_test_curve   "sm2_test_curve"

#define OID_sm2_param_def   "1.2.156.10197.301.8"
#define LN_sm2_param_def    "sm2_curve"
#define SN_sm2_param_def    "sm2_curve"

#define OID_gost_cc_curve   "2.16.156.7.23.3.76"
#define LN_gost_cc_curve    "gost_cc_r34.10_2001_curve"
#define SN_gost_cc_curve    "gost_cc_curve"

#define EVP_PKEY_SET_PEER_KEY       "evp-pkey-set-peer-key"
#define EVP_PKEY_SET_MY_KEY         "evp-pkey-set-my-key"
#define EVP_PKEY_SET_ZA             "evp-pkey-set-za"
#define EVP_PKEY_SET_ZB             "evp-pkey-set-zb"
#define EVP_PKEY_SET_CURVE_BY_SN    "evp-pkey-set-curve-id"

#endif //CCS_ENGINE_OBJECT_H
