/*
 * Author Chen Gao
 * Created at 1/3/18
 *
 * This file sm2_param.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_EC_PARAM_H
#define CCS_ENGINE_EC_PARAM_H

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif
#endif //CCS_ENGINE_EC_PARAM_H
