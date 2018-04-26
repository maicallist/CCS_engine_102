/*
 * Author Chen Gao
 * Created at 3/30/18
 *
 * This file mode_gcm.h is part of ccs_engine.
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
#ifndef CCS_ENGINE_MODE_GCM_H
#define CCS_ENGINE_MODE_GCM_H

#include <stdlib.h>
#include <stdint.h>
#include <memory.h>
#include <openssl/ossl_typ.h>
#include "converter.h"
#include "cipher_ctx.h"

/**
 *
 * @param r
 *      hash tag
 * @param hkey
 * @param aad
 * @param len_aad
 * @param cfx
 * @param len_cfx
 * @return
 *      1 if success, 0 on error.
 */
int
ghash(uint8_t *r,
      uint8_t *hkey,
      uint8_t *aad,
      size_t len_aad,
      uint8_t *cfx,
      size_t len_cfx);

int
do_encrypt_sm4_128_gcm(sm4_ctx_t *stx,
                       const uint8_t *plx,
                       uint8_t *cfx,
                       size_t len,
                       uint8_t *cfx_buf,
                       size_t offset,
                       uint8_t *iv);

int
do_decrypt_sm4_128_gcm(sm4_ctx_t *stx,
                       uint8_t *plx,
                       size_t len,
                       uint8_t *cfx_buf,
                       size_t offset,
                       uint8_t *iv);

int
do_tag_sm4_128_gcm(uint8_t *r,
                   sm4_ctx_t *stx,
                   uint8_t *hkey,
                   uint8_t *aad,
                   size_t aadl,
                   uint8_t *cfx,
                   size_t cfxl,
                   uint8_t *oiv);

int
verify_tag_sm4_128_gcm(uint8_t *tag_in,
                       size_t tag_len,
                       sm4_ctx_t *stx,
                       uint8_t *hkey,
                       uint8_t *aad,
                       size_t aadl,
                       uint8_t *cfx,
                       size_t cfxl,
                       uint8_t *oiv);

#endif //CCS_ENGINE_MODE_GCM_H
