/*
 * Author Chen Gao
 * Created at 1/3/18
 *
 * This file sm2_kdf.c is part of ccs_engine.
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


#include <string.h>
#include "sm2.h"
#include "../md/sm3_hash.h"

static void
convert_counter(unsigned char *conv, u_int32_t counter)
{
    conv[0] = (unsigned char) ((counter >> 24) & 0xff);
    conv[1] = (unsigned char) ((counter >> 16) & 0xff);
    conv[2] = (unsigned char) ((counter >> 8) & 0xff);
    conv[3] = (unsigned char) (counter & 0xff);
}

/*
 * derive key from shared secret.
 *
 * param [in] is null terminated at in_len + 1 position
 */
void *
sm2_kdf(void *in, size_t in_len, void *out, size_t *out_len)
{

    if (in == NULL || out_len == NULL || out == NULL)
        return NULL;

    /* check key length smaller than (2^32 - 1) * digest_length */
    if (*out_len == 0)
        *out_len = 16;
    else if (*out_len << 3 > 0xffffffff00)
        return NULL;

    u_int32_t counter = 0x00000001;

    //round up key_len/digest_len
    size_t round = 1 + ((*out_len - 1) / SM3_DIGEST_LENGTH);

    for (; counter <= round; ++counter)
    {
        unsigned char conv[4];
        convert_counter(conv, counter);

        unsigned char hash_input[in_len + 4];
        memcpy(hash_input, in, in_len);
        memcpy(hash_input + in_len, conv, 4);

        unsigned char *block =
            OPENSSL_malloc(sizeof(unsigned char) * (SM3_DIGEST_LENGTH + 1));
        block[SM3_DIGEST_LENGTH] = '\0';

        // REVIEW calling low level api
        // directly calling sm3 may not be the best option
        sm3((uint8_t *) hash_input, in_len + 4, block);

        if (counter == round && round != ((int) *out_len / SM3_DIGEST_LENGTH))
            memcpy(out + ((counter - 1) * SM3_DIGEST_LENGTH),
                   block,
                   (*out_len) % (size_t) SM3_DIGEST_LENGTH);
        else
            memcpy(out + ((counter - 1) * SM3_DIGEST_LENGTH),
                   block,
                   SM3_DIGEST_LENGTH);
        OPENSSL_free(block);
    }

    return out_len;
}
