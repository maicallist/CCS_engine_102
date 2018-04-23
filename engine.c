/*
 * Author Chen Gao
 * Created at 23 Apr 2018
 *
 * This file engine.c is part of ccs_engine.
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
