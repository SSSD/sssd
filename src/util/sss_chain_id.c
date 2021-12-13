/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2021 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "util/sss_chain_id.h"
#include "config.h"

extern const char *debug_chain_id_fmt;

#ifdef BUILD_CHAIN_ID
void sss_chain_id_set_format(const char *fmt)
{
    debug_chain_id_fmt = fmt;
}

uint64_t sss_chain_id_set(uint64_t id)
{
    uint64_t old_id = debug_chain_id;
    debug_chain_id = id;
    return old_id;
}

uint64_t sss_chain_id_get(void)
{
    return debug_chain_id;
}
#else /* BUILD_CHAIN_ID not defined */

void sss_chain_id_set_format(const char *fmt)
{
    return;
}

uint64_t sss_chain_id_set(uint64_t id)
{
    return 0;
}

uint64_t sss_chain_id_get(void)
{
    return 0;
}

#endif /* BUILD_CHAIN_ID */
