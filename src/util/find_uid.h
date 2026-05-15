/*
    SSSD

    Create uid table

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#ifndef __FIND_UID_H__
#define __FIND_UID_H__

#include <talloc.h>
#include <sys/types.h>
#include <dhash.h>

#include "util/util.h"

errno_t get_uid_table(TALLOC_CTX *mem_ctx, hash_table_t **table);
errno_t check_if_uid_is_active(uid_t uid, bool *result);

#endif /* __FIND_UID_H__ */
