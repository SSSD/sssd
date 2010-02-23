/*
    SSSD

    Kerberos Backend, header file for utilities

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

#ifndef __KRB5_UTILS_H__
#define __KRB5_UTILS_H__

#include <talloc.h>

#include "providers/krb5/krb5_auth.h"
#include "providers/data_provider.h"

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template, bool file_mode,
                             bool *private_path);

errno_t become_user(uid_t uid, gid_t gid);

errno_t create_ccache_dir(TALLOC_CTX *mem_ctx, const char *filename,
                          pcre *illegal_re, uid_t uid, gid_t gid,
                          bool private_path);
#endif /* __KRB5_UTILS_H__ */
