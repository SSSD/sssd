/*
    SSSD

    Kerberos 5 Backend Module -- ccache related utilities

    Authors:
        Sumit Bose <sbose@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

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

#ifndef __KRB5_CCACHE_H__
#define __KRB5_CCACHE_H__

#include "util/util.h"

struct tgt_times {
    time_t authtime;
    time_t starttime;
    time_t endtime;
    time_t renew_till;
};

errno_t sss_krb5_check_ccache_princ(krb5_context kctx,
                                    const char *ccname,
                                    krb5_principal user_princ);

errno_t sss_krb5_cc_verify_ccache(const char *ccname, const char *realm,
                                  const char *principal);

errno_t safe_remove_old_ccache_file(const char *old_ccache,
                                    const char *new_ccache);

errno_t switch_to_user(void);

/**
 * @brief Copy given ccache into a MEMORY ccache
 *
 * @param[in] mem_ctx Talloc memory context the new ccache name should be
 *                    allocated on
 * @param[in] kctx Kerberos context
 * @param[in] ccache_file Name of existing ccache
 * @param[out] _mem_name Name of the new MEMORY ccache
 *
 * In contrast to MEMORY keytabs MEMORY ccaches can and must be removed
 * explicitly with krb5_cc_destroy() from the memory. Just calling
 * krb5_cc_close() will keep the MEMORY ccache in memory even if there are no
 * open handles for the given MEMORY ccache.
 */
krb5_error_code copy_ccache_into_memory(TALLOC_CTX *mem_ctx, krb5_context kctx,
                                        const char *ccache_file,
                                        char **_mem_name);
#endif /* __KRB5_CCACHE_H__ */
