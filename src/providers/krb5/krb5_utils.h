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
#include "config.h"

#include "providers/krb5/krb5_auth.h"
#include "providers/data_provider.h"

errno_t find_or_guess_upn(TALLOC_CTX *mem_ctx, struct ldb_message *msg,
                          struct krb5_ctx *krb5_ctx,
                          struct sss_domain_info *dom, const char *user,
                          const char *user_dom, char **_upn);

errno_t check_if_cached_upn_needs_update(struct sysdb_ctx *sysdb,
                                         struct sss_domain_info *domain,
                                         const char *user,
                                         const char *upn);

errno_t create_ccache_dir(const char *dirname, pcre *illegal_re,
                          uid_t uid, gid_t gid);

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template, bool file_mode,
                             bool case_sensitive);

errno_t become_user(uid_t uid, gid_t gid);
struct sss_creds;
errno_t switch_creds(TALLOC_CTX *mem_ctx,
                     uid_t uid, gid_t gid,
                     int num_gids, gid_t *gids,
                     struct sss_creds **saved_creds);
errno_t restore_creds(struct sss_creds *saved_creds);

errno_t sss_krb5_precreate_ccache(const char *ccname, pcre *illegal_re,
                                  uid_t uid, gid_t gid);
errno_t sss_krb5_cc_destroy(const char *ccname, uid_t uid, gid_t gid);
errno_t sss_krb5_check_ccache_princ(uid_t uid, gid_t gid,
                                    const char *ccname, const char *principal);
errno_t sss_krb5_cc_verify_ccache(const char *ccname, uid_t uid, gid_t gid,
                                  const char *realm, const char *principal);

errno_t get_ccache_file_data(const char *ccache_file, const char *client_name,
                             struct tgt_times *tgtt);


errno_t get_domain_or_subdomain(struct be_ctx *be_ctx,
                                char *domain_name,
                                struct sss_domain_info **dom);
#endif /* __KRB5_UTILS_H__ */
