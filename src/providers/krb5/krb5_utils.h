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

/* Operations on a credential cache */
typedef errno_t (*cc_be_create_fn)(const char *location, pcre *illegal_re,
                                   uid_t uid, gid_t gid, bool private_path);
typedef errno_t (*cc_be_check_existing)(const char *location, uid_t uid,
                                        const char *realm, const char *princ,
                                        const char *cc_template, bool *active,
                                        bool *valid);

/* A ccache back end */
struct sss_krb5_cc_be {
    enum sss_krb5_cc_type type;

    cc_be_create_fn create;
    cc_be_check_existing check_existing;
};

extern struct sss_krb5_cc_be file_cc;

errno_t create_ccache_dir(const char *dirname, pcre *illegal_re,
                          uid_t uid, gid_t gid, bool private_path);

errno_t cc_file_create(const char *filename, pcre *illegal_re,
                       uid_t uid, gid_t gid, bool private_path);

struct sss_krb5_cc_be *get_cc_be_ops(enum sss_krb5_cc_type type);
struct sss_krb5_cc_be *get_cc_be_ops_ccache(const char *ccache);

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template, bool file_mode,
                             bool case_sensitive, bool *private_path);

errno_t become_user(uid_t uid, gid_t gid);
struct sss_creds;
errno_t switch_creds(TALLOC_CTX *mem_ctx,
                     uid_t uid, gid_t gid,
                     int num_gids, gid_t *gids,
                     struct sss_creds **saved_creds);
errno_t restore_creds(struct sss_creds *saved_creds);

errno_t sss_krb5_cc_destroy(const char *ccname, uid_t uid, gid_t gid);
errno_t sss_krb5_check_ccache_princ(uid_t uid, gid_t gid,
                                    const char *ccname, const char *principal);

errno_t get_ccache_file_data(const char *ccache_file, const char *client_name,
                             struct tgt_times *tgtt);

#ifdef HAVE_KRB5_CC_COLLECTION

extern struct sss_krb5_cc_be dir_cc;
extern struct sss_krb5_cc_be keyring_cc;

errno_t cc_dir_create(const char *location, pcre *illegal_re,
                      uid_t uid, gid_t gid, bool private_path);

#endif /* HAVE_KRB5_CC_COLLECTION */


errno_t get_domain_or_subdomain(TALLOC_CTX *mem_ctx, struct be_ctx *be_ctx,
                                char *domain_name,
                                struct sss_domain_info **dom);
#endif /* __KRB5_UTILS_H__ */
