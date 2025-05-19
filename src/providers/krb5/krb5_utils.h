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
#include "krb5_plugin/idp/idp.h"

errno_t find_or_guess_upn(TALLOC_CTX *mem_ctx, struct ldb_message *msg,
                          struct krb5_ctx *krb5_ctx,
                          struct sss_domain_info *dom, const char *user,
                          const char *user_dom, char **_upn);

errno_t check_if_cached_upn_needs_update(struct sysdb_ctx *sysdb,
                                         struct sss_domain_info *domain,
                                         const char *user,
                                         const char *upn);

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template, sss_regexp_t *illegal_re,
                             bool file_mode, bool case_sensitive);

errno_t get_domain_or_subdomain(struct be_ctx *be_ctx,
                                char *domain_name,
                                struct sss_domain_info **dom);

errno_t
parse_krb5_map_user(TALLOC_CTX *mem_ctx,
                    const char *krb5_map_user,
                    const char *dom_name,
                    struct map_id_name_to_krb_primary **_name_to_primary);

errno_t attach_oauth2_info_msg(struct pam_data *pd,
                               struct sss_idp_oauth2 *data);

#endif /* __KRB5_UTILS_H__ */
