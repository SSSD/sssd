/*
    SSSD

    IPA Common utility code

    Copyright (C) Simo Sorce <ssorce@redhat.com> 2009

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

#ifndef _IPA_COMMON_H_
#define _IPA_COMMON_H_

#include "util/util.h"
#include "confdb/confdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/krb5/krb5_common.h"

enum ipa_basic_opt {
    IPA_DOMAIN = 0,
    IPA_SERVER,
    IPA_HOSTNAME,
    IPA_SEARCH_TIMEOUT,
    IPA_NETWORK_TIMEOUT,
    IPA_OPT_TIMEOUT,
    IPA_OFFLINE_TIMEOUT,
    IPA_ENUM_REFRESH_TIMEOUT,
    IPA_ENTRY_CACHE_TIMEOUT,

    IPA_OPTS_BASIC /* opts counter */
};

struct ipa_options {
    struct dp_option *basic;
    struct sdap_options *id;
};

/* options parsers */
int ipa_get_options(TALLOC_CTX *memctx,
                    struct confdb_ctx *cdb,
                    const char *conf_path,
                    struct sss_domain_info *dom,
                    struct ipa_options **_opts);

int ipa_get_id_options(TALLOC_CTX *memctx,
                       struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct ipa_options *ipa_opts,
                       struct sdap_options **_opts);

int ipa_get_auth_options(TALLOC_CTX *memctx,
                         struct confdb_ctx *cdb,
                         const char *conf_path,
                         struct ipa_options *ipa_opts,
                         struct dp_option **_opts);

#endif /* _IPA_COMMON_H_ */
