/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef AD_COMMON_H_
#define AD_COMMON_H_

#include "util/util.h"
#include "providers/ldap/ldap_common.h"

#define AD_SERVICE_NAME "AD"

struct ad_options;

enum ad_basic_opt {
    AD_DOMAIN = 0,
    AD_SERVER,
    AD_BACKUP_SERVER,
    AD_HOSTNAME,
    AD_KEYTAB,
    AD_KRB5_REALM,

    AD_OPTS_BASIC /* opts counter */
};

struct ad_id_ctx {
    struct sdap_id_ctx *sdap_id_ctx;
    struct ad_options *ad_options;
};

struct ad_service {
    struct sdap_service *sdap;
    struct krb5_service *krb5_service;
};

struct ad_options {
    /* Common options */
    struct dp_option *basic;
    struct ad_service *service;

    /* ID Provider */
    struct sdap_options *id;
    struct ad_id_ctx *id_ctx;

    /* Auth and chpass Provider */
    struct dp_option *auth;
    struct krb5_ctx *auth_ctx;
};

errno_t
ad_get_common_options(TALLOC_CTX *mem_ctx,
                      struct confdb_ctx *cdb,
                      const char *conf_path,
                      struct sss_domain_info *dom,
                      struct ad_options **_opts);

errno_t
ad_failover_init(TALLOC_CTX *mem_ctx, struct be_ctx *ctx,
                 const char *primary_servers,
                 const char *backup_servers,
                 struct ad_options *options,
                 struct ad_service **_service);

errno_t
ad_get_id_options(struct ad_options *ad_opts,
                   struct confdb_ctx *cdb,
                   const char *conf_path,
                   struct sdap_options **_opts);
errno_t
ad_get_auth_options(TALLOC_CTX *mem_ctx,
                    struct ad_options *ad_opts,
                    struct be_ctx *bectx,
                    struct dp_option **_opts);

#endif /* AD_COMMON_H_ */
