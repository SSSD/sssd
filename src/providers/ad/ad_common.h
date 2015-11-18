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

#define AD_SERVICE_NAME    "AD"
#define AD_GC_SERVICE_NAME "AD_GC"
/* The port the Global Catalog runs on */
#define AD_GC_PORT      3268

#define AD_AT_OBJECT_SID "objectSID"
#define AD_AT_DNS_DOMAIN "DnsDomain"
#define AD_AT_NT_VERSION "NtVer"
#define AD_AT_NETLOGON   "netlogon"

#define MASTER_DOMAIN_SID_FILTER "objectclass=domain"

struct ad_options;

enum ad_basic_opt {
    AD_DOMAIN = 0,
    AD_SERVER,
    AD_BACKUP_SERVER,
    AD_HOSTNAME,
    AD_KEYTAB,
    AD_KRB5_REALM,
    AD_ENABLE_DNS_SITES,
    AD_ACCESS_FILTER,
    AD_ENABLE_GC,
    AD_GPO_ACCESS_CONTROL,
    AD_GPO_CACHE_TIMEOUT,
    AD_GPO_MAP_INTERACTIVE,
    AD_GPO_MAP_REMOTE_INTERACTIVE,
    AD_GPO_MAP_NETWORK,
    AD_GPO_MAP_BATCH,
    AD_GPO_MAP_SERVICE,
    AD_GPO_MAP_PERMIT,
    AD_GPO_MAP_DENY,
    AD_GPO_DEFAULT_RIGHT,
    AD_SITE,
    AD_KRB5_CONFD_PATH,

    AD_OPTS_BASIC /* opts counter */
};

struct ad_id_ctx {
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_id_conn_ctx *ldap_ctx;
    struct sdap_id_conn_ctx *gc_ctx;
    struct ad_options *ad_options;
};

struct ad_service {
    struct sdap_service *sdap;
    struct sdap_service *gc;
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
    struct krb5_ctx *auth_ctx;

    /* Dynamic DNS updates */
    struct be_resolv_ctx *be_res;
    struct be_nsupdate_ctx *dyndns_ctx;
};

errno_t
ad_get_common_options(TALLOC_CTX *mem_ctx,
                      struct confdb_ctx *cdb,
                      const char *conf_path,
                      struct sss_domain_info *dom,
                      struct ad_options **_opts);

struct ad_options *ad_create_default_options(TALLOC_CTX *mem_ctx);

struct ad_options *ad_create_2way_trust_options(TALLOC_CTX *mem_ctx,
                                                const char *realm,
                                                const char *ad_domain,
                                                const char *hostname);

struct ad_options *ad_create_1way_trust_options(TALLOC_CTX *mem_ctx,
                                                const char *ad_domain,
                                                const char *hostname,
                                                const char *keytab,
                                                const char *sasl_authid);

errno_t
ad_failover_init(TALLOC_CTX *mem_ctx, struct be_ctx *ctx,
                 const char *primary_servers,
                 const char *backup_servers,
                 const char *krb5_realm,
                 const char *ad_service,
                 const char *ad_gc_service,
                 const char *ad_domain,
                 struct ad_service **_service);

errno_t
ad_get_id_options(struct ad_options *ad_opts,
                   struct confdb_ctx *cdb,
                   const char *conf_path,
                   struct sdap_options **_opts);
errno_t
ad_get_autofs_options(struct ad_options *ad_opts,
                      struct confdb_ctx *cdb,
                      const char *conf_path);
errno_t
ad_get_auth_options(TALLOC_CTX *mem_ctx,
                    struct ad_options *ad_opts,
                    struct be_ctx *bectx,
                    struct dp_option **_opts);

errno_t
ad_get_dyndns_options(struct be_ctx *be_ctx,
                      struct ad_options *ad_opts);

struct ad_id_ctx *
ad_id_ctx_init(struct ad_options *ad_opts, struct be_ctx *bectx);

struct sdap_id_conn_ctx **
ad_gc_conn_list(TALLOC_CTX *mem_ctx, struct ad_id_ctx *ad_ctx,
               struct sss_domain_info *dom);

struct sdap_id_conn_ctx **
ad_ldap_conn_list(TALLOC_CTX *mem_ctx,
                  struct ad_id_ctx *ad_ctx,
                  struct sss_domain_info *dom);

struct sdap_id_conn_ctx **
ad_user_conn_list(struct ad_id_ctx *ad_ctx,
                  struct sss_domain_info *dom);

struct sdap_id_conn_ctx *
ad_get_dom_ldap_conn(struct ad_id_ctx *ad_ctx, struct sss_domain_info *dom);

/* AD dynamic DNS updates */
errno_t ad_dyndns_init(struct be_ctx *be_ctx,
                       struct ad_options *ctx);
void ad_dyndns_timer(void *pvt);

int ad_sudo_init(struct be_ctx *be_ctx,
                 struct ad_id_ctx *id_ctx,
                 struct bet_ops **ops,
                 void **pvt_data);

int ad_autofs_init(struct be_ctx *be_ctx,
                  struct ad_id_ctx *id_ctx,
                  struct bet_ops **ops,
                  void **pvt_data);

#endif /* AD_COMMON_H_ */
