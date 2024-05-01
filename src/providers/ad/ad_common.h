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
#define AD_GC_PORT         3268
#define AD_GC_LDAPS_PORT   3269

#define AD_AT_OBJECT_SID "objectSID"
#define AD_AT_DNS_DOMAIN "DnsDomain"
#define AD_AT_NT_VERSION "NtVer"
#define AD_AT_NETLOGON   "netlogon"

#define MASTER_DOMAIN_SID_FILTER "objectclass=domain"

struct ad_options;

enum ad_basic_opt {
    AD_DOMAIN = 0,
    AD_ENABLED_DOMAINS,
    AD_SERVER,
    AD_BACKUP_SERVER,
    AD_HOSTNAME,
    AD_KEYTAB,
    AD_KRB5_REALM,
    AD_ENABLE_DNS_SITES,
    AD_ACCESS_FILTER,
    AD_ENABLE_GC,
    AD_GPO_ACCESS_CONTROL,
    AD_GPO_IMPLICIT_DENY,
    AD_GPO_IGNORE_UNREADABLE,
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
    AD_MAXIMUM_MACHINE_ACCOUNT_PASSWORD_AGE,
    AD_MACHINE_ACCOUNT_PASSWORD_RENEWAL_OPTS,
    AD_UPDATE_SAMBA_MACHINE_ACCOUNT_PASSWORD,
    AD_USE_LDAPS,
#ifdef BUILD_ALLOW_REMOTE_DOMAIN_LOCAL_GROUPS
    AD_ALLOW_REMOTE_DOMAIN_LOCAL,
#endif

    AD_OPTS_BASIC /* opts counter */
};

struct ad_id_ctx {
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_id_conn_ctx *ldap_ctx;
    struct sdap_id_conn_ctx *gc_ctx;
    struct ad_options *ad_options;
};

struct ad_resolver_ctx {
    struct sdap_resolver_ctx *sdap_resolver_ctx;
    struct ad_id_ctx *ad_id_ctx;
};

struct ad_service {
    struct sdap_service *sdap;
    struct sdap_service *gc;
    struct krb5_service *krb5_service;
    const char *ldap_scheme;
    int port;
    int gc_port;
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

    /* Discovered site and forest names */
    const char *current_site;
    const char *current_forest;
};

errno_t
ad_get_common_options(TALLOC_CTX *mem_ctx,
                      struct confdb_ctx *cdb,
                      const char *conf_path,
                      struct sss_domain_info *dom,
                      struct ad_options **_opts);

/* FIXME: ad_get_common_options and ad_create_options are
 * similar. The later is subdomain specific. It may be
 * good to merge the two into one more generic funtion. */
struct ad_options *ad_create_options(TALLOC_CTX *mem_ctx,
                                     struct confdb_ctx *cdb,
                                     const char *conf_path,
                                     struct data_provider *dp,
                                     struct sss_domain_info *subdom);

struct ad_options *ad_create_trust_options(TALLOC_CTX *mem_ctx,
                                           struct confdb_ctx *cdb,
                                           const char *conf_path,
                                           struct data_provider *dp,
                                           struct sss_domain_info *subdom,
                                           const char *realm,
                                           const char *hostname,
                                           const char *keytab,
                                           const char *sasl_authid);

errno_t ad_set_search_bases(struct sdap_options *id_opts,
                            struct sdap_domain *sdap);

errno_t
ad_failover_init(TALLOC_CTX *mem_ctx, struct be_ctx *ctx,
                 const char *primary_servers,
                 const char *backup_servers,
                 const char *krb5_realm,
                 const char *ad_service,
                 const char *ad_gc_service,
                 const char *ad_domain,
                 bool use_kdcinfo,
                 bool ad_use_ldaps,
                 size_t n_lookahead_primary,
                 size_t n_lookahead_backup,
                 struct ad_service **_service);

void
ad_failover_reset(struct be_ctx *bectx,
                  struct ad_service *adsvc);

errno_t
ad_get_id_options(struct ad_options *ad_opts,
                   struct confdb_ctx *cdb,
                   const char *conf_path,
                   struct data_provider *dp,
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

void ad_set_ssf_and_mech_for_ldaps(struct sdap_options *id_opts);

struct ad_id_ctx *
ad_id_ctx_init(struct ad_options *ad_opts, struct be_ctx *bectx);

errno_t
ad_resolver_ctx_init(TALLOC_CTX *mem_ctx,
                     struct ad_id_ctx *ad_id_ctx,
                     struct ad_resolver_ctx **out_ctx);

struct sdap_id_conn_ctx **
ad_gc_conn_list(TALLOC_CTX *mem_ctx, struct ad_id_ctx *ad_ctx,
               struct sss_domain_info *dom);

struct sdap_id_conn_ctx **
ad_ldap_conn_list(TALLOC_CTX *mem_ctx,
                  struct ad_id_ctx *ad_ctx,
                  struct sss_domain_info *dom);

struct sdap_id_conn_ctx **
ad_user_conn_list(TALLOC_CTX *mem_ctx,
                  struct ad_id_ctx *ad_ctx,
                  struct sss_domain_info *dom);

struct sdap_id_conn_ctx *
ad_get_dom_ldap_conn(struct ad_id_ctx *ad_ctx, struct sss_domain_info *dom);

/* AD dynamic DNS updates */
errno_t ad_dyndns_init(struct be_ctx *be_ctx,
                       struct ad_options *ctx);

errno_t ad_sudo_init(TALLOC_CTX *mem_ctx,
                    struct be_ctx *be_ctx,
                    struct ad_id_ctx *id_ctx,
                    struct dp_method *dp_methods);

errno_t ad_autofs_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct ad_id_ctx *id_ctx,
                       struct dp_method *dp_methods);

errno_t ad_machine_account_password_renewal_init(struct be_ctx *be_ctx,
                                                 struct ad_options *ad_opts);

errno_t netlogon_get_domain_info(TALLOC_CTX *mem_ctx,
                                 struct sysdb_attrs *reply,
                                 bool check_next_nearest_site_as_well,
                                 char **_flat_name,
                                 char **_site,
                                 char **_forest);

errno_t ad_inherit_opts_if_needed(struct dp_option *parent_opts,
                                  struct dp_option *suddom_opts,
                                  struct confdb_ctx *cdb,
                                  const char *subdom_conf_path,
                                  int opt_id);

errno_t ad_refresh_init(struct be_ctx *be_ctx,
                        struct ad_id_ctx *id_ctx);

errno_t
ad_options_switch_site(struct ad_options *ad_options, struct be_ctx *be_ctx,
                       const char *new_site, const char *new_forest);
#endif /* AD_COMMON_H_ */
