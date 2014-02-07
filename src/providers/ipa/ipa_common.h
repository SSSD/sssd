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
#include "providers/ad/ad_common.h"
#include "providers/ad/ad_srv.h"

struct ipa_service {
    struct sdap_service *sdap;
    struct krb5_service *krb5_service;
};

enum ipa_basic_opt {
    IPA_DOMAIN = 0,
    IPA_SERVER,
    IPA_BACKUP_SERVER,
    IPA_HOSTNAME,
    IPA_HBAC_SEARCH_BASE,
    IPA_HOST_SEARCH_BASE,
    IPA_SELINUX_SEARCH_BASE,
    IPA_SUBDOMAINS_SEARCH_BASE,
    IPA_MASTER_DOMAIN_SEARCH_BASE,
    IPA_KRB5_REALM,
    IPA_HBAC_REFRESH,
    IPA_SELINUX_REFRESH,
    IPA_HBAC_DENY_METHOD,
    IPA_HBAC_SUPPORT_SRCHOST,
    IPA_AUTOMOUNT_LOCATION,
    IPA_RANGES_SEARCH_BASE,
    IPA_ENABLE_DNS_SITES,
    IPA_SERVER_MODE,

    IPA_OPTS_BASIC /* opts counter */
};

enum ipa_netgroup_attrs {
    IPA_OC_NETGROUP = 0,
    IPA_AT_NETGROUP_NAME,
    IPA_AT_NETGROUP_MEMBER,
    IPA_AT_NETGROUP_MEMBER_OF,
    IPA_AT_NETGROUP_MEMBER_USER,
    IPA_AT_NETGROUP_MEMBER_HOST,
    IPA_AT_NETGROUP_EXTERNAL_HOST,
    IPA_AT_NETGROUP_DOMAIN,
    IPA_AT_NETGROUP_UUID,

    IPA_OPTS_NETGROUP /* attrs counter */
};

enum ipa_host_attrs {
    IPA_OC_HOST = 0,
    IPA_AT_HOST_NAME,
    IPA_AT_HOST_FQDN,
    IPA_AT_HOST_SERVERHOSTNAME,
    IPA_AT_HOST_MEMBER_OF,
    IPA_AT_HOST_SSH_PUBLIC_KEY,
    IPA_AT_HOST_UUID,

    IPA_OPTS_HOST /* attrs counter */
};

enum ipa_hostgroup_attrs {
    IPA_OC_HOSTGROUP = 0,
    IPA_AT_HOSTGROUP_NAME,
    IPA_AT_HOSTGROUP_MEMBER_OF,
    IPA_AT_HOSTGROUP_UUID,

    IPA_OPTS_HOSTGROUP /* attrs counter */
};

enum ipa_selinux_usermap_attrs {
    IPA_OC_SELINUX_USERMAP = 0,
    IPA_AT_SELINUX_USERMAP_NAME,
    IPA_AT_SELINUX_USERMAP_MEMBER_USER,
    IPA_AT_SELINUX_USERMAP_MEMBER_HOST,
    IPA_AT_SELINUX_USERMAP_SEE_ALSO,
    IPA_AT_SELINUX_USERMAP_SELINUX_USER,
    IPA_AT_SELINUX_USERMAP_ENABLED,
    IPA_AT_SELINUX_USERMAP_USERCAT,
    IPA_AT_SELINUX_USERMAP_HOSTCAT,
    IPA_AT_SELINUX_USERMAP_UUID,

    IPA_OPTS_SELINUX_USERMAP /* attrs counter */
};

struct ipa_auth_ctx {
    struct krb5_ctx *krb5_auth_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_auth_ctx *sdap_auth_ctx;
    struct dp_option *ipa_options;
};

/* In server mode, each subdomain corresponds to an AD context */

struct ipa_id_ctx {
    struct sdap_id_ctx *sdap_id_ctx;
    struct ipa_options *ipa_options;

    /* Only used with server mode */
    struct ipa_server_mode_ctx *server_mode;
};

struct ipa_options {
    struct dp_option *basic;

    struct sdap_attr_map *host_map;
    struct sdap_attr_map *hostgroup_map;
    struct sdap_attr_map *selinuxuser_map;

    struct sdap_search_base **host_search_bases;
    struct sdap_search_base **hbac_search_bases;
    struct sdap_search_base **selinux_search_bases;
    struct sdap_search_base **subdomains_search_bases;
    struct sdap_search_base **master_domain_search_bases;
    struct sdap_search_base **ranges_search_bases;
    struct ipa_service *service;

    /* id provider */
    struct sdap_options *id;
    struct ipa_id_ctx *id_ctx;
    struct be_resolv_ctx *be_res;
    struct be_nsupdate_ctx *dyndns_ctx;

    /* auth and chpass provider */
    struct dp_option *auth;
    struct ipa_auth_ctx *auth_ctx;
};

#define IPA_RANGE_LOCAL "ipa-local"
#define IPA_RANGE_AD_TRUST "ipa-ad-trust"
#define IPA_RANGE_AD_TRUST_POSIX "ipa-ad-trust-posix"

/* options parsers */
int ipa_get_options(TALLOC_CTX *memctx,
                    struct confdb_ctx *cdb,
                    const char *conf_path,
                    struct sss_domain_info *dom,
                    struct ipa_options **_opts);

int ipa_get_id_options(struct ipa_options *ipa_opts,
                       struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct sdap_options **_opts);

int ipa_get_auth_options(struct ipa_options *ipa_opts,
                         struct confdb_ctx *cdb,
                         const char *conf_path,
                         struct dp_option **_opts);

int ipa_get_autofs_options(struct ipa_options *ipa_opts,
                           struct confdb_ctx *cdb,
                           const char *conf_path,
                           struct sdap_options **_opts);

errno_t ipa_get_dyndns_options(struct be_ctx *be_ctx,
                               struct ipa_options *ctx);

int ipa_autofs_init(struct be_ctx *be_ctx,
                    struct ipa_id_ctx *id_ctx,
                    struct bet_ops **ops,
                    void **pvt_data);

int ipa_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                     const char *primary_servers,
                     const char *backup_servers,
                     struct ipa_options *options,
                     struct ipa_service **_service);

int ipa_sudo_init(struct be_ctx *be_ctx,
                  struct ipa_id_ctx *id_ctx,
                  struct bet_ops **ops,
                  void **pvt_data);

errno_t get_idmap_data_from_range(struct range_info *r, char *domain_name,
                                  char **_name, char **_sid, uint32_t *_rid,
                                  struct sss_idmap_range *_range,
                                  bool *_external_mapping);

errno_t ipa_idmap_get_ranges_from_sysdb(struct sdap_idmap_ctx *idmap_ctx,
                                        const char *dom_name,
                                        const char *dom_sid_str,
                                        bool allow_collisions);

errno_t ipa_idmap_init(TALLOC_CTX *mem_ctx,
                       struct sdap_id_ctx *id_ctx,
                       struct sdap_idmap_ctx **_idmap_ctx);
#endif /* _IPA_COMMON_H_ */
