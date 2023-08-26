/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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

#ifndef _SDAP_ASYNC_H_
#define _SDAP_ASYNC_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <talloc.h>
#include <tevent.h>
#include "providers/backend.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_id_op.h"
#include "providers/fail_over.h"

#define AD_TOKENGROUPS_ATTR "tokenGroups"

struct tevent_req *sdap_connect_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sdap_options *opts,
                                     const char *uri,
                                     struct sockaddr *sockaddr,
                                     socklen_t sockaddr_len,
				     bool use_start_tls);
int sdap_connect_recv(struct tevent_req *req,
                      TALLOC_CTX *memctx,
                      struct sdap_handle **sh);

struct tevent_req *sdap_connect_host_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sdap_options *opts,
                                          struct resolv_ctx *resolv_ctx,
                                          enum restrict_family family_order,
                                          enum host_database *host_db,
                                          const char *protocol,
                                          const char *host,
                                          int port,
                                          bool use_start_tls);

errno_t sdap_connect_host_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               struct sdap_handle **_sh);

/* Search users in LDAP, return them as attrs */
enum sdap_entry_lookup_type {
    SDAP_LOOKUP_SINGLE,         /* Direct single-user/group lookup */
    SDAP_LOOKUP_WILDCARD,       /* Multiple entries with a limit */
    SDAP_LOOKUP_ENUMERATE,      /* Fetch all entries from the server */
};

struct tevent_req *sdap_search_user_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sss_domain_info *dom,
                                         struct sdap_options *opts,
                                         struct sdap_search_base **search_bases,
                                         struct sdap_handle *sh,
                                         const char **attrs,
                                         const char *filter,
                                         int timeout,
                                         enum sdap_entry_lookup_type lookup_type);
int sdap_search_user_recv(TALLOC_CTX *memctx, struct tevent_req *req,
                          char **higher_usn, struct sysdb_attrs ***users,
                          size_t *count);

/* Search users in LDAP using the request above, save them to cache */
struct tevent_req *sdap_get_users_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_search_base **search_bases,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter,
                                       int timeout,
                                       enum sdap_entry_lookup_type lookup_type,
                                       struct sysdb_attrs *mapped_attrs);
int sdap_get_users_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx, char **timestamp);

struct tevent_req *sdap_get_groups_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sdap_domain *sdom,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter,
                                       int timeout,
                                       enum sdap_entry_lookup_type lookup_type,
                                       bool no_members);
int sdap_get_groups_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx, char **timestamp);

struct tevent_req *sdap_get_netgroups_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sss_domain_info *dom,
                                           struct sysdb_ctx *sysdb,
                                           struct sdap_options *opts,
                                           struct sdap_search_base **search_bases,
                                           struct sdap_handle *sh,
                                           const char **attrs,
                                           const char *filter,
                                           int timeout);
int sdap_get_netgroups_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx, char **timestamp,
                            size_t *reply_count,
                            struct sysdb_attrs ***reply);

struct tevent_req *
sdap_host_info_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct sdap_handle *sh,
                    struct sdap_options *opts,
                    const char *hostname,
                    struct sdap_attr_map *host_map,
                    struct sdap_search_base **search_bases);

errno_t
sdap_host_info_recv(struct tevent_req *req,
                    TALLOC_CTX *mem_ctx,
                    size_t *host_count,
                    struct sysdb_attrs ***hosts);

struct tevent_req *sdap_auth_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_handle *sh,
                                  const char *sasl_mech,
                                  const char *sasl_user,
                                  const char *user_dn,
                                  struct sss_auth_token *authtok,
                                  int simple_bind_timeout,
                                  bool use_ppolicy);

errno_t sdap_auth_recv(struct tevent_req *req,
                       TALLOC_CTX *memctx,
                       struct sdap_ppolicy_data **ppolicy);

struct tevent_req *sdap_get_initgr_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sdap_domain *sdom,
                                        struct sdap_handle *sh,
                                        struct sdap_id_ctx *id_ctx,
                                        struct sdap_id_conn_ctx *conn,
                                        const char *name,
                                        int filter_type,
                                        const char *extra_value,
                                        const char **grp_attrs);
int sdap_get_initgr_recv(struct tevent_req *req);

struct tevent_req *sdap_exop_modify_passwd_send(TALLOC_CTX *memctx,
                                                struct tevent_context *ev,
                                                struct sdap_handle *sh,
                                                char *user_dn,
                                                const char *password,
                                                const char *new_password,
                                                int timeout,
                                                bool use_ppolicy);
errno_t sdap_exop_modify_passwd_recv(struct tevent_req *req,
                                     TALLOC_CTX *mem_ctx,
                                     char **user_error_msg);

struct tevent_req *
sdap_modify_passwd_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sdap_handle *sh,
                        int timeout,
                        char *attr,
                        const char *user_dn,
                        const char *new_password);

errno_t sdap_modify_passwd_recv(struct tevent_req *req,
                                TALLOC_CTX * mem_ctx,
                                char **_user_error_message);

struct tevent_req *
sdap_modify_shadow_lastchange_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sdap_handle *sh,
                             const char *dn,
                             char *attr);

errno_t sdap_modify_shadow_lastchange_recv(struct tevent_req *req);

enum connect_tls {
    CON_TLS_DFL,
    CON_TLS_ON,
    CON_TLS_OFF
};

struct tevent_req *sdap_cli_connect_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct be_ctx *be,
                                         struct sdap_service *service,
                                         bool skip_rootdse,
                                         enum connect_tls force_tls,
                                         bool skip_auth);
int sdap_cli_connect_recv(struct tevent_req *req,
                          TALLOC_CTX *memctx,
                          bool *can_retry,
                          struct sdap_handle **gsh,
                          struct sdap_server_opts **srv_opts);

/* Exposes all options of generic send while allowing to parse by map */
struct tevent_req *sdap_get_and_parse_generic_send(TALLOC_CTX *memctx,
                                                   struct tevent_context *ev,
                                                   struct sdap_options *opts,
                                                   struct sdap_handle *sh,
                                                   const char *search_base,
                                                   int scope,
                                                   const char *filter,
                                                   const char **attrs,
                                                   struct sdap_attr_map *map,
                                                   int map_num_attrs,
                                                   int attrsonly,
                                                   LDAPControl **serverctrls,
                                                   LDAPControl **clientctrls,
                                                   int sizelimit,
                                                   int timeout,
                                                   bool allow_paging);
int sdap_get_and_parse_generic_recv(struct tevent_req *req,
                                    TALLOC_CTX *mem_ctx,
                                    size_t *reply_count,
                                    struct sysdb_attrs ***reply);

struct tevent_req *sdap_get_generic_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh,
                                         const char *search_base,
                                         int scope,
                                         const char *filter,
                                         const char **attrs,
                                         struct sdap_attr_map *map,
                                         int map_num_attrs,
                                         int timeout,
                                         bool allow_paging);
int sdap_get_generic_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx, size_t *reply_count,
                         struct sysdb_attrs ***reply_list);

bool sdap_has_deref_support_ex(struct sdap_handle *sh,
                               struct sdap_options *opts,
                               bool ignore_client);
bool sdap_has_deref_support(struct sdap_handle *sh,
                            struct sdap_options *opts);

enum sdap_deref_flags {
    SDAP_DEREF_FLG_SILENT = 1 << 0,     /* Do not warn if dereference fails */
};

struct tevent_req *
sdap_deref_search_with_filter_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_options *opts,
                                   struct sdap_handle *sh,
                                   const char *search_base,
                                   const char *filter,
                                   const char *deref_attr,
                                   const char **attrs,
                                   int num_maps,
                                   struct sdap_attr_map_info *maps,
                                   int timeout,
                                   unsigned flags);
int sdap_deref_search_with_filter_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *reply_count,
                                       struct sdap_deref_attrs ***reply);

struct tevent_req *
sdap_deref_search_send(TALLOC_CTX *memctx,
                       struct tevent_context *ev,
                       struct sdap_options *opts,
                       struct sdap_handle *sh,
                       const char *base_dn,
                       const char *deref_attr,
                       const char **attrs,
                       int num_maps,
                       struct sdap_attr_map_info *maps,
                       int timeout);
int sdap_deref_search_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sdap_deref_attrs ***reply);


struct tevent_req *
sdap_sd_search_send(TALLOC_CTX *memctx,
		    struct tevent_context *ev,
		    struct sdap_options *opts,
		    struct sdap_handle *sh,
		    const char *base_dn,
		    int sd_flags,
		    const char **attrs,
		    int timeout);
int sdap_sd_search_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        size_t *_reply_count,
                        struct sysdb_attrs ***_reply,
                        size_t *_ref_count,
                        char ***_refs);

errno_t
sdap_attrs_add_ldap_attr(struct sysdb_attrs *ldap_attrs,
                         const char *attr_name,
                         const char *attr_desc,
                         bool multivalued,
                         const char *name,
                         struct sysdb_attrs *attrs);

#define sdap_attrs_add_string(ldap_attrs, attr_name, attr_desc, name, attrs) \
        sdap_attrs_add_ldap_attr(ldap_attrs, attr_name, attr_desc, \
                                 false, name, attrs)

#define sdap_attrs_add_list(ldap_attrs, attr_name, attr_desc, name, attrs) \
    sdap_attrs_add_ldap_attr(ldap_attrs, attr_name, attr_desc,   \
                             true, name, attrs)

errno_t
sdap_save_all_names(const char *name,
                    struct sysdb_attrs *ldap_attrs,
                    struct sss_domain_info *dom,
                    enum sysdb_member_type entry_type,
                    struct sysdb_attrs *attrs);

struct tevent_req *
sdap_get_services_send(TALLOC_CTX *memctx,
                       struct tevent_context *ev,
                       struct sss_domain_info *dom,
                       struct sysdb_ctx *sysdb,
                       struct sdap_options *opts,
                       struct sdap_search_base **search_bases,
                       struct sdap_handle *sh,
                       const char **attrs,
                       const char *filter,
                       int timeout,
                       bool enumeration);
errno_t
sdap_get_services_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       char **usn_value);

struct tevent_req *
enum_services_send(TALLOC_CTX *memctx,
                   struct tevent_context *ev,
                   struct sdap_id_ctx *id_ctx,
                   struct sdap_id_op *op,
                   bool purge);

errno_t
enum_services_recv(struct tevent_req *req);

struct tevent_req *
sdap_get_iphost_send(TALLOC_CTX *memctx,
                     struct tevent_context *ev,
                     struct sss_domain_info *dom,
                     struct sysdb_ctx *sysdb,
                     struct sdap_options *opts,
                     struct sdap_search_base **search_bases,
                     struct sdap_handle *sh,
                     const char **attrs,
                     const char *filter,
                     int timeout,
                     bool enumeration);
errno_t
sdap_get_iphost_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     char **usn_value);

struct tevent_req *
enum_iphosts_send(TALLOC_CTX *memctx,
                  struct tevent_context *ev,
                  struct sdap_id_ctx *id_ctx,
                  struct sdap_id_op *op,
                  bool purge);

errno_t
enum_iphosts_recv(struct tevent_req *req);

struct tevent_req *
sdap_get_ipnetwork_send(TALLOC_CTX *memctx,
                        struct tevent_context *ev,
                        struct sss_domain_info *dom,
                        struct sysdb_ctx *sysdb,
                        struct sdap_options *opts,
                        struct sdap_search_base **search_bases,
                        struct sdap_handle *sh,
                        const char **attrs,
                        const char *filter,
                        int timeout,
                        bool enumeration);

errno_t
sdap_get_ipnetwork_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        char **usn_value);

struct tevent_req *
enum_ipnetworks_send(TALLOC_CTX *memctx,
                     struct tevent_context *ev,
                     struct sdap_id_ctx *id_ctx,
                     struct sdap_id_op *op,
                     bool purge);

errno_t
enum_ipnetworks_recv(struct tevent_req *req);

struct tevent_req *
sdap_ad_tokengroups_initgroups_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sdap_id_ctx *id_ctx,
                                    struct sdap_id_conn_ctx *conn,
                                    struct sdap_options *opts,
                                    struct sysdb_ctx *sysdb,
                                    struct sss_domain_info *domain,
                                    struct sdap_handle *sh,
                                    const char *name,
                                    const char *orig_dn,
                                    int timeout,
                                    bool use_id_mapping);

errno_t
sdap_ad_tokengroups_initgroups_recv(struct tevent_req *req);

errno_t
sdap_handle_id_collision_for_incomplete_groups(struct data_provider *dp,
                                               struct sss_domain_info *domain,
                                               const char *name,
                                               gid_t gid,
                                               const char *original_dn,
                                               const char *sid_str,
                                               const char *uuid,
                                               bool posix,
                                               time_t now);

struct sdap_id_conn_ctx *get_ldap_conn_from_sdom_pvt(struct sdap_options *opts,
                                                     struct sdap_domain *sdom);
#endif /* _SDAP_ASYNC_H_ */
