/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#ifndef _SDAP_SUDO_H_
#define _SDAP_SUDO_H_

#include "providers/backend.h"
#include "providers/ldap/ldap_common.h"

struct sdap_sudo_ctx {
    struct sdap_id_ctx *id_ctx;
    struct be_ptask *full_refresh;
    struct be_ptask *smart_refresh;

    char **hostnames;
    char **ip_addr;
    bool include_netgroups;
    bool include_regexp;
    bool use_host_filter;

    bool full_refresh_done;

    bool run_hostinfo;
};

/* Common functions from ldap_sudo.c */

errno_t sdap_sudo_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct sdap_id_ctx *id_ctx,
                       struct sdap_attr_map *native_map,
                       struct dp_method *dp_methods);

/* sdap async interface */
struct tevent_req *sdap_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct sdap_sudo_ctx *sudo_ctx,
                                          const char *ldap_filter,
                                          const char *sysdb_filter,
                                          bool update_usn);

int sdap_sudo_refresh_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           int *dp_error,
                           size_t *num_rules);

struct tevent_req *sdap_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                                               struct sdap_sudo_ctx *sudo_ctx);

int sdap_sudo_full_refresh_recv(struct tevent_req *req,
                                int *dp_error);

struct tevent_req *sdap_sudo_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_sudo_ctx *sudo_ctx);

int sdap_sudo_smart_refresh_recv(struct tevent_req *req,
                                 int *dp_error);

struct tevent_req *sdap_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_sudo_ctx *sudo_ctx,
                                                const char **rules);

int sdap_sudo_rules_refresh_recv(struct tevent_req *req,
                                 int *dp_error,
                                 bool *deleted);

errno_t
sdap_sudo_ptask_setup(struct be_ctx *be_ctx, struct sdap_sudo_ctx *sudo_ctx);

/* host info */
struct tevent_req * sdap_sudo_get_hostinfo_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_options *opts,
                                                struct be_ctx *be_ctx);

int sdap_sudo_get_hostinfo_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                char ***hostnames, char ***ip_addr);

/* (&(objectClass=sudoRole)(|(cn=defaults)(sudoUser=ALL)%s)) */
#define SDAP_SUDO_FILTER_USER "(&(objectClass=%s)(|(%s=%s)(%s=ALL)%s))"
#define SDAP_SUDO_FILTER_CLASS "(%s=%s)"
#define SDAP_SUDO_FILTER_DEFAULTS  "(&(objectClass=%s)(%s=%s))"
#define SDAP_SUDO_DEFAULTS    "defaults"

#define SDAP_SUDO_FILTER_USERNAME "(%s=%s)"
#define SDAP_SUDO_FILTER_UID "(%s=#%u)"
#define SDAP_SUDO_FILTER_GROUP "(%s=%%%s)"
#define SDAP_SUDO_FILTER_NETGROUP "(%s=+%s)"

#endif /* _SDAP_SUDO_H_ */
