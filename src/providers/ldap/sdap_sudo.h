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

struct sdap_sudo_ctx {
    struct sdap_id_ctx *id_ctx;

    char **hostnames;
    char **ip_addr;
    bool include_netgroups;
    bool include_regexp;
    bool use_host_filter;
};

/* Common functions from ldap_sudo.c */
void sdap_sudo_handler(struct be_req *breq);
int sdap_sudo_init(struct be_ctx *be_ctx,
                   struct sdap_id_ctx *id_ctx,
                   struct bet_ops **ops,
                   void **pvt_data);

/* sdap async interface */
struct tevent_req *sdap_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct be_ctx *be_ctx,
                                          struct sdap_options *opts,
                                          struct sdap_id_conn_cache *conn_cache,
                                          const char *ldap_filter,
                                          const char *sysdb_filter);

int sdap_sudo_refresh_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           int *dp_error,
                           int *error,
                           char **usn,
                           size_t *num_rules);

/* timer */

typedef struct tevent_req * (*sdap_sudo_timer_fn_t)(TALLOC_CTX *mem_ctx,
                                                    struct sdap_sudo_ctx *sudo_ctx);

struct tevent_req * sdap_sudo_timer_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sdap_sudo_ctx *sudo_ctx,
                                         struct timeval when,
                                         time_t timeout,
                                         sdap_sudo_timer_fn_t fn);

int sdap_sudo_timer_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct tevent_req **_subreq);

/* host info */
struct tevent_req * sdap_sudo_get_hostinfo_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_options *opts,
                                                struct be_ctx *be_ctx);

int sdap_sudo_get_hostinfo_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                char ***hostnames, char ***ip_addr);

/* (&(objectClass=sudoRole)(|(cn=defaults)(sudoUser=ALL)%s)) */
#define SDAP_SUDO_FILTER_USER "(&(objectClass=%s)(|(%s=%s)(%s=ALL)%s))"
#define SDAP_SUDO_FILTER_CLASS "(objectClass=%s)"
#define SDAP_SUDO_FILTER_DEFAULTS  "(&(objectClass=%s)(%s=%s))"
#define SDAP_SUDO_DEFAULTS    "defaults"

#define SDAP_SUDO_FILTER_USERNAME "(%s=%s)"
#define SDAP_SUDO_FILTER_UID "(%s=#%u)"
#define SDAP_SUDO_FILTER_GROUP "(%s=%%%s)"
#define SDAP_SUDO_FILTER_NETGROUP "(%s=+%s)"

#endif /* _SDAP_SUDO_H_ */
