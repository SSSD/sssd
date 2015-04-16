/*
    Authors:
        Simo Sorce <ssorce@redhat.com>
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

#ifndef __PAMSRV_H__
#define __PAMSRV_H__

#include <security/pam_appl.h>
#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder.h"

struct pam_auth_req;

typedef void (pam_dp_callback_t)(struct pam_auth_req *preq);

struct pam_ctx {
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int neg_timeout;
    time_t id_timeout;
    hash_table_t *id_table;
    size_t trusted_uids_count;
    uid_t *trusted_uids;

    /* List of domains that are accessible even for untrusted users. */
    char **public_domains;
    int public_domains_count;
};

struct pam_auth_dp_req {
    struct pam_auth_req *preq;
};

struct pam_auth_req {
    struct cli_ctx *cctx;
    struct sss_domain_info *domain;

    struct pam_data *pd;

    pam_dp_callback_t *callback;

    bool is_uid_trusted;
    bool check_provider;
    void *data;
    bool use_cached_auth;
    /* whether cached authentication was tried and failed */
    bool cached_auth_failed;

    struct pam_auth_dp_req *dpreq_spy;
};

struct sss_cmd_table *get_pam_cmds(void);

int pam_dp_send_req(struct pam_auth_req *preq, int timeout);

int LOCAL_pam_handler(struct pam_auth_req *preq);

#endif /* __PAMSRV_H__ */
