/*
   SSSD

   Data Provider, private header file

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#ifndef __DP_BACKEND_H__
#define __DP_BACKEND_H__

#include "providers/data_provider.h"
#include "db/sysdb.h"
#include "responder/pam/pamsrv.h"

struct be_mod_ops;

struct be_ctx {
    struct event_context *ev;
    struct confdb_ctx *cdb;
    struct sysdb_ctx *sysdb;
    struct service_sbus_ctx *ss_ctx;
    struct service_sbus_ctx *dp_ctx;
    const char *name;
    const char *domain;
    const char *identity;
    const char *conf_path;
    struct be_mod_ops *ops;
    void *pvt_data;
};

struct be_req;

typedef void (*be_async_callback_t)(struct be_req *, int, const char *);

struct be_req {
    struct be_ctx *be_ctx;
    void *req_data;

    be_async_callback_t fn;
    void *pvt;
};

struct be_acct_req {
    int entry_type;
    int attr_type;
    int filter_type;
    char *filter_value;
};

struct be_online_req {
    int online;
};

struct be_pam_handler {
    int pam_status; 
    const char *domain;
    struct pam_data *pd;
};

typedef void (*be_req_fn_t)(struct be_req *);

struct be_mod_ops {
    be_req_fn_t check_online;
    be_req_fn_t get_account_info;
    be_req_fn_t pam_handler;
};

#endif /* __DP_BACKEND_H___ */
