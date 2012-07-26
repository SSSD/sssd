/*
    SSSD

    IPA Backend Module -- Access control

    Authors:
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

#ifndef _IPA_ACCESS_H_
#define _IPA_ACCESS_H_

#include "providers/ldap/ldap_common.h"

enum ipa_access_mode {
    IPA_ACCESS_DENY = 0,
    IPA_ACCESS_ALLOW
};

struct ipa_access_ctx {
    struct sdap_id_ctx *sdap_ctx;
    struct dp_option *ipa_options;
    struct time_rules_ctx *tr_ctx;
    time_t last_update;
    struct sdap_access_ctx *sdap_access_ctx;

    struct sdap_attr_map *host_map;
    struct sdap_attr_map *hostgroup_map;
    struct sdap_search_base **host_search_bases;
    struct sdap_search_base **hbac_search_bases;
};

struct hbac_ctx {
    struct sdap_id_ctx *sdap_ctx;
    struct ipa_access_ctx *access_ctx;
    struct sdap_id_op *sdap_op;
    struct dp_option *ipa_options;
    struct time_rules_ctx *tr_ctx;
    struct be_req *be_req;
    struct pam_data *pd;

    struct sdap_search_base **search_bases;

    /* Hosts */
    size_t host_count;
    struct sysdb_attrs **hosts;
    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
    struct sysdb_attrs *ipa_host;

    /* Rules */
    bool get_deny_rules;
    size_t rule_count;
    struct sysdb_attrs **rules;

    /* Services */
    size_t service_count;
    struct sysdb_attrs **services;
    size_t servicegroup_count;
    struct sysdb_attrs **servicegroups;
};

/* Get BE context associated with HBAC context */
static inline struct be_ctx *hbac_ctx_be(struct hbac_ctx *hbac_ctx)
{
    struct be_req *req = hbac_ctx != NULL ? hbac_ctx->be_req : NULL;
    return req != NULL ? req->be_ctx : NULL;
}

/* Get sysdb associated with HBAC context */
static inline struct sysdb_ctx *hbac_ctx_sysdb(struct hbac_ctx *hbac_ctx)
{
    struct be_req *be_req = hbac_ctx->be_req;
    return be_req != NULL ? be_req->sysdb : NULL;
}

/* Get tevent context associated with HBAC context */
static inline struct tevent_context *hbac_ctx_ev(struct hbac_ctx *hbac_ctx)
{
    struct be_ctx *be_ctx = hbac_ctx_be(hbac_ctx);
    return be_ctx != NULL ? be_ctx->ev : NULL;
}

/* Get sdap_id_ctx associated with HBAC context */
static inline struct sdap_id_ctx *hbac_ctx_sdap_id_ctx(struct hbac_ctx *hbac_ctx)
{
    return hbac_ctx != NULL ? hbac_ctx->sdap_ctx : NULL;
}

/* Get struct sdap_id_op associated with HBAC context */
static inline struct sdap_id_op *hbac_ctx_sdap_id_op(struct hbac_ctx *hbac_ctx)
{
    return hbac_ctx != NULL ? hbac_ctx->sdap_op : NULL;
}

/* Check whether the current HBAC request is processed in off-line mode */
static inline bool hbac_ctx_is_offline(struct hbac_ctx *ctx)
{
    return ctx == NULL || ctx->sdap_op == NULL;
}


void ipa_access_handler(struct be_req *be_req);

errno_t hbac_get_cached_rules(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              size_t *_rule_count,
                              struct sysdb_attrs ***_rules);

#endif /* _IPA_ACCESS_H_ */
