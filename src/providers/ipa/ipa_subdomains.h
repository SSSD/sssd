/*
    SSSD

    IPA Subdomains Module

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef _IPA_SUBDOMAINS_H_
#define _IPA_SUBDOMAINS_H_

#include "providers/dp_backend.h"
#include "providers/ipa/ipa_common.h"

struct be_ctx *ipa_get_subdomains_be_ctx(struct be_ctx *be_ctx);

const char *get_flat_name_from_subdomain_name(struct be_ctx *be_ctx,
                                              const char *name);

int ipa_subdom_init(struct be_ctx *be_ctx,
                    struct ipa_id_ctx *id_ctx,
                    struct bet_ops **ops,
                    void **pvt_data);

/* The following are used in server mode only */
struct ipa_ad_server_ctx {
    struct sss_domain_info *dom;
    struct ad_id_ctx *ad_id_ctx;

    struct ipa_ad_server_ctx *next, *prev;
};

struct ipa_server_mode_ctx {
    const char *realm;
    const char *hostname;

    struct ipa_ad_server_ctx *trusts;
};

int ipa_ad_subdom_init(struct be_ctx *be_ctx,
                       struct ipa_id_ctx *id_ctx);

enum req_input_type {
    REQ_INP_NAME,
    REQ_INP_ID,
    REQ_INP_SECID
};

struct req_input {
    enum req_input_type type;
    union {
        const char *name;
        uint32_t id;
        const char *secid;
    } inp;
};
#endif /* _IPA_SUBDOMAINS_H_ */
