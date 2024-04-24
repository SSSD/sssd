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

#include "providers/backend.h"
#include "providers/ipa/ipa_common.h"
#include "config.h"

#ifndef IPA_TRUST_KEYTAB_DIR
#define IPA_TRUST_KEYTAB_DIR         SSS_STATEDIR"/keytabs"
#endif /* IPA_TRUST_KEYTAB_DIR */

/* ==Sid2Name Extended Operation============================================= */
#define EXOP_SID2NAME_OID "2.16.840.1.113730.3.8.10.4"
#define EXOP_SID2NAME_V1_OID "2.16.840.1.113730.3.8.10.4.1"
#define EXOP_SID2NAME_V2_OID "2.16.840.1.113730.3.8.10.4.2"

enum extdom_protocol {
    EXTDOM_INVALID_VERSION = -1,
    EXTDOM_V0,
    EXTDOM_V1,
    EXTDOM_V2
};

struct ipa_subdomains_ctx {
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *ipa_id_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_search_base **search_bases;
    struct sdap_search_base **master_search_bases;
    struct sdap_search_base **ranges_search_bases;
    struct sdap_search_base **host_search_bases;

    time_t last_refreshed;
    bool view_read_at_init;
    /* List of krb5_service structures for each subdomain
     * in order to write the kdcinfo files. For use on
     * the client only
     */
    struct ipa_sd_k5_svc_list *k5svc_list;
};

errno_t ipa_subdomains_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            struct ipa_id_ctx *ipa_id_ctx,
                            struct dp_method *dp_methods);

/* The following are used in server mode only */
enum ipa_trust_type {
    IPA_TRUST_UNKNOWN = 0,
    IPA_TRUST_AD = 1,
    IPA_TRUST_IPA = 2,
};

struct ipa_subdom_server_ctx {
    struct sss_domain_info *dom;
    enum ipa_trust_type type;
    union {
        struct ad_id_ctx *ad_id_ctx;
        struct ipa_id_ctx *ipa_id_ctx;
    } id_ctx;

    struct ipa_subdom_server_ctx *next, *prev;
};

/* Can be used to set up trusted subdomain, for example fetch
 * keytab in server mode
 */
struct tevent_req *
ipa_server_trusted_dom_setup_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct ipa_id_ctx *id_ctx,
                                  struct sss_domain_info *subdom);
errno_t ipa_server_trusted_dom_setup_recv(struct tevent_req *req);

/* To be used by ipa_subdomains.c only */
struct tevent_req *
ipa_server_create_trusts_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct be_ctx *be_ctx,
                              struct ipa_id_ctx *id_ctx,
                              struct sss_domain_info *parent);

errno_t ipa_server_create_trusts_recv(struct tevent_req *req);

void ipa_ad_subdom_remove(struct be_ctx *be_ctx,
                          struct ipa_id_ctx *id_ctx,
                          struct sss_domain_info *subdom);

int ipa_ad_subdom_init(struct be_ctx *be_ctx,
                       struct ipa_id_ctx *id_ctx);

errno_t ipa_server_get_trust_direction(struct sysdb_attrs *sd,
                                       struct ldb_context *ldb_ctx,
                                       uint32_t *_direction);

errno_t ipa_server_get_trust_type(struct sysdb_attrs *sd,
                                  struct ldb_context *ldb_ctx,
                                  uint32_t *_type);

const char *ipa_trust_dir2str(uint32_t direction);
const char *ipa_trust_type2str(uint32_t type);

/* Utilities */
#define IPA_TRUST_DIRECTION "ipaNTTrustDirection"
#define IPA_PARTNER_TRUST_TYPE "ipaPartnerTrustType"

struct ldb_dn *ipa_subdom_ldb_dn(TALLOC_CTX *mem_ctx,
                                 struct ldb_context *ldb_ctx,
                                 struct sysdb_attrs *attrs);

bool ipa_subdom_is_member_dom(struct ldb_dn *dn);

/* struct for external group memberships, defined in
 * ipa_subdomains_ext_groups.c */
struct ipa_ext_groups;

struct ipa_server_mode_ctx {
    const char *realm;
    const char *hostname;

    struct ipa_subdom_server_ctx *trusts;
    struct ipa_ext_groups *ext_groups;

    uid_t kt_owner_uid;
    uid_t kt_owner_gid;
};

int ipa_ad_subdom_init(struct be_ctx *be_ctx,
                       struct ipa_id_ctx *id_ctx);

enum req_input_type {
    REQ_INP_NAME,
    REQ_INP_ID,
    REQ_INP_SECID,
    REQ_INP_CERT
};

struct req_input {
    enum req_input_type type;
    union {
        const char *name;
        uint32_t id;
        const char *secid;
        const char *cert;
    } inp;
};

struct tevent_req *ipa_get_ad_memberships_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct dp_id_data *ar,
                                        struct ipa_server_mode_ctx *server_mode,
                                        struct sss_domain_info *user_dom,
                                        struct sdap_id_ctx *sdap_id_ctx,
                                        const char *domain);

errno_t ipa_get_ad_memberships_recv(struct tevent_req *req, int *dp_error_out);

struct tevent_req *ipa_ext_group_member_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             const char *ext_member,
                                             void *pvt);
errno_t ipa_ext_group_member_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  enum sysdb_member_type *_member_type,
                                  struct sss_domain_info **_dom,
                                  struct sysdb_attrs **_member);

#endif /* _IPA_SUBDOMAINS_H_ */
