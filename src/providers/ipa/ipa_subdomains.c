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

#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_id.h"

#include <ctype.h>

#define SUBDOMAINS_FILTER "objectclass=ipaNTTrustedDomain"
#define MASTER_DOMAIN_FILTER "objectclass=ipaNTDomainAttrs"
#define RANGE_FILTER "objectclass=ipaIDRange"

#define IPA_CN "cn"
#define IPA_FLATNAME "ipaNTFlatName"
#define IPA_SID "ipaNTSecurityIdentifier"
#define IPA_TRUSTED_DOMAIN_SID "ipaNTTrustedDomainSID"
#define IPA_RANGE_TYPE "ipaRangeType"

#define IPA_BASE_ID "ipaBaseID"
#define IPA_ID_RANGE_SIZE "ipaIDRangeSize"
#define IPA_BASE_RID "ipaBaseRID"
#define IPA_SECONDARY_BASE_RID "ipaSecondaryBaseRID"
#define OBJECTCLASS "objectClass"

#define IPA_ASSIGNED_ID_VIEW "ipaAssignedIDView"

/* do not refresh more often than every 5 seconds for now */
#define IPA_SUBDOMAIN_REFRESH_LIMIT 5

#define IPA_SUBDOMAIN_DISABLED_PERIOD 3600

enum ipa_subdomains_req_type {
    IPA_SUBDOMAINS_MASTER,
    IPA_SUBDOMAINS_SLAVE,
    IPA_SUBDOMAINS_RANGES,

    IPA_SUBDOMAINS_MAX /* Counter */
};

struct ipa_subdomains_req_params {
    const char *filter;
    tevent_req_fn cb;
    const char *attrs[9];
};

struct ipa_subdomains_ctx {
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *id_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_search_base **search_bases;
    struct sdap_search_base **master_search_bases;
    struct sdap_search_base **ranges_search_bases;
    struct sdap_search_base **host_search_bases;

    time_t last_refreshed;
    struct tevent_timer *timer_event;
    bool configured_explicit;
    time_t disabled_until;
    bool view_read_at_init;
};

static void ipa_subdomains_done(struct ipa_subdomains_ctx *sd_ctx,
                                struct be_req *req, int dp_err,
                                int error, const char *errstr)
{
    sd_ctx->view_read_at_init = true;
    return be_req_terminate(req, dp_err, error, errstr);
}

struct be_ctx *ipa_get_subdomains_be_ctx(struct be_ctx *be_ctx)
{
    struct ipa_subdomains_ctx *subdom_ctx;

    subdom_ctx = talloc_get_type(be_ctx->bet_info[BET_SUBDOMAINS].pvt_bet_data,
                                 struct ipa_subdomains_ctx);
    if (subdom_ctx == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Subdomains are not configured.\n");
        return NULL;
    }

    return subdom_ctx->be_ctx;
}

static errno_t
ipa_subdom_reinit(struct ipa_subdomains_ctx *ctx)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Re-initializing domain %s\n", ctx->be_ctx->domain->name);

    ret = sss_write_krb5_conf_snippet(
                              dp_opt_get_string(ctx->id_ctx->ipa_options->basic,
                                                IPA_KRB5_CONFD_PATH));
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_write_krb5_conf_snippet failed.\n");
        /* Just continue */
    }

    ret = sysdb_master_domain_update(ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_master_domain_update failed.\n");
        return ret;
    }

    ret = sysdb_update_subdomains(ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_subdomains failed.\n");
        return ret;
    }

    ret = sss_write_domain_mappings(ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "sss_krb5_write_mappings failed.\n");
        /* Just continue */
    }

    return EOK;
}

static errno_t ipa_ranges_parse_results(TALLOC_CTX *mem_ctx,
                                        char *domain_name,
                                        size_t count,
                                        struct sysdb_attrs **reply,
                                        struct range_info ***_range_list)
{
    struct range_info **range_list = NULL;
    struct range_info *r;
    const char *value;
    size_t c;
    size_t d;
    int ret;
    enum idmap_error_code err;
    char *name1;
    char *name2;
    char *sid1;
    char *sid2;
    uint32_t rid1;
    uint32_t rid2;
    struct sss_idmap_range range1;
    struct sss_idmap_range range2;
    bool mapping1;
    bool mapping2;

    range_list = talloc_array(mem_ctx, struct range_info *, count + 1);
    if (range_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    for (c = 0; c < count; c++) {
        r = talloc_zero(range_list, struct range_info);
        if (r == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        r->name = talloc_strdup(r, value);
        if (r->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_TRUSTED_DOMAIN_SID, &value);
        if (ret == EOK) {
            r->trusted_dom_sid = talloc_strdup(r, value);
            if (r->trusted_dom_sid == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_BASE_ID,
                                       &r->base_id);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_ID_RANGE_SIZE,
                                       &r->id_range_size);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_BASE_RID,
                                       &r->base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_SECONDARY_BASE_RID,
                                       &r->secondary_base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_RANGE_TYPE, &value);
        if (ret == EOK) {
            r->range_type = talloc_strdup(r, value);
            if (r->range_type == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else if (ret == ENOENT) {
            /* Older IPA servers might not have the range_type attribute, but
             * only support local ranges and trusts with algorithmic mapping. */
            if (r->trusted_dom_sid == NULL) {
                r->range_type = talloc_strdup(r, IPA_RANGE_LOCAL);
            } else {
                r->range_type = talloc_strdup(r, IPA_RANGE_AD_TRUST);
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
        if (r->range_type == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = get_idmap_data_from_range(r, domain_name, &name1, &sid1, &rid1,
                                        &range1, &mapping1);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_idmap_data_from_range failed.\n");
            goto done;
        }
        for (d = 0; d < c; d++) {
            ret = get_idmap_data_from_range(range_list[d], domain_name, &name2,
                                            &sid2, &rid2, &range2, &mapping2);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "get_idmap_data_from_range failed.\n");
                goto done;
            }

            err = sss_idmap_check_collision_ex(name1, sid1, &range1, rid1,
                                               r->name, mapping1,
                                               name2, sid2, &range2, rid2,
                                               range_list[d]->name, mapping2);
            if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Collision of ranges [%s] and [%s] detected.\n",
                      r->name, range_list[d]->name);
                ret = EINVAL;
                goto done;
            }
        }

        range_list[c] = r;
    }

    range_list[c] = NULL;

    *_range_list = range_list;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(range_list);
    }

    return ret;
}

static errno_t ipa_subdom_enumerates(struct sss_domain_info *parent,
                                     struct sysdb_attrs *attrs,
                                     bool *_enumerates)
{
    errno_t ret;
    const char *name;

    ret = sysdb_attrs_get_string(attrs, IPA_CN, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        return ret;
    }

    *_enumerates = subdomain_enumerates(parent, name);
    return EOK;
}

static errno_t ipa_subdom_get_forest(TALLOC_CTX *mem_ctx,
                                     struct ldb_context *ldb_ctx,
                                     struct sysdb_attrs *attrs,
                                     char **_forest)
{
    int ret;
    struct ldb_dn *dn = NULL;
    const char *name;
    const struct ldb_val *val;
    char *forest = NULL;

    dn = ipa_subdom_ldb_dn(mem_ctx, ldb_ctx, attrs);
    if (dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_subdom_ldb_dn failed.\n");
        ret = EIO;
        goto done;
    }

    if (ipa_subdom_is_member_dom(dn) == false) {
        ret = sysdb_attrs_get_string(attrs, IPA_CN, &name);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        forest = talloc_strdup(mem_ctx, name);
        if (forest == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_INTERNAL, "The forest name is %s\n", forest);
        ret = EOK;
        goto done;
    }

    val = ldb_dn_get_component_val(dn, 1);
    forest = talloc_strndup(mem_ctx, (const char *) val->data, val->length);
    if (forest == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(dn);

    if (ret == EOK) {
        *_forest = forest;
    }

    return ret;
}

static errno_t ipa_get_sd_trust_direction(struct sysdb_attrs *sd,
                                          struct ipa_id_ctx *id_ctx,
                                          struct ldb_context *ldb_ctx,
                                          uint32_t *_direction)
{
    if (id_ctx->server_mode != NULL) {
        return ipa_server_get_trust_direction(sd, ldb_ctx, _direction);
    } else {
        /* Clients do not have access to the trust objects's trust direction
         * and don't generally care
         */
        *_direction = 0;
        return EOK;
    }
}

static errno_t ipa_subdom_store(struct sss_domain_info *parent,
                                struct ipa_id_ctx *id_ctx,
                                struct sdap_idmap_ctx *sdap_idmap_ctx,
                                struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    char *realm;
    const char *flat;
    const char *id;
    char *forest = NULL;
    int ret;
    bool mpg;
    bool enumerate;
    uint32_t direction;

    tmp_ctx = talloc_new(parent);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_attrs_get_string(attrs, IPA_CN, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }

    realm = get_uppercase_realm(tmp_ctx, name);
    if (!realm) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_string(attrs, IPA_FLATNAME, &flat);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }

    ret = sysdb_attrs_get_string(attrs, IPA_TRUSTED_DOMAIN_SID, &id);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }

    mpg = sdap_idmap_domain_has_algorithmic_mapping(sdap_idmap_ctx, name, id);

    ret = ipa_subdom_get_forest(tmp_ctx, sysdb_ctx_get_ldb(parent->sysdb),
                                attrs, &forest);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_subdom_enumerates(parent, attrs, &enumerate);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_get_sd_trust_direction(attrs, id_ctx,
                                     sysdb_ctx_get_ldb(parent->sysdb),
                                     &direction);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa_get_sd_trust_direction failed: %d\n", ret);
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Trust direction of %s is %s\n", name, ipa_trust_dir2str(direction));
    ret = sysdb_subdomain_store(parent->sysdb, name, realm, flat,
                                id, mpg, enumerate, forest,
                                direction);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_subdomain_store failed.\n");
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static void ipa_subdom_store_step(struct sss_domain_info *parent,
                                  struct ipa_id_ctx *id_ctx,
                                  struct sdap_idmap_ctx *sdap_idmap_ctx,
                                  struct sysdb_attrs *attrs)
{
    int ret;

    ret = ipa_subdom_store(parent, id_ctx, sdap_idmap_ctx, attrs);
    if (ret == ERR_TRUST_NOT_SUPPORTED) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unsupported trust type, skipping\n");
    } else if (ret) {
        /* Nothing we can do about the error. */
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to parse subdom data, "
              "will try to use cached subdomain\n");
    }
}

static errno_t ipa_subdomains_refresh(struct ipa_subdomains_ctx *ctx,
                                      int count, struct sysdb_attrs **reply,
                                      bool *changes)
{
    struct sss_domain_info *parent, *dom;
    bool handled[count];
    const char *value;
    int c, h;
    int ret;

    parent = ctx->be_ctx->domain;
    memset(handled, 0, sizeof(bool) * count);
    h = 0;

    /* check existing subdomains */
    for (dom = get_next_domain(parent, SSS_GND_DESCEND);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, 0)) {
        for (c = 0; c < count; c++) {
            if (handled[c]) {
                continue;
            }
            ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
                goto done;
            }
            if (strcmp(value, dom->name) == 0) {
                break;
            }
        }

        if (c >= count) {
            /* ok this subdomain does not exist anymore, let's clean up */
            sss_domain_set_state(dom, DOM_DISABLED);
            ret = sysdb_subdomain_delete(dom->sysdb, dom->name);
            if (ret != EOK) {
                goto done;
            }

            /* Remove the AD ID ctx from the list of LDAP domains */
            ipa_ad_subdom_remove(ctx->be_ctx, ctx->id_ctx, dom);
        } else {
            /* ok let's try to update it */
            ipa_subdom_store_step(parent, ctx->id_ctx,
                                  ctx->sdap_id_ctx->opts->idmap_ctx,
                                  reply[c]);
            handled[c] = true;
            h++;
        }
    }

    if (count == h) {
        /* all domains were already accounted for and have been updated */
        ret = EOK;
        goto done;
    }

    /* if we get here it means we have changes to the subdomains list */
    *changes = true;

    for (c = 0; c < count; c++) {
        if (handled[c]) {
            continue;
        }

        ipa_subdom_store_step(parent, ctx->id_ctx,
                              ctx->sdap_id_ctx->opts->idmap_ctx,
                              reply[c]);
    }

    ret = EOK;
done:
    if (ret != EOK) {
        ctx->last_refreshed = 0;
    } else {
        ctx->last_refreshed = time(NULL);
    }

    return ret;
}

struct ipa_subdomains_req_ctx {
    struct be_req *be_req;
    struct ipa_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;

    char *current_filter;

    struct sdap_search_base **search_bases;
    int search_base_iter;

    size_t reply_count;
    struct sysdb_attrs **reply;
};

static void ipa_subdomains_get_conn_done(struct tevent_req *req);
static errno_t
ipa_subdomains_handler_get_start(struct ipa_subdomains_req_ctx *ctx,
                                 struct sdap_search_base **search_bases,
                                 enum ipa_subdomains_req_type type);
static errno_t
ipa_subdomains_handler_get_cont(struct ipa_subdomains_req_ctx *ctx,
                                enum ipa_subdomains_req_type type);
static void ipa_subdomains_handler_done(struct tevent_req *req);
static void ipa_subdomains_handler_master_done(struct tevent_req *req);
static void ipa_subdomains_handler_ranges_done(struct tevent_req *req);

static struct ipa_subdomains_req_params subdomain_requests[] = {
    { MASTER_DOMAIN_FILTER,
      ipa_subdomains_handler_master_done,
      { IPA_CN, IPA_FLATNAME, IPA_SID, NULL }
    },
    { SUBDOMAINS_FILTER,
      ipa_subdomains_handler_done,
      { IPA_CN, IPA_FLATNAME, IPA_TRUSTED_DOMAIN_SID,
        IPA_TRUST_DIRECTION, NULL }
    },
    { RANGE_FILTER,
      ipa_subdomains_handler_ranges_done,
      { OBJECTCLASS, IPA_CN,
        IPA_BASE_ID, IPA_BASE_RID, IPA_SECONDARY_BASE_RID,
        IPA_ID_RANGE_SIZE, IPA_TRUSTED_DOMAIN_SID, IPA_RANGE_TYPE, NULL
      }
    }
};

static void ipa_subdomains_retrieve(struct ipa_subdomains_ctx *ctx, struct be_req *be_req)
{
    struct ipa_subdomains_req_ctx *req_ctx = NULL;
    struct tevent_req *req;
    int dp_error = DP_ERR_FATAL;
    int ret;

    req_ctx = talloc(be_req, struct ipa_subdomains_req_ctx);
    if (req_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    req_ctx->be_req = be_req;
    req_ctx->sd_ctx = ctx;
    req_ctx->search_base_iter = 0;
    req_ctx->search_bases = ctx->ranges_search_bases;
    req_ctx->current_filter = NULL;
    req_ctx->reply_count = 0;
    req_ctx->reply = NULL;

    req_ctx->sdap_op = sdap_id_op_create(req_ctx,
                                         ctx->sdap_id_ctx->conn->conn_cache);
    if (req_ctx->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        ret = ENOMEM;
        goto done;
    }

    req = sdap_id_op_connect_send(req_ctx->sdap_op, req_ctx, &ret);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
        goto done;
    }

    tevent_req_set_callback(req, ipa_subdomains_get_conn_done, req_ctx);

    return;

done:
    talloc_free(req_ctx);
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    ipa_subdomains_done(ctx, be_req, dp_error, ret, NULL);
}

static void ipa_subdomains_get_conn_done(struct tevent_req *req)
{
    int ret;
    int dp_error = DP_ERR_FATAL;
    struct ipa_subdomains_req_ctx *ctx;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);

    ret = sdap_id_op_connect_recv(req, &dp_error);
    talloc_zfree(req);
    if (ret) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No IPA server is available, cannot get the "
                   "subdomain list while offline\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to IPA server: [%d](%s)\n",
                   ret, strerror(ret));
        }

        goto fail;
    }

    ret = ipa_subdomains_handler_get_start(ctx,
                                           ctx->sd_ctx->ranges_search_bases,
                                           IPA_SUBDOMAINS_RANGES);
    if (ret != EOK && ret != EAGAIN) {
        goto fail;
    }

    return;

fail:
    ipa_subdomains_done(ctx->sd_ctx, ctx->be_req, dp_error, ret, NULL);
}

static errno_t
ipa_subdomains_handler_get(struct ipa_subdomains_req_ctx *ctx,
                           enum ipa_subdomains_req_type type)
{
    struct tevent_req *req;
    struct sdap_search_base *base;
    struct ipa_subdomains_req_params *params;

    if (type >= IPA_SUBDOMAINS_MAX) {
        return EINVAL;
    }

    params = &subdomain_requests[type];

    base = ctx->search_bases[ctx->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    talloc_free(ctx->current_filter);
    ctx->current_filter = sdap_get_id_specific_filter(ctx, params->filter,
                                                            base->filter);
    if (ctx->current_filter == NULL) {
        return ENOMEM;
    }

    req = sdap_get_generic_send(ctx, ctx->sd_ctx->be_ctx->ev,
                        ctx->sd_ctx->sdap_id_ctx->opts,
                        sdap_id_op_handle(ctx->sdap_op),
                        base->basedn, base->scope,
                        ctx->current_filter, params->attrs, NULL, 0,
                        dp_opt_get_int(ctx->sd_ctx->sdap_id_ctx->opts->basic,
                                       SDAP_SEARCH_TIMEOUT), false);

    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, params->cb, ctx);

    return EAGAIN;
}

static errno_t
ipa_subdomains_handler_get_start(struct ipa_subdomains_req_ctx *ctx,
                                 struct sdap_search_base **search_bases,
                                 enum ipa_subdomains_req_type type)
{
    ctx->search_base_iter = 0;
    ctx->search_bases = search_bases;
    return ipa_subdomains_handler_get(ctx, type);
}

static errno_t
ipa_subdomains_handler_get_cont(struct ipa_subdomains_req_ctx *ctx,
                                enum ipa_subdomains_req_type type)
{
    ctx->search_base_iter++;
    return ipa_subdomains_handler_get(ctx, type);
}

static void ipa_get_view_name_done(struct tevent_req *req);
static void ipa_server_create_trusts_done(struct tevent_req *trust_req);
static errno_t ipa_check_master(struct ipa_subdomains_req_ctx *ctx);

static errno_t ipa_get_view_name(struct ipa_subdomains_req_ctx *ctx)
{
    struct tevent_req *req;
    struct sdap_search_base *base;
    const char *attrs[] = {IPA_CN, OBJECTCLASS, NULL};
    struct sdap_attr_map_info *maps;

    maps = talloc_zero(ctx, struct sdap_attr_map_info);
    if (maps == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }
    maps->map = ctx->sd_ctx->id_ctx->ipa_options->view_map;
    maps->num_attrs = IPA_OPTS_VIEW;

    base = ctx->search_bases[ctx->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    req = sdap_deref_search_with_filter_send(ctx, ctx->sd_ctx->be_ctx->ev,
                        ctx->sd_ctx->sdap_id_ctx->opts,
                        sdap_id_op_handle(ctx->sdap_op),
                        base->basedn,
                        ctx->current_filter, IPA_ASSIGNED_ID_VIEW, attrs,
                        1, maps,
                        dp_opt_get_int(ctx->sd_ctx->sdap_id_ctx->opts->basic,
                                       SDAP_SEARCH_TIMEOUT));

    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, ipa_get_view_name_done, ctx);

    return EAGAIN;
}

static void ipa_get_view_name_done(struct tevent_req *req)
{
    int ret;
    int sret;
    struct ipa_subdomains_req_ctx *ctx;
    size_t reply_count;
    struct sdap_deref_attrs **reply = NULL;
    const char *view_name;
    int dp_error = DP_ERR_FATAL;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);

    ret = sdap_deref_search_with_filter_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        /* Depending on the version 389ds return a different error code if the
         * search for the view name failed because our dereference attribute
         * ipaAssignedIDView is not known. Newer version return
         * LDAP_UNAVAILABLE_CRITICAL_EXTENSION(12) which is translated to
         * EOPNOTSUPP and older versions return LDAP_PROTOCOL_ERROR(2) which
         * is returned as EIO. In both cases we have to assume that the server
         * is not view aware and keep the view name unset. */
        if (ret == EOPNOTSUPP || ret == EIO) {
            DEBUG(SSSDBG_TRACE_FUNC, "get_view_name request failed, looks " \
                                     "like server does not support views.\n");
            ret = ipa_check_master(ctx);
            if (ret == EAGAIN) {
                return;
            } else if (ret != EOK) {
                goto done;
            }

        } else {
            DEBUG(SSSDBG_OP_FAILURE, "get_view_name request failed.\n");
        }
        goto done;
    }

    if (reply_count == 0) {
        ctx->search_base_iter++;
        ret = ipa_get_view_name(ctx);
        if (ret == EAGAIN) {
            return;
        } else if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, "No view found, using default.\n");
            view_name = SYSDB_DEFAULT_VIEW_NAME;
        } else {
            goto done;
        }
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "get_view_name request returned more than one object.\n");
        ret = EINVAL;
        goto done;
    } else {
        ret = sysdb_attrs_get_string(reply[0]->attrs, SYSDB_VIEW_NAME,
                                     &view_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Found view name [%s].\n", view_name);
    if (is_default_view(view_name)) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Found IPA default view name, replacing with sysdb default.\n");
        view_name = SYSDB_DEFAULT_VIEW_NAME;
    }

    DEBUG(SSSDBG_TRACE_ALL, "read_at_init [%s] current view  [%s].\n",
                             ctx->sd_ctx->view_read_at_init ? "true" : "false",
                             ctx->sd_ctx->id_ctx->view_name);

    if (ctx->sd_ctx->id_ctx->view_name != NULL
            && strcmp(ctx->sd_ctx->id_ctx->view_name, view_name) != 0
            && ctx->sd_ctx->view_read_at_init) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "View name changed, this is not supported at runtime. " \
              "Please restart SSSD to get the new view applied.\n");
    } else {
        if (ctx->sd_ctx->id_ctx->view_name == NULL
            || strcmp(ctx->sd_ctx->id_ctx->view_name, view_name) != 0) {
            /* View name changed */

            if (ctx->sd_ctx->id_ctx->view_name != NULL) {
                ret = sysdb_transaction_start(
                                            ctx->sd_ctx->be_ctx->domain->sysdb);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_transaction_start failed.\n");
                    goto done;
                }

                if (!is_default_view(ctx->sd_ctx->id_ctx->view_name)
                        && !is_local_view(ctx->sd_ctx->id_ctx->view_name)) {
                    /* Old view was not the default view, delete view tree */
                    ret = sysdb_delete_view_tree(
                                             ctx->sd_ctx->be_ctx->domain->sysdb,
                                             ctx->sd_ctx->id_ctx->view_name);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "sysdb_delete_view_tree failed.\n");
                        sret = sysdb_transaction_cancel(
                                            ctx->sd_ctx->be_ctx->domain->sysdb);
                        if (sret != EOK) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "sysdb_transaction_cancel failed.\n");
                            goto done;
                        }
                        goto done;
                    }
                }

                ret = sysdb_invalidate_overrides(
                                            ctx->sd_ctx->be_ctx->domain->sysdb);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_invalidate_overrides failed.\n");
                    sret = sysdb_transaction_cancel(
                                            ctx->sd_ctx->be_ctx->domain->sysdb);
                    if (sret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "sysdb_transaction_cancel failed.\n");
                        goto done;
                    }
                    goto done;
                }

                ret = sysdb_transaction_commit(
                                            ctx->sd_ctx->be_ctx->domain->sysdb);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                                          "sysdb_transaction_commit failed.\n");
                    goto done;
                }

                /* TODO: start referesh task */
            }

            ret = sysdb_update_view_name(ctx->sd_ctx->be_ctx->domain->sysdb,
                                         view_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Cannot add/update view name to sysdb.\n");
            } else {
                talloc_free(ctx->sd_ctx->id_ctx->view_name);
                ctx->sd_ctx->id_ctx->view_name = talloc_strdup(
                                                            ctx->sd_ctx->id_ctx,
                                                            view_name);
                if (ctx->sd_ctx->id_ctx->view_name == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Cannot copy view name.\n");
                }
            }
        }

        if (!ctx->sd_ctx->view_read_at_init) {
            /* refresh view data of all domains at startup */
            ret = sysdb_master_domain_update(ctx->sd_ctx->be_ctx->domain);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_master_domain_update failed.\n");
                goto done;
            }

            ret = sysdb_update_subdomains(ctx->sd_ctx->be_ctx->domain);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_subdomains failed.\n");
                goto done;
            }
        }

        ctx->sd_ctx->view_read_at_init = true;

    }

    ret = EOK;
done:
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    ipa_subdomains_done(ctx->sd_ctx, ctx->be_req, dp_error, ret, NULL);
}

static void ipa_subdomains_handler_done(struct tevent_req *req)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ipa_subdomains_req_ctx *ctx;
    struct sss_domain_info *domain;
    bool refresh_has_changes = false;
    int dp_error = DP_ERR_FATAL;
    struct tevent_req *trust_req;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);
    domain = ctx->sd_ctx->be_ctx->domain;

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send request failed.\n");
        goto done;
    }

    if (reply_count) {
        ctx->reply = talloc_realloc(ctx, ctx->reply, struct sysdb_attrs *,
                                    ctx->reply_count + reply_count);
        if (ctx->reply == NULL) {
            ret = ENOMEM;
            goto done;
        }
        memcpy(ctx->reply+ctx->reply_count, reply,
               reply_count * sizeof(struct sysdb_attrs *));
        ctx->reply_count += reply_count;
    }

    ret = ipa_subdomains_handler_get_cont(ctx, IPA_SUBDOMAINS_SLAVE);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

    ret = ipa_subdomains_refresh(ctx->sd_ctx, ctx->reply_count, ctx->reply,
                                 &refresh_has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to refresh subdomains.\n");
        goto done;
    }

    if (refresh_has_changes) {
        ret = ipa_subdom_reinit(ctx->sd_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not reinitialize subdomains\n");
            goto done;
        }

        if (ctx->sd_ctx->id_ctx->server_mode != NULL) {
            trust_req = ipa_server_create_trusts_send(ctx, ctx->sd_ctx->be_ctx->ev,
                                                      ctx->sd_ctx->be_ctx,
                                                      ctx->sd_ctx->id_ctx,
                                                      domain);
            if (trust_req == NULL) {
                ret = ENOMEM;
                goto done;
            }
            tevent_req_set_callback(trust_req, ipa_server_create_trusts_done, ctx);
            return;
        }
    }

    ctx->search_base_iter = 0;
    ctx->search_bases = ctx->sd_ctx->host_search_bases;
    talloc_zfree(ctx->current_filter);
    ctx->current_filter = talloc_asprintf(ctx, "(&(objectClass=%s)(%s=%s))",
              ctx->sd_ctx->id_ctx->ipa_options->host_map[IPA_OC_HOST].name,
              ctx->sd_ctx->id_ctx->ipa_options->host_map[IPA_AT_HOST_FQDN].name,
              dp_opt_get_string(ctx->sd_ctx->id_ctx->ipa_options->basic,
                                IPA_HOSTNAME));
    if (ctx->current_filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (ctx->sd_ctx->id_ctx->server_mode == NULL) {
        /* Only get view on clients, on servers it is always 'default' */
        ret = ipa_get_view_name(ctx);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;
done:
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    ipa_subdomains_done(ctx->sd_ctx, ctx->be_req, dp_error, ret, NULL);
}

static void ipa_server_create_trusts_done(struct tevent_req *trust_req)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    struct ipa_subdomains_req_ctx *ctx;

    ctx = tevent_req_callback_data(trust_req, struct ipa_subdomains_req_ctx);

    ret = ipa_server_create_trusts_recv(trust_req);
    talloc_zfree(trust_req);
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }

    ipa_subdomains_done(ctx->sd_ctx, ctx->be_req, dp_error, ret, NULL);
}

static errno_t ipa_check_master(struct ipa_subdomains_req_ctx *ctx)
{
    int ret;
    struct sss_domain_info *domain;

    domain = ctx->sd_ctx->be_ctx->domain;

    ret = sysdb_master_domain_update(domain);
    if (ret != EOK) {
        return ret;
    }

    if (domain->flat_name == NULL ||
        domain->domain_id == NULL ||
        domain->realm == NULL) {

        ret = ipa_subdomains_handler_get_start(ctx,
                                               ctx->sd_ctx->master_search_bases,
                                               IPA_SUBDOMAINS_MASTER);
        if (ret == EAGAIN) {
            return EAGAIN;
        } else if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}


static void ipa_subdomains_handler_ranges_done(struct tevent_req *req)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ipa_subdomains_req_ctx *ctx;
    struct range_info **range_list = NULL;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);
    domain = ctx->sd_ctx->be_ctx->domain;
    sysdb = domain->sysdb;

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send request failed.\n");
        goto done;
    }

    ret = ipa_ranges_parse_results(ctx, domain->name,
                                   reply_count, reply, &range_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa_ranges_parse_results request failed.\n");
        goto done;
    }

    ret = sysdb_update_ranges(sysdb, range_list);
    talloc_free(range_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_ranges failed.\n");
        goto done;
    }

    ret = ipa_check_master(ctx);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_ALL, "Checking master record..\n");
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_check_master failed.\n");
        goto done;
    }
    /* Master domain is up-to-date. Continue checking subdomains */

    DEBUG(SSSDBG_TRACE_ALL, "Master record up2date, checking subdomains\n");
    ret = ipa_subdomains_handler_get_start(ctx, ctx->sd_ctx->search_bases,
                                           IPA_SUBDOMAINS_SLAVE);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_OP_FAILURE, "No search base for ranges available.\n");
    ret = EINVAL;

done:
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    ipa_subdomains_done(ctx->sd_ctx, ctx->be_req, dp_error, ret, NULL);
}

static void ipa_subdomains_handler_master_done(struct tevent_req *req)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    size_t reply_count = 0;
    struct sysdb_attrs **reply = NULL;
    struct ipa_subdomains_req_ctx *ctx;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send request failed.\n");
        goto done;
    }

    if (reply_count) {
        const char *flat = NULL;
        const char *id = NULL;
        const char *realm;

        ret = sysdb_attrs_get_string(reply[0], IPA_FLATNAME, &flat);
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[0], IPA_SID, &id);
        if (ret != EOK) {
            goto done;
        }

        realm = dp_opt_get_string(ctx->sd_ctx->id_ctx->ipa_options->basic,
                                  IPA_KRB5_REALM);
        if (realm == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "No Kerberos realm for IPA?\n");
            ret = EINVAL;
            goto done;
        }

        ret = sysdb_master_domain_add_info(ctx->sd_ctx->be_ctx->domain,
                                           realm, flat, id, NULL);
        if (ret != EOK) {
            goto done;
        }

        /* There is only one master record. Don't bother checking other IPA
         * search bases; move to checking subdomains instead
         */
        ret = ipa_subdomains_handler_get_start(ctx,
                                               ctx->sd_ctx->search_bases,
                                               IPA_SUBDOMAINS_SLAVE);
        if (ret == EAGAIN) {
            return;
        }

        /* Either no search bases or an error. End the request in both cases */
    } else {
        ret = ipa_subdomains_handler_get_cont(ctx, IPA_SUBDOMAINS_MASTER);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            goto done;
        }

        /* Right now we know there has been an error
         * and we don't have the master domain record
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Master domain record not found!\n");

        if (!ctx->sd_ctx->configured_explicit) {
            ctx->sd_ctx->disabled_until = time(NULL) +
                                          IPA_SUBDOMAIN_DISABLED_PERIOD;
        }

        ret = EIO;
    }

done:
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    ipa_subdomains_done(ctx->sd_ctx, ctx->be_req, dp_error, ret, NULL);
}

static void ipa_subdom_online_cb(void *pvt);

static void ipa_subdom_timer_refresh(struct tevent_context *ev,
                                     struct tevent_timer *te,
                                     struct timeval current_time,
                                     void *pvt)
{
    ipa_subdom_online_cb(pvt);
}

static void ipa_subdom_be_req_callback(struct be_req *be_req,
                                       int dp_err, int dp_ret,
                                       const char *errstr)
{
    talloc_free(be_req);
}

static void ipa_subdom_reset_timeouts_cb(void *pvt)
{
    struct ipa_subdomains_ctx *ctx;

    ctx = talloc_get_type(pvt, struct ipa_subdomains_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bad private pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Resetting last_refreshed and disabled_until.\n");
    ctx->last_refreshed = 0;
    ctx->disabled_until = 0;
}

static void ipa_subdom_online_cb(void *pvt)
{
    struct ipa_subdomains_ctx *ctx;
    struct be_req *be_req;
    struct timeval tv;
    uint32_t refresh_interval;

    ctx = talloc_get_type(pvt, struct ipa_subdomains_ctx);
    if (!ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bad private pointer\n");
        return;
    }

    ctx->disabled_until = 0;

    refresh_interval = ctx->be_ctx->domain->subdomain_refresh_interval;

    be_req = be_req_create(ctx, NULL, ctx->be_ctx,
                           ipa_subdom_be_req_callback, NULL);
    if (be_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_req_create() failed.\n");
        return;
    }

    ipa_subdomains_retrieve(ctx, be_req);

    tv = tevent_timeval_current_ofs(refresh_interval, 0);
    ctx->timer_event = tevent_add_timer(ctx->be_ctx->ev, ctx, tv,
                                        ipa_subdom_timer_refresh, ctx);
    if (!ctx->timer_event) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add subdom timer event\n");
    }
}

static void ipa_subdom_offline_cb(void *pvt)
{
    struct ipa_subdomains_ctx *ctx;

    ctx = talloc_get_type(pvt, struct ipa_subdomains_ctx);

    if (ctx) {
        talloc_zfree(ctx->timer_event);
    }
}

static errno_t get_config_status(struct be_ctx *be_ctx,
                                 bool *configured_explicit)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    char *tmp_str;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = confdb_get_string(be_ctx->cdb, tmp_ctx, be_ctx->conf_path,
                            CONFDB_DOMAIN_SUBDOMAINS_PROVIDER, NULL,
                            &tmp_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "confdb_get_string failed.\n");
        goto done;
    }

    if (tmp_str == NULL) {
        *configured_explicit = false;
    } else {
        *configured_explicit = true;
    }

    DEBUG(SSSDBG_TRACE_ALL, "IPA subdomain provider is configured %s.\n",
                             *configured_explicit ? "explicit" : "implicit");

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

void ipa_subdomains_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct ipa_subdomains_ctx *ctx;
    time_t now;

    ctx = talloc_get_type(be_ctx->bet_info[BET_SUBDOMAINS].pvt_bet_data,
                          struct ipa_subdomains_ctx);
    if (!ctx) {
        be_req_terminate(be_req, DP_ERR_FATAL, EINVAL, NULL);
        return;
    }

    now = time(NULL);

    if (ctx->disabled_until > now) {
        DEBUG(SSSDBG_TRACE_ALL, "Subdomain provider disabled.\n");
        ipa_subdomains_done(ctx, be_req, DP_ERR_OK, EOK, NULL);
        return;
    }

    if (ctx->last_refreshed > now - IPA_SUBDOMAIN_REFRESH_LIMIT) {
        ipa_subdomains_done(ctx, be_req, DP_ERR_OK, EOK, NULL);
        return;
    }

    ipa_subdomains_retrieve(ctx, be_req);
}

struct bet_ops ipa_subdomains_ops = {
    .handler = ipa_subdomains_handler,
    .finalize = NULL
};

int ipa_subdom_init(struct be_ctx *be_ctx,
                    struct ipa_id_ctx *id_ctx,
                    struct bet_ops **ops,
                    void **pvt_data)
{
    struct ipa_subdomains_ctx *ctx;
    int ret;
    bool configured_explicit = false;

    ret = get_config_status(be_ctx, &configured_explicit);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_config_status failed.\n");
        return ret;
    }

    ctx = talloc_zero(id_ctx, struct ipa_subdomains_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ctx->be_ctx = be_ctx;
    ctx->id_ctx = id_ctx;
    ctx->sdap_id_ctx = id_ctx->sdap_id_ctx;
    ctx->search_bases = id_ctx->ipa_options->subdomains_search_bases;
    ctx->master_search_bases = id_ctx->ipa_options->master_domain_search_bases;
    ctx->ranges_search_bases = id_ctx->ipa_options->ranges_search_bases;
    ctx->host_search_bases = id_ctx->ipa_options->host_search_bases;
    ctx->configured_explicit = configured_explicit;
    ctx->disabled_until = 0;
    *ops = &ipa_subdomains_ops;
    *pvt_data = ctx;

    ret = be_add_unconditional_online_cb(ctx, be_ctx,
                                         ipa_subdom_reset_timeouts_cb, ctx,
                                         NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to add subdom reset timeouts callback\n");
    }

    ret = be_add_online_cb(ctx, be_ctx, ipa_subdom_online_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add subdom online callback\n");
    }

    ret = be_add_offline_cb(ctx, be_ctx, ipa_subdom_offline_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add subdom offline callback\n");
    }

    ret = ipa_subdom_reinit(ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not load the list of subdomains. "
              "Users from trusted domains might not be resolved correctly\n");
    }

    ret = ipa_ad_subdom_init(be_ctx, id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ipa_ad_subdom_init failed.\n");
        return ret;
    }

    return EOK;
}
