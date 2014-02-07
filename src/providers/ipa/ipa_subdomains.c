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

    time_t last_refreshed;
    struct tevent_timer *timer_event;
    bool configured_explicit;
    time_t disabled_until;
};

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
ipa_ad_ctx_new(struct be_ctx *be_ctx,
               struct ipa_id_ctx *id_ctx,
               struct sss_domain_info *subdom,
               struct ad_id_ctx **_ad_id_ctx)
{
    struct ad_options *ad_options;
    struct ad_id_ctx *ad_id_ctx;
    const char *gc_service_name;
    struct ad_srv_plugin_ctx *srv_ctx;
    char *ad_domain;
    struct sdap_domain *sdom;
    errno_t ret;

    ad_options = ad_create_default_options(id_ctx, id_ctx->server_mode->realm,
                                           id_ctx->server_mode->hostname);
    if (ad_options == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD options\n");
        talloc_free(ad_options);
        return ENOMEM;
    }

    ad_domain = subdom->name;

    ret = dp_opt_set_string(ad_options->basic, AD_DOMAIN, ad_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set AD domain\n");
        talloc_free(ad_options);
        return ret;
    }

    ret = dp_opt_set_string(ad_options->basic, AD_KRB5_REALM,
                            id_ctx->server_mode->realm);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set AD realm\n");
        talloc_free(ad_options);
        return ret;
    }

    gc_service_name = talloc_asprintf(ad_options, "%s%s", "gc_", subdom->name);
    if (gc_service_name == NULL) {
        talloc_free(ad_options);
        return ENOMEM;
    }

    /* Set KRB5 realm to same as the one of IPA when IPA
     * is able to attach PAC. For testing, use hardcoded. */
    ret = ad_failover_init(ad_options, be_ctx, NULL, NULL,
                           id_ctx->server_mode->realm,
                           subdom->name, gc_service_name,
                           subdom->name, &ad_options->service);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD failover\n");
        talloc_free(ad_options);
        return ret;
    }

    ad_id_ctx = ad_id_ctx_init(ad_options, be_ctx);
    if (ad_id_ctx == NULL) {
        talloc_free(ad_options);
        return ENOMEM;
    }
    ad_id_ctx->sdap_id_ctx->opts = ad_options->id;
    ad_options->id_ctx = ad_id_ctx;

    /* use AD plugin */
    srv_ctx = ad_srv_plugin_ctx_init(be_ctx, be_ctx->be_res,
                                     default_host_dbs,
                                     ad_id_ctx->ad_options->id,
                                     id_ctx->server_mode->hostname,
                                     ad_domain);
    if (srv_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
        return ENOMEM;
    }
    be_fo_set_srv_lookup_plugin(be_ctx, ad_srv_plugin_send,
                                ad_srv_plugin_recv, srv_ctx, "AD");

    ret = sdap_domain_subdom_add(ad_id_ctx->sdap_id_ctx,
                                 ad_id_ctx->sdap_id_ctx->opts->sdom,
                                 subdom->parent);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize sdap domain\n");
        talloc_free(ad_options);
        return ret;
    }

    sdom = sdap_domain_get(ad_id_ctx->sdap_id_ctx->opts, subdom);
    if (sdom == NULL) {
        return EFAULT;
    }

    ret = sdap_id_setup_tasks(be_ctx,
                              ad_id_ctx->sdap_id_ctx,
                              sdom,
                              ldap_enumeration_send,
                              ldap_enumeration_recv,
                              ad_id_ctx->sdap_id_ctx);
    if (ret != EOK) {
        talloc_free(ad_options);
        return ret;
    }

    sdom->pvt = ad_id_ctx;

    /* Set up the ID mapping object */
    ad_id_ctx->sdap_id_ctx->opts->idmap_ctx =
        id_ctx->sdap_id_ctx->opts->idmap_ctx;

    *_ad_id_ctx = ad_id_ctx;
    return EOK;
}

static errno_t
ipa_server_trust_add(struct be_ctx *be_ctx,
                     struct ipa_id_ctx *id_ctx,
                     struct sss_domain_info *subdom)
{
    struct ipa_ad_server_ctx *trust_ctx;
    struct ad_id_ctx *ad_id_ctx;
    errno_t ret;

    ret = ipa_ad_ctx_new(be_ctx, id_ctx, subdom, &ad_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot create ad_id_ctx for subdomain %s\n", subdom->name);
        return ret;
    }

    trust_ctx = talloc(id_ctx->server_mode, struct ipa_ad_server_ctx);
    if (trust_ctx == NULL) {
        return ENOMEM;
    }
    trust_ctx->dom = subdom;
    trust_ctx->ad_id_ctx = ad_id_ctx;

    DLIST_ADD(id_ctx->server_mode->trusts, trust_ctx);
    return EOK;
}

static errno_t
ipa_ad_subdom_refresh(struct be_ctx *be_ctx,
                      struct ipa_id_ctx *id_ctx,
                      struct sss_domain_info *parent)
{
    struct sss_domain_info *dom;
    struct ipa_ad_server_ctx *trust_iter;
    errno_t ret;

    if (dp_opt_get_bool(id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        return EOK;
    }

    for (dom = get_next_domain(parent, true);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, false)) {

        /* Check if we already have an ID context for this subdomain */
        DLIST_FOR_EACH(trust_iter, id_ctx->server_mode->trusts) {
            if (trust_iter->dom == dom) {
                break;
            }
        }

        /* Newly detected trust */
        if (trust_iter == NULL) {
            ret = ipa_server_trust_add(be_ctx, id_ctx, dom);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot create ad_id_ctx for subdomain %s\n",
                       dom->name);
                continue;
            }
        }
    }

    return EOK;
}

static errno_t
ipa_subdom_reinit(struct ipa_subdomains_ctx *ctx)
{
    errno_t ret;

    ret = sysdb_update_subdomains(ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_subdomains failed.\n");
        return ret;
    }

    ret = sss_write_domain_mappings(ctx->be_ctx->domain,
                    dp_opt_get_bool(ctx->id_ctx->ipa_options->basic,
                    IPA_SERVER_MODE));
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "sss_krb5_write_mappings failed.\n");
        /* Just continue */
    }

    return EOK;
}

static void
ipa_ad_subdom_remove(struct ipa_subdomains_ctx *ctx,
                     struct sss_domain_info *subdom)
{
    struct ipa_ad_server_ctx *iter;
    struct sdap_domain *sdom;

    if (dp_opt_get_bool(ctx->id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        return;
    }

    DLIST_FOR_EACH(iter, ctx->id_ctx->server_mode->trusts) {
        if (iter->dom == subdom) break;
    }

    if (iter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No IPA-AD context for subdomain %s\n",
              subdom->name);
        return;
    }

    sdom = sdap_domain_get(iter->ad_id_ctx->sdap_id_ctx->opts, subdom);
    if (sdom == NULL) return;
    be_ptask_destroy(&sdom->enum_task);
    be_ptask_destroy(&sdom->cleanup_task);

    sdap_domain_remove(iter->ad_id_ctx->sdap_id_ctx->opts, subdom);
    DLIST_REMOVE(ctx->id_ctx->server_mode->trusts, iter);

    /* terminate all requests for this subdomain so we can free it */
    be_terminate_domain_requests(ctx->be_ctx, subdom->name);
    talloc_zfree(sdom);
}

const char *get_flat_name_from_subdomain_name(struct be_ctx *be_ctx,
                                              const char *name)
{
    struct ipa_subdomains_ctx *ctx;
    struct sss_domain_info *dom;

    ctx = talloc_get_type(be_ctx->bet_info[BET_SUBDOMAINS].pvt_bet_data,
                          struct ipa_subdomains_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Subdomains are not configured.\n");
        return NULL;
    }

    dom = find_subdomain_by_name(ctx->be_ctx->domain, name, true);
    if (dom) {
        return dom->flat_name;
    }

    return NULL;
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
            DEBUG(SSSDBG_OP_FAILURE, ("get_idmap_data_from_range failed.\n"));
            goto done;
        }
        for (d = 0; d < c; d++) {
            ret = get_idmap_data_from_range(range_list[d], domain_name, &name2,
                                            &sid2, &rid2, &range2, &mapping2);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("get_idmap_data_from_range failed.\n"));
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
    const char *orig_dn;
    struct ldb_dn *dn = NULL;
    const struct ldb_val *val;
    char *forest = NULL;

    ret = sysdb_attrs_get_string(attrs, SYSDB_ORIG_DN, &orig_dn);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL, "Checking if we need the forest name for [%s].\n",
                             orig_dn);

    dn = ldb_dn_new(mem_ctx, ldb_ctx, orig_dn);
    if (dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        goto done;
    }

    if (!ldb_dn_validate(dn)) {
        DEBUG(SSSDBG_OP_FAILURE, "Original DN [%s] is not a valid DN.\n",
                                  orig_dn);
        ret = EINVAL;
        goto done;
    }

    if (ldb_dn_get_comp_num(dn) < 5) {
        /* We are only interested in the member domain objects. In IPA the
         * forest root object is stored as e.g.
         * cn=AD.DOM,cn=ad,cn=trusts,dc=example,dc=com. Member domains in the
         * forest are children of the forest root object e.g.
         * cn=SUB.AD.DOM,cn=AD.DOM,cn=ad,cn=trusts,dc=example,dc=com. Since
         * the forest name is not stored in the member objects we derive it
         * from the RDN of the forest root object. */
        ret = EOK;
        goto done;
    }

    val = ldb_dn_get_component_val(dn, 3);
    if (strncasecmp("trusts", (const char *) val->data, val->length) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "4th component is not 'trust', nothing to do.\n");
        ret = EOK;
        goto done;
    }

    val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp("ad", (const char *) val->data, val->length) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "3rd component is not 'ad', nothing to do.\n");
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

done:
    talloc_free(dn);

    if (ret == EOK) {
        *_forest = forest;
    }

    return ret;
}

static errno_t ipa_subdom_store(struct sss_domain_info *parent,
                                struct sdap_idmap_ctx *sdap_idmap_ctx,
                                struct sysdb_attrs *attrs,
                                bool enumerate)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    char *realm;
    const char *flat;
    const char *id;
    char *forest = NULL;
    int ret;
    bool mpg;

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

    ret = sysdb_subdomain_store(parent->sysdb, name, realm, flat,
                                id, mpg, enumerate, forest);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_subdomain_store failed.\n");
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
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
    bool enumerate;

    parent = ctx->be_ctx->domain;
    memset(handled, 0, sizeof(bool) * count);
    h = 0;

    /* check existing subdomains */
    for (dom = get_next_domain(parent, true);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, false)) {
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
            dom->disabled = true;
            ret = sysdb_subdomain_delete(dom->sysdb, dom->name);
            if (ret != EOK) {
                goto done;
            }

            /* Remove the AD ID ctx from the list of LDAP domains */
            ipa_ad_subdom_remove(ctx, dom);
        } else {
            /* ok let's try to update it */
            ret = ipa_subdom_enumerates(parent, reply[c], &enumerate);
            if (ret != EOK) {
                goto done;
            }

            ret = ipa_subdom_store(parent, ctx->sdap_id_ctx->opts->idmap_ctx,
                                   reply[c], enumerate);
            if (ret) {
                /* Nothing we can do about the errorr. Let's at least try
                 * to reuse the existing domain
                 */
                DEBUG(SSSDBG_MINOR_FAILURE, "Failed to parse subdom data, "
                      "will try to use cached subdomain\n");
            }
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
        /* Nothing we can do about the errorr. Let's at least try
         * to reuse the existing domain.
         */
        ret = ipa_subdom_enumerates(parent, reply[c], &enumerate);
        if (ret != EOK) {
            goto done;
        }

        ret = ipa_subdom_store(parent, ctx->sdap_id_ctx->opts->idmap_ctx,
                               reply[c], enumerate);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to parse subdom data, "
                  "will try to use cached subdomain\n");
        }
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
ipa_subdomains_handler_get(struct ipa_subdomains_req_ctx *ctx,
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
      { IPA_CN, IPA_FLATNAME, IPA_TRUSTED_DOMAIN_SID, NULL }
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
    be_req_terminate(be_req, dp_error, ret, NULL);
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

    ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_RANGES);
    if (ret != EOK && ret != EAGAIN) {
        goto fail;
    }

    return;

fail:
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
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

static void ipa_subdomains_handler_done(struct tevent_req *req)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ipa_subdomains_req_ctx *ctx;
    struct sss_domain_info *domain;
    bool refresh_has_changes = false;
    int dp_error = DP_ERR_FATAL;

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

    ctx->search_base_iter++;
    ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_SLAVE);
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

        ret = ipa_ad_subdom_refresh(ctx->sd_ctx->be_ctx, ctx->sd_ctx->id_ctx,
                                    domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_ad_subdom_refresh failed.\n");
            goto done;
        }
    }

    ret = sysdb_master_domain_update(domain);
    if (ret != EOK) {
        goto done;
    }

    if (domain->flat_name == NULL ||
        domain->domain_id == NULL ||
        domain->realm == NULL) {

        ctx->search_base_iter = 0;
        ctx->search_bases = ctx->sd_ctx->master_search_bases;
        ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_MASTER);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            goto done;
        }
    } else {
        ret = EOK;
    }

done:
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
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

    ctx->search_base_iter = 0;
    ctx->search_bases = ctx->sd_ctx->search_bases;
    ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_SLAVE);
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
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static void ipa_subdomains_handler_master_done(struct tevent_req *req)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    size_t reply_count;
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

        ret = sysdb_attrs_get_string(reply[0], IPA_FLATNAME, &flat);
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[0], IPA_SID, &id);
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_master_domain_add_info(ctx->sd_ctx->be_ctx->domain,
                                           flat, id, NULL);
    } else {
        ctx->search_base_iter++;
        ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_MASTER);
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
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
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
        be_req_terminate(be_req, DP_ERR_OK, EOK, NULL);
        return;
    }

    if (ctx->last_refreshed > now - IPA_SUBDOMAIN_REFRESH_LIMIT) {
        be_req_terminate(be_req, DP_ERR_OK, EOK, NULL);
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
    ctx->configured_explicit = configured_explicit;
    ctx->disabled_until = 0;
    *ops = &ipa_subdomains_ops;
    *pvt_data = ctx;

    ret = be_add_unconditional_online_cb(ctx, be_ctx,
                                         ipa_subdom_reset_timeouts_cb, ctx,
                                         NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to add subdom reset timeouts callback");
    }

    ret = be_add_online_cb(ctx, be_ctx, ipa_subdom_online_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add subdom online callback");
    }

    ret = be_add_offline_cb(ctx, be_ctx, ipa_subdom_offline_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add subdom offline callback");
    }

    ret = ipa_subdom_reinit(ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not load the list of subdomains. "
              "Users from trusted domains might not be resolved correctly\n");
    }

    return EOK;
}

int ipa_ad_subdom_init(struct be_ctx *be_ctx,
                       struct ipa_id_ctx *id_ctx)
{
    char *realm;
    char *hostname;
    errno_t ret;

    if (dp_opt_get_bool(id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        return EOK;
    }

    /* The IPA code relies on the default FQDN format to unparse user
     * names. Warn loudly if the full_name_format was customized on the
     * IPA server
     */
    if ((strcmp(be_ctx->domain->names->fq_fmt,
               CONFDB_DEFAULT_FULL_NAME_FORMAT) != 0)
            && (strcmp(be_ctx->domain->names->fq_fmt,
                       CONFDB_DEFAULT_FULL_NAME_FORMAT_INTERNAL) != 0)) {
        DEBUG(SSSDBG_FATAL_FAILURE, "%s is set to a non-default value [%s] " \
              "lookups of subdomain users will likely fail!\n",
              CONFDB_FULL_NAME_FORMAT, be_ctx->domain->names->fq_fmt);
        sss_log(SSS_LOG_ERR, "%s is set to a non-default value [%s] " \
                "lookups of subdomain users will likely fail!\n",
                CONFDB_FULL_NAME_FORMAT, be_ctx->domain->names->fq_fmt);
        /* Attempt to continue */
    }

    realm = dp_opt_get_string(id_ctx->ipa_options->basic, IPA_KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No Kerberos realm for IPA?\n");
        return EINVAL;
    }

    hostname = dp_opt_get_string(id_ctx->ipa_options->basic, IPA_HOSTNAME);
    if (hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No host name for IPA?\n");
        return EINVAL;
    }

    id_ctx->server_mode = talloc_zero(id_ctx, struct ipa_server_mode_ctx);
    if (id_ctx->server_mode == NULL) {
        return ENOMEM;
    }
    id_ctx->server_mode->realm = realm;
    id_ctx->server_mode->hostname = hostname;
    id_ctx->server_mode->trusts = NULL;
    id_ctx->server_mode->ext_groups = NULL;

    ret = ipa_ad_subdom_refresh(be_ctx, id_ctx, be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_ad_subdom_refresh failed.\n");
        return ret;
    }

    return EOK;
}
