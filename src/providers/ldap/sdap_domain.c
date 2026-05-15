/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2008-2010 Red Hat

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

#include "providers/ldap/ldap_common.h"

int
sdap_domain_destructor(void *mem)
{
    struct sdap_domain *dom =
            talloc_get_type(mem, struct sdap_domain);
    DLIST_REMOVE(*(dom->head), dom);
    return 0;
}

struct sdap_domain *
sdap_domain_get(struct sdap_options *opts,
                struct sss_domain_info *dom)
{
    struct sdap_domain *sditer = NULL;

    DLIST_FOR_EACH(sditer, opts->sdom) {
        if (sditer->dom == dom) {
            break;
        }
    }

    return sditer;
}

struct sdap_domain *
sdap_domain_get_by_name(struct sdap_options *opts,
                        const char *dom_name)
{
    struct sdap_domain *sditer = NULL;

    if (dom_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing domain name.\n");
        return NULL;
    }

    DLIST_FOR_EACH(sditer, opts->sdom) {
        if (sditer->dom->name != NULL
                && strcasecmp(sditer->dom->name, dom_name) == 0) {
            break;
        }
    }

    return sditer;
}

struct sdap_domain *
sdap_domain_get_by_dn(struct sdap_options *opts,
                      const char *dn)
{
    struct sdap_domain *sditer = NULL;
    struct sdap_domain *sdmatch = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    int match_len;
    int best_match_len = 0;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    DLIST_FOR_EACH(sditer, opts->sdom) {
        if (sss_ldap_dn_in_search_bases_len(tmp_ctx, dn, sditer->search_bases,
                                            NULL, &match_len)
            || sss_ldap_dn_in_search_bases_len(tmp_ctx, dn,
                   sditer->user_search_bases, NULL, &match_len)
            || sss_ldap_dn_in_search_bases_len(tmp_ctx, dn,
                   sditer->group_search_bases, NULL, &match_len)
            || sss_ldap_dn_in_search_bases_len(tmp_ctx, dn,
                   sditer->netgroup_search_bases, NULL, &match_len)
            || sss_ldap_dn_in_search_bases_len(tmp_ctx, dn,
                   sditer->sudo_search_bases, NULL, &match_len)
            || sss_ldap_dn_in_search_bases_len(tmp_ctx, dn,
                   sditer->service_search_bases, NULL, &match_len)
            || sss_ldap_dn_in_search_bases_len(tmp_ctx, dn,
                   sditer->autofs_search_bases, NULL, &match_len)) {
            if (best_match_len < match_len) {
                /*this is a longer match*/
                best_match_len = match_len;
                sdmatch = sditer;
            }
        }
    }
    talloc_free(tmp_ctx);
    return sdmatch;
}

errno_t
sdap_domain_add(struct sdap_options *opts,
                struct sss_domain_info *dom,
                struct sdap_domain **_sdom)
{
    struct sdap_domain *sdom;
    errno_t ret;

    sdom = talloc_zero(opts, struct sdap_domain);
    if (sdom == NULL) {
        return ENOMEM;
    }
    sdom->dom = dom;
    sdom->head = &opts->sdom;

    /* Convert the domain name into search base */
    ret = domain_to_basedn(sdom, sdom->dom->name, &sdom->basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
            "Cannot convert domain name [%s] to base DN [%d]: %s\n",
            dom->name, ret, strerror(ret));
        goto done;
    }

    talloc_set_destructor((TALLOC_CTX *)sdom, sdap_domain_destructor);
    DLIST_ADD_END(opts->sdom, sdom, struct sdap_domain *);

    if (_sdom) *_sdom = sdom;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sdom);
    }

    return ret;
}

errno_t
sdap_domain_subdom_add(struct sdap_id_ctx *sdap_id_ctx,
                       struct sdap_domain *sdom_list,
                       struct sss_domain_info *parent)
{
    struct sss_domain_info *dom;
    struct sdap_domain *sdom, *sditer;
    errno_t ret;

    for (dom = get_next_domain(parent, SSS_GND_DESCEND|SSS_GND_INCLUDE_DISABLED);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, SSS_GND_INCLUDE_DISABLED)) {

        /* Always create sdap domain object for the forest root, even if it is
         * disabled so that we can connect later to discover trusted domains
         * in the forest. */
        if (sss_domain_get_state(dom) == DOM_DISABLED
                && !sss_domain_is_forest_root(dom)) {
            continue;
        }

        DLIST_FOR_EACH(sditer, sdom_list) {
            if (sditer->dom == dom) {
                break;
            }
        }

        if (sditer == NULL) {
            /* New sdap domain */
            DEBUG(SSSDBG_TRACE_FUNC, "subdomain %s is a new one, will "
                  "create a new sdap domain object\n", dom->name);

            ret = sdap_domain_add(sdap_id_ctx->opts, dom, &sdom);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                    "Cannot add new sdap domain for domain %s [%d]: %s\n",
                    parent->name, ret, strerror(ret));
                return ret;
            }
        } else if (sditer->search_bases != NULL) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "subdomain %s has already initialized search bases\n",
                  dom->name);
            continue;
        } else {
            sdom = sditer;
        }

        /* Update search bases */
        talloc_zfree(sdom->search_bases);
        sdom->search_bases = talloc_array(sdom, struct sdap_search_base *, 2);
        if (sdom->search_bases == NULL) {
            return ENOMEM;
        }
        sdom->search_bases[1] = NULL;

        ret = sdap_create_search_base(sdom, sysdb_ctx_get_ldb(dom->sysdb),
                                      sdom->basedn, LDAP_SCOPE_SUBTREE,
                                      NULL, &sdom->search_bases[0]);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot create new sdap search base\n");
            return ret;
        }

        sdom->user_search_bases = sdom->search_bases;
        sdom->group_search_bases = sdom->search_bases;
        sdom->netgroup_search_bases = sdom->search_bases;
        sdom->sudo_search_bases = sdom->search_bases;
        sdom->service_search_bases = sdom->search_bases;
        sdom->autofs_search_bases = sdom->search_bases;
    }

    return EOK;
}

void
sdap_domain_remove(struct sdap_options *opts,
                   struct sss_domain_info *dom)
{
    struct sdap_domain *sdom;

    sdom = sdap_domain_get(opts, dom);
    if (sdom == NULL) return;

    DLIST_REMOVE(*(sdom->head), sdom);
}
