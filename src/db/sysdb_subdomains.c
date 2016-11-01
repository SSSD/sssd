/*
   SSSD

   System Database - Sub-domain related calls

   Copyright (C) 2012 Jan Zeleny <jzeleny@redhat.com>
   Copyright (C) 2012 Sumit Bose <sbose@redhat.com>

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

#include "util/util.h"
#include "db/sysdb_private.h"

struct sss_domain_info *new_subdomain(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *parent,
                                      const char *name,
                                      const char *realm,
                                      const char *flat_name,
                                      const char *id,
                                      bool mpg,
                                      bool enumerate,
                                      const char *forest,
                                      uint32_t trust_direction)
{
    struct sss_domain_info *dom;
    bool inherit_option;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Creating [%s] as subdomain of [%s]!\n", name, parent->name);

    dom = talloc_zero(mem_ctx, struct sss_domain_info);
    if (dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return NULL;
    }

    dom->parent = parent;

    /* Sub-domains always have the same view as the parent */
    dom->has_views = parent->has_views;
    if (parent->view_name != NULL) {
        dom->view_name = talloc_strdup(dom, parent->view_name);
        if (dom->view_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy parent's view name.\n");
            goto fail;
        }
    }

    dom->name = talloc_strdup(dom, name);
    if (dom->name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy domain name.\n");
        goto fail;
    }

    dom->provider = talloc_strdup(dom, parent->provider);
    if (dom->provider == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy provider name.\n");
        goto fail;
    }

    dom->conn_name = talloc_strdup(dom, parent->conn_name);
    if (dom->conn_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy connection name.\n");
        goto fail;
    }

    if (realm != NULL) {
        dom->realm = talloc_strdup(dom, realm);
        if (dom->realm == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy realm name.\n");
            goto fail;
        }
    }

    if (flat_name != NULL) {
        dom->flat_name = talloc_strdup(dom, flat_name);
        if (dom->flat_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy flat name.\n");
            goto fail;
        }
    }

    if (id != NULL) {
        dom->domain_id = talloc_strdup(dom, id);
        if (dom->domain_id == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy id.\n");
            goto fail;
        }
    }

    if (forest != NULL) {
        dom->forest = talloc_strdup(dom, forest);
        if (dom->forest == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy forest.\n");
            goto fail;
        }
    }

    dom->enumerate = enumerate;
    dom->fqnames = true;
    dom->mpg = mpg;
    dom->state = DOM_ACTIVE;

    /* If the parent domain filters out group members, the subdomain should
     * as well if configured */
    inherit_option = string_in_list(CONFDB_DOMAIN_IGNORE_GROUP_MEMBERS,
                                    parent->sd_inherit, false);
    if (inherit_option) {
        dom->ignore_group_members = parent->ignore_group_members;
    }

    dom->trust_direction = trust_direction;
    /* If the parent domain explicitly limits ID ranges, the subdomain
     * should honour the limits as well.
     */
    dom->id_min = parent->id_min ? parent->id_min : 0;
    dom->id_max = parent->id_max ? parent->id_max : 0xffffffff;
    dom->pwd_expiration_warning = parent->pwd_expiration_warning;
    dom->cache_credentials = parent->cache_credentials;
    dom->cache_credentials_min_ff_length =
                                        parent->cache_credentials_min_ff_length;
    dom->case_sensitive = false;
    dom->user_timeout = parent->user_timeout;
    dom->group_timeout = parent->group_timeout;
    dom->netgroup_timeout = parent->netgroup_timeout;
    dom->service_timeout = parent->service_timeout;
    dom->names = parent->names;

    dom->override_homedir = parent->override_homedir;
    dom->fallback_homedir = parent->fallback_homedir;
    dom->subdomain_homedir = parent->subdomain_homedir;
    dom->override_shell = parent->override_shell;
    dom->default_shell = parent->default_shell;
    dom->homedir_substr = parent->homedir_substr;

    if (parent->sysdb == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing sysdb context in parent domain.\n");
        goto fail;
    }
    dom->sysdb = parent->sysdb;

    return dom;

fail:
    talloc_free(dom);
    return NULL;
}

static bool is_forest_root(struct sss_domain_info *d)
{
    if (d->forest == NULL) {
        /* IPA subdomain provider saves/saved trusted forest root domains
         * without the forest attribute. Those are automatically forest
         * roots
         */
        return true;
    }

    if (d->realm && (strcasecmp(d->forest, d->realm) == 0)) {
        return true;
    }

    return false;
}

static bool is_same_forest(struct sss_domain_info *root,
                           struct sss_domain_info *member)
{
    if (member->forest != NULL
            && root->realm != NULL
            && strcasecmp(member->forest, root->realm) == 0) {
        return true;
    }

    return false;
}

static void link_forest_roots(struct sss_domain_info *domain)
{
    struct sss_domain_info *d;
    struct sss_domain_info *dd;
    uint32_t gnd_flags = SSS_GND_ALL_DOMAINS;

    for (d = domain; d; d = get_next_domain(d, gnd_flags)) {
        d->forest_root = NULL;
    }

    for (d = domain; d; d = get_next_domain(d, gnd_flags)) {
        if (d->forest_root != NULL) {
            continue;
        }

        if (is_forest_root(d) == true) {
            d->forest_root = d;
            DEBUG(SSSDBG_TRACE_INTERNAL, "[%s] is a forest root\n", d->name);

            for (dd = domain; dd; dd = get_next_domain(dd, gnd_flags)) {
                if (dd->forest_root != NULL) {
                    continue;
                }

                if (is_same_forest(d, dd) == true) {
                    dd->forest_root = d;
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "[%s] is a forest root of [%s]\n",
                          d->forest_root->name,
                          dd->name);
                }
            }
        }
    }
}

errno_t sysdb_update_subdomains(struct sss_domain_info *domain)
{
    int i;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_ID,
                           SYSDB_SUBDOMAIN_MPG,
                           SYSDB_SUBDOMAIN_ENUM,
                           SYSDB_SUBDOMAIN_FOREST,
                           SYSDB_SUBDOMAIN_TRUST_DIRECTION,
                           SYSDB_UPN_SUFFIXES,
                           NULL};
    struct sss_domain_info *dom;
    struct ldb_dn *basedn;
    const char *name;
    const char *realm;
    const char *flat;
    const char *id;
    const char *forest;
    bool mpg;
    bool enumerate;
    uint32_t trust_direction;
    struct ldb_message_element *tmp_el;
    const char **upn_suffixes;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    basedn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, SYSDB_BASE);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_ONELEVEL,
                     attrs, "objectclass=%s", SYSDB_SUBDOMAIN_CLASS);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* disable all domains,
     * let the search result refresh any that are still valid */
    for (dom = domain->subdomains; dom; dom = get_next_domain(dom, false)) {
        sss_domain_set_state(dom, DOM_DISABLED);
    }

    if (res->count == 0) {
        ret = EOK;
        goto done;
    }

    for (i = 0; i < res->count; i++) {

        name = ldb_msg_find_attr_as_string(res->msgs[i], "cn", NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "The object [%s] doesn't have a name\n",
                   ldb_dn_get_linearized(res->msgs[i]->dn));
            ret = EINVAL;
            goto done;
        }

        realm = ldb_msg_find_attr_as_string(res->msgs[i],
                                            SYSDB_SUBDOMAIN_REALM, NULL);

        flat = ldb_msg_find_attr_as_string(res->msgs[i],
                                           SYSDB_SUBDOMAIN_FLAT, NULL);

        id = ldb_msg_find_attr_as_string(res->msgs[i],
                                         SYSDB_SUBDOMAIN_ID, NULL);

        mpg = ldb_msg_find_attr_as_bool(res->msgs[i],
                                        SYSDB_SUBDOMAIN_MPG, false);

        enumerate = ldb_msg_find_attr_as_bool(res->msgs[i],
                                              SYSDB_SUBDOMAIN_ENUM, false);

        forest = ldb_msg_find_attr_as_string(res->msgs[i],
                                             SYSDB_SUBDOMAIN_FOREST, NULL);

        upn_suffixes = NULL;
        tmp_el = ldb_msg_find_element(res->msgs[0], SYSDB_UPN_SUFFIXES);
        if (tmp_el != NULL) {
            upn_suffixes = sss_ldb_el_to_string_list(tmp_ctx, tmp_el);
            if (upn_suffixes == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_ldb_el_to_string_list failed.\n");
                ret = ENOMEM;
                goto done;
            }
        }

        trust_direction = ldb_msg_find_attr_as_int(res->msgs[i],
                                             SYSDB_SUBDOMAIN_TRUST_DIRECTION,
                                             0);

        for (dom = domain->subdomains; dom;
                dom = get_next_domain(dom, SSS_GND_INCLUDE_DISABLED)) {
            if (strcasecmp(dom->name, name) == 0) {
                sss_domain_set_state(dom, DOM_ACTIVE);

                /* in theory these may change, but it should never happen */
                if (strcasecmp(dom->realm, realm) != 0) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Realm name changed from [%s] to [%s]!\n",
                           dom->realm, realm);
                    talloc_zfree(dom->realm);
                    dom->realm = talloc_strdup(dom, realm);
                    if (dom->realm == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }
                if (strcasecmp(dom->flat_name, flat) != 0) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Flat name changed from [%s] to [%s]!\n",
                           dom->flat_name, flat);
                    talloc_zfree(dom->flat_name);
                    dom->flat_name = talloc_strdup(dom, flat);
                    if (dom->flat_name == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }
                if (strcasecmp(dom->domain_id, id) != 0) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Domain changed from [%s] to [%s]!\n",
                           dom->domain_id, id);
                    talloc_zfree(dom->domain_id);
                    dom->domain_id = talloc_strdup(dom, id);
                    if (dom->domain_id == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }

                if (dom->mpg != mpg) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "MPG state change from [%s] to [%s]!\n",
                           dom->mpg ? "true" : "false",
                           mpg ? "true" : "false");
                    dom->mpg = mpg;
                }

                if (dom->enumerate != enumerate) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "enumerate state change from [%s] to [%s]!\n",
                           dom->enumerate ? "true" : "false",
                           enumerate ? "true" : "false");
                    dom->enumerate = enumerate;
                }

                if ((dom->forest == NULL && forest != NULL)
                        || (dom->forest != NULL && forest != NULL
                            && strcasecmp(dom->forest, forest) != 0)) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Forest changed from [%s] to [%s]!\n",
                           dom->forest, forest);
                    talloc_zfree(dom->forest);
                    dom->forest = talloc_strdup(dom, forest);
                    if (dom->forest == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }

                talloc_zfree(dom->upn_suffixes);
                dom->upn_suffixes = talloc_steal(dom, upn_suffixes);

                if (!dom->has_views && dom->view_name == NULL) {
                    /* maybe views are not initialized, copy from parent */
                    dom->has_views = dom->parent->has_views;
                    if (dom->parent->view_name != NULL) {
                        dom->view_name = talloc_strdup(dom,
                                                       dom->parent->view_name);
                        if (dom->view_name == NULL) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "Failed to copy parent's view name.\n");
                            ret = ENOMEM;
                            goto done;
                        }
                    }
                } else {
                    if (dom->has_views != dom->parent->has_views
                            || strcmp(dom->view_name,
                                      dom->parent->view_name) != 0) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                            "Sub-domain [%s][%s] and parent [%s][%s] " \
                            "views are different.\n",
                            dom->has_views ? "has view" : "has no view",
                            dom->view_name,
                            dom->parent->has_views ? "has view" : "has no view",
                            dom->parent->view_name);
                        ret = EINVAL;
                        goto done;
                    }
                }

                if (dom->trust_direction != trust_direction) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Trust direction change from [%d] to [%d]!\n",
                           dom->trust_direction, trust_direction);
                    dom->trust_direction = trust_direction;
                }

                break;
            }
        }
        /* If not found in loop it is a new subdomain */
        if (dom == NULL) {
            dom = new_subdomain(domain, domain, name, realm,
                                flat, id, mpg, enumerate, forest,
                                trust_direction);
            if (dom == NULL) {
                ret = ENOMEM;
                goto done;
            }
            DLIST_ADD_END(domain->subdomains, dom, struct sss_domain_info *);
        }
    }

    link_forest_roots(domain);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_master_domain_update(struct sss_domain_info *domain)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *tmp_str;
    struct ldb_message_element *tmp_el;
    struct ldb_dn *basedn;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_ID,
                           SYSDB_SUBDOMAIN_FOREST,
                           SYSDB_UPN_SUFFIXES,
                           NULL};
    char *view_name = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_DOM_BASE, domain->name);
    if (basedn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_BASE, attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Base search returned [%d] results, "
                                 "expected 1.\n", res->count);
        ret = EINVAL;
        goto done;
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_REALM,
                                          NULL);
    if (tmp_str != NULL &&
        (domain->realm == NULL || strcasecmp(tmp_str, domain->realm) != 0)) {
        talloc_free(domain->realm);
        domain->realm = talloc_strdup(domain, tmp_str);
        if (domain->realm == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_FLAT,
                                          NULL);
    if (tmp_str != NULL &&
        (domain->flat_name == NULL ||
         strcasecmp(tmp_str, domain->flat_name) != 0)) {
        talloc_free(domain->flat_name);
        domain->flat_name = talloc_strdup(domain, tmp_str);
        if (domain->flat_name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_ID,
                                          NULL);
    if (tmp_str != NULL &&
        (domain->domain_id == NULL ||
         strcasecmp(tmp_str, domain->domain_id) != 0)) {
        talloc_free(domain->domain_id);
        domain->domain_id = talloc_strdup(domain, tmp_str);
        if (domain->domain_id == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_FOREST,
                                          NULL);
    if (tmp_str != NULL &&
        (domain->forest == NULL ||
         strcasecmp(tmp_str, domain->forest) != 0)) {
        talloc_free(domain->forest);
        domain->forest = talloc_strdup(domain, tmp_str);
        if (domain->forest == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp_el = ldb_msg_find_element(res->msgs[0], SYSDB_UPN_SUFFIXES);
    if (tmp_el != NULL) {
        talloc_free(domain->upn_suffixes);
        domain->upn_suffixes = sss_ldb_el_to_string_list(domain, tmp_el);
        if (domain->upn_suffixes == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_ldb_el_to_string_list failed.\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        talloc_zfree(domain->upn_suffixes);
    }

    ret = sysdb_get_view_name(tmp_ctx, domain->sysdb, &view_name);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_view_name failed.\n");
        goto done;
    }

    /* If no view is defined the default view will be used. In this case
     * domain->has_views is FALSE and
     * domain->view_name is set to SYSDB_DEFAULT_VIEW_NAME
     *
     * If there is a view defined
     * domain->has_views is TRUE and
     * domain->view_name is set to the given view name
     *
     * Currently changing the view is not supported hence we have to check for
     * changes and error out accordingly.
     */
    if (ret == ENOENT || is_default_view(view_name)) {
        /* handle default view */
        if (domain->has_views) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "View name change is currently not supported. " \
                  "New view is the default view while current view is [%s]. " \
                  "View name is not changed!\n", domain->view_name);
        } else {
            if (domain->view_name == NULL) {
                domain->view_name = talloc_strdup(domain,
                                                  SYSDB_DEFAULT_VIEW_NAME);
                if (domain->view_name == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
            } else {
                if (strcmp(domain->view_name, SYSDB_DEFAULT_VIEW_NAME) != 0) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Domain [%s] has no view but view name [%s] " \
                          "is not the default view name [%s].\n",
                          domain->name, domain->view_name,
                          SYSDB_DEFAULT_VIEW_NAME);
                    ret = EINVAL;
                    goto done;
                }
            }
        }
    } else {
        /* handle view other than default */
        if (domain->has_views) {
            if (strcmp(domain->view_name, view_name) != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "View name change is currently not supported. " \
                      "New view is [%s] while current view is [%s]. " \
                      "View name is not changed!\n",
                      view_name, domain->view_name);
            }
        } else {
            if (domain->view_name == NULL) {
                domain->has_views = true;
                domain->view_name = talloc_steal(domain, view_name);
                if (domain->view_name == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_steal failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
            } else {
                if (strcmp(domain->view_name, SYSDB_DEFAULT_VIEW_NAME) == 0) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                        "View name change is currently not supported. " \
                        "New view is [%s] while current is the default view. " \
                        "View name is not changed!\n", view_name);
                } else {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Domain currently has no views, " \
                          "but current view name is set to [%s] " \
                          "and new view name is [%s].\n",
                          domain->view_name, view_name);
                    ret = EINVAL;
                    goto done;
                }
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_master_domain_add_info(struct sss_domain_info *domain,
                                     const char *realm,
                                     const char *flat,
                                     const char *id,
                                     const char *forest,
                                     struct ldb_message_element *upn_suffixes)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    int ret;
    bool do_update = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_DOM_BASE, domain->name);
    if (msg->dn == NULL) {
        ret = EIO;
        goto done;
    }

    if (flat != NULL && (domain->flat_name == NULL ||
                         strcmp(domain->flat_name, flat) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FLAT,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FLAT, flat);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

    if (id != NULL && (domain->domain_id == NULL ||
                       strcmp(domain->domain_id, id) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_ID,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_ID, id);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

   if (forest != NULL && (domain->forest == NULL ||
                       strcmp(domain->forest, forest) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FOREST,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FOREST, forest);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

   if (realm != NULL && (domain->realm == NULL ||
                       strcmp(domain->realm, realm) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_REALM,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_REALM, realm);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    }

    if (upn_suffixes != NULL) {
        talloc_free(discard_const(upn_suffixes->name));
        upn_suffixes->name = talloc_strdup(upn_suffixes, SYSDB_UPN_SUFFIXES);
        if (upn_suffixes->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_msg_add(msg, upn_suffixes, LDB_FLAG_MOD_REPLACE);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        do_update = true;
    } else {
        /* Remove alternative_domain_suffixes from the cache */
        if (domain->upn_suffixes != NULL) {
            ret = ldb_msg_add_empty(msg, SYSDB_UPN_SUFFIXES,
                                    LDB_FLAG_MOD_DELETE, NULL);
            if (ret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(ret);
                goto done;
            }

            do_update = true;
        }
    }

    if (do_update == false) {
        ret = EOK;
        goto done;
    }

    ret = ldb_modify(domain->sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add subdomain attributes to "
                                     "[%s]: [%d][%s]!\n", domain->name, ret,
                                     ldb_errstring(domain->sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = sysdb_master_domain_update(domain);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_subdomain_store(struct sysdb_ctx *sysdb,
                              const char *name, const char *realm,
                              const char *flat_name, const char *domain_id,
                              bool mpg, bool enumerate, const char *forest,
                              uint32_t trust_direction,
                              struct ldb_message_element *upn_suffixes)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_ID,
                           SYSDB_SUBDOMAIN_MPG,
                           SYSDB_SUBDOMAIN_ENUM,
                           SYSDB_SUBDOMAIN_FOREST,
                           SYSDB_SUBDOMAIN_TRUST_DIRECTION,
                           SYSDB_UPN_SUFFIXES,
                           NULL};
    const char *tmp_str;
    struct ldb_message_element *tmp_el;
    bool tmp_bool;
    bool store = false;
    int realm_flags = 0;
    int flat_flags = 0;
    int id_flags = 0;
    int mpg_flags = 0;
    int enum_flags = 0;
    int forest_flags = 0;
    int td_flags = 0;
    int upn_flags = 0;
    uint32_t tmp_td;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE, name);
    if (dn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(sysdb->ldb, tmp_ctx, &res,
                     dn, LDB_SCOPE_BASE, attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        ret = sysdb_domain_create(sysdb, name);
        if (ret) {
            goto done;
        }
        store = true;
        if (realm) realm_flags = LDB_FLAG_MOD_ADD;
        if (flat_name) flat_flags = LDB_FLAG_MOD_ADD;
        if (domain_id) id_flags = LDB_FLAG_MOD_ADD;
        mpg_flags = LDB_FLAG_MOD_ADD;
        enum_flags = LDB_FLAG_MOD_ADD;
        if (forest) forest_flags = LDB_FLAG_MOD_ADD;
        if (trust_direction) td_flags = LDB_FLAG_MOD_ADD;
        if (upn_suffixes) upn_flags = LDB_FLAG_MOD_ADD;
    } else if (res->count != 1) {
        ret = EINVAL;
        goto done;
    } else { /* 1 found */
        if (realm) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_REALM, NULL);
            if (!tmp_str || strcasecmp(tmp_str, realm) != 0) {
                realm_flags = LDB_FLAG_MOD_REPLACE;
            }
        }
        if (flat_name) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_FLAT, NULL);
            if (!tmp_str || strcasecmp(tmp_str, flat_name) != 0) {
                flat_flags = LDB_FLAG_MOD_REPLACE;
            }
        }
        if (domain_id) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_ID, NULL);
            if (!tmp_str || strcasecmp(tmp_str, domain_id) != 0) {
                id_flags = LDB_FLAG_MOD_REPLACE;
            }
        }

        tmp_bool = ldb_msg_find_attr_as_bool(res->msgs[0], SYSDB_SUBDOMAIN_MPG,
                                             !mpg);
        if (tmp_bool != mpg) {
            mpg_flags = LDB_FLAG_MOD_REPLACE;
        }
        tmp_bool = ldb_msg_find_attr_as_bool(res->msgs[0], SYSDB_SUBDOMAIN_ENUM,
                                             !enumerate);
        if (tmp_bool != enumerate) {
            enum_flags = LDB_FLAG_MOD_REPLACE;
        }

        if (forest) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_FOREST, NULL);
            if (!tmp_str || strcasecmp(tmp_str, forest) != 0) {
                forest_flags = LDB_FLAG_MOD_REPLACE;
            }
        }

        tmp_td = ldb_msg_find_attr_as_uint(res->msgs[0],
                                           SYSDB_SUBDOMAIN_TRUST_DIRECTION,
                                           0);
        if (tmp_td != trust_direction) {
            td_flags = LDB_FLAG_MOD_REPLACE;
        }

        if (upn_suffixes) {
            tmp_el = ldb_msg_find_element(res->msgs[0], SYSDB_UPN_SUFFIXES);
            /* Luckily ldb_msg_element_compare() only compares the values and
             * not the name. */
            if (tmp_el == NULL
                    || ldb_msg_element_compare(upn_suffixes, tmp_el) != 0) {
                upn_flags = LDB_FLAG_MOD_REPLACE;
            }
        }
    }

    if (!store && realm_flags == 0 && flat_flags == 0 && id_flags == 0
            && mpg_flags == 0 && enum_flags == 0 && forest_flags == 0
            && td_flags == 0 && upn_flags == 0) {
        ret = EOK;
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = dn;

    if (store) {
        ret = ldb_msg_add_empty(msg, SYSDB_OBJECTCLASS, LDB_FLAG_MOD_ADD, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS, SYSDB_SUBDOMAIN_CLASS);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (realm_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_REALM, realm_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_REALM, realm);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (flat_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FLAT, flat_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FLAT, flat_name);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (id_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_ID, id_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_ID, domain_id);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (mpg_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_MPG, mpg_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_MPG,
                                 mpg ? "TRUE" : "FALSE");
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (enum_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_ENUM, enum_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_ENUM,
                                 enumerate ? "TRUE" : "FALSE");
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (forest_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_FOREST, forest_flags,
                                NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_FOREST, forest);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (td_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_TRUST_DIRECTION,
                                td_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_fmt(msg, SYSDB_SUBDOMAIN_TRUST_DIRECTION,
                              "%u", trust_direction);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (upn_flags) {
        tmp_el = talloc_zero(tmp_ctx, struct ldb_message_element);
        if (tmp_el == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }

        tmp_el->name = SYSDB_UPN_SUFFIXES;
        tmp_el->num_values = upn_suffixes->num_values;
        tmp_el->values = upn_suffixes->values;
        ret = ldb_msg_add(msg, tmp_el, upn_flags);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add subdomain attributes to "
                                     "[%s]: [%d][%s]!\n", name, ret,
                                     ldb_errstring(sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_subdomain_delete(struct sysdb_ctx *sysdb, const char *name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_dn *dn;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Removing sub-domain [%s] from db.\n", name);
    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE, name);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_delete_recursive(sysdb, dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_recursive failed.\n");
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t match_cn_users(TALLOC_CTX *tmp_ctx,
                              struct sysdb_attrs **usr_attrs,
                              size_t count,
                              const char *dom_basedn,
                              struct sysdb_attrs **_result)
{
    errno_t ret;
    const char *orig_dn;
    size_t dn_len;
    struct sysdb_attrs *result = NULL;
    const char *result_dn_str = NULL;
    char *cn_users_basedn;
    size_t cn_users_basedn_len;

    cn_users_basedn = talloc_asprintf(tmp_ctx, "%s%s", "cn=users,", dom_basedn);
    if (cn_users_basedn == NULL) {
        ret = ENOMEM;
        goto done;
    }
    cn_users_basedn_len = strlen(cn_users_basedn);
    DEBUG(SSSDBG_TRACE_ALL, "cn=users baseDN is [%s].\n", cn_users_basedn);

    for (size_t c = 0; c < count; c++) {
        ret = sysdb_attrs_get_string(usr_attrs[c], SYSDB_ORIG_DN, &orig_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
        dn_len = strlen(orig_dn);

        if (dn_len > cn_users_basedn_len
                && strcasecmp(orig_dn + (dn_len - cn_users_basedn_len),
                              cn_users_basedn) == 0) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Found matching dn [%s].\n", orig_dn);
            if (result != NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Found 2 matching DN [%s] and [%s], expecting only 1.\n",
                      result_dn_str, orig_dn);
                ret = EINVAL;
                goto done;
            }
            result = usr_attrs[c];
            result_dn_str = orig_dn;
        }
    }

    ret = EOK;
done:
    *_result = result;
    return ret;
}

static errno_t match_non_dc_comp(TALLOC_CTX *tmp_ctx,
                                 struct sss_domain_info *dom,
                                 struct sysdb_attrs **usr_attrs,
                                 size_t count,
                                 struct ldb_dn *ldb_basedn,
                                 const char *basedn,
                                 const char *domain_component_name,
                                 struct sysdb_attrs **_result)
{
    errno_t ret;
    const char *orig_dn;
    size_t orig_dn_len;
    size_t basedn_len;
    struct ldb_context *ldb_ctx;
    struct ldb_dn *ldb_orig_dn;
    int dn_comp_num;
    int basedn_comp_num;
    const char *component_name;
    struct sysdb_attrs *result = NULL;
    const char *result_dn_str = NULL;

    ldb_ctx = sysdb_ctx_get_ldb(dom->sysdb);
    if (ldb_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing ldb context.\n");
        ret = EINVAL;
        goto done;
    }

    basedn_len = strlen(basedn);

    basedn_comp_num = ldb_dn_get_comp_num(ldb_basedn);
    basedn_comp_num++;

    for (size_t c = 0; c < count; c++) {
        ret = sysdb_attrs_get_string(usr_attrs[c], SYSDB_ORIG_DN, &orig_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
        orig_dn_len = strlen(orig_dn);

        if (orig_dn_len > basedn_len
                /* Does the user's original DN with the non-domain part
                 * stripped match the domain base DN?
                 */
                && strcasecmp(orig_dn + (orig_dn_len - basedn_len),
                              basedn) == 0) {
            ldb_orig_dn = ldb_dn_new(tmp_ctx, ldb_ctx, orig_dn);
            if (ldb_orig_dn == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed");
                ret = ENOMEM;
                goto done;
            }

            dn_comp_num = ldb_dn_get_comp_num(ldb_orig_dn);
            if (dn_comp_num > basedn_comp_num) {
                component_name = ldb_dn_get_component_name(ldb_orig_dn,
                        (dn_comp_num - basedn_comp_num));
                DEBUG(SSSDBG_TRACE_ALL, "Comparing [%s] and [%s].\n",
                      component_name,
                      domain_component_name);
                /* If the component is NOT a DC component, then the entry
                 * must come from our domain, perhaps from a child container.
                 * If it matched the DC component, the entry was from a child
                 * subdomain different from this one.
                 */
                if (component_name != NULL
                        && strcasecmp(component_name,
                                      domain_component_name) != 0) {
                    DEBUG(SSSDBG_TRACE_ALL,
                            "Found matching dn [%s].\n", orig_dn);
                    if (result != NULL) {
                        DEBUG(SSSDBG_OP_FAILURE,
                                "Found 2 matching DN [%s] and [%s], "
                                "expecting only 1.\n", result_dn_str, orig_dn);
                        ret = EINVAL;
                        goto done;
                    }
                    result = usr_attrs[c];
                    result_dn_str = orig_dn;
                }
            }
        }
    }

    ret = EOK;
    *_result = result;
done:
    return ret;
}

static errno_t match_basedn(TALLOC_CTX *tmp_ctx,
                            struct sss_domain_info *dom,
                            struct sysdb_attrs **usr_attrs,
                            size_t count,
                            const char *dom_basedn,
                            const char *domain_component_name,
                            struct sysdb_attrs **_result)
{
    struct ldb_context *ldb_ctx;
    struct ldb_dn *ldb_dom_basedn;

    ldb_ctx = sysdb_ctx_get_ldb(dom->sysdb);
    if (ldb_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing ldb context.\n");
        return EINVAL;
    }


    ldb_dom_basedn = ldb_dn_new(tmp_ctx, ldb_ctx, dom_basedn);
    if (ldb_dom_basedn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        return ENOMEM;
    }

    return match_non_dc_comp(tmp_ctx, dom,
                             usr_attrs, count,
                             ldb_dom_basedn, dom_basedn,
                             domain_component_name,
                             _result);
}

static errno_t match_search_base(TALLOC_CTX *tmp_ctx,
                                 struct sss_domain_info *dom,
                                 const char *domain_component_name,
                                 const char *domain_search_base,
                                 struct sysdb_attrs **usr_attrs,
                                 size_t count,
                                 struct sysdb_attrs **_result)
{
    errno_t ret;
    bool ok;
    const char *search_base;
    struct ldb_context *ldb_ctx;
    struct sysdb_attrs *result = NULL;
    struct ldb_dn *ldb_search_base;
    int search_base_comp_num;
    int non_dc_comp_num;
    const char *component_name;

    ldb_ctx = sysdb_ctx_get_ldb(dom->sysdb);
    if (ldb_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing ldb context.\n");
        ret = EINVAL;
        goto done;
    }

    ldb_search_base = ldb_dn_new(tmp_ctx, ldb_ctx, domain_search_base);
    if (ldb_search_base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* strip non-DC components from the search base */
    search_base_comp_num = ldb_dn_get_comp_num(ldb_search_base);
    for (non_dc_comp_num = 0;
         non_dc_comp_num < search_base_comp_num;
         non_dc_comp_num++) {

        component_name = ldb_dn_get_component_name(ldb_search_base,
                                                   non_dc_comp_num);
        if (strcasecmp(domain_component_name, component_name) == 0) {
            break;
        }
    }

    if (non_dc_comp_num == search_base_comp_num) {
        /* The search base does not have any non-DC components, the search wouldn't
         * match anyway
         */
        ret = EOK;
        *_result = NULL;
        goto done;
    }

    ok = ldb_dn_remove_child_components(ldb_search_base, non_dc_comp_num);
    if (!ok) {
        ret = EINVAL;
        goto done;
    }

    search_base = ldb_dn_get_linearized(ldb_search_base);
    if (search_base == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = match_cn_users(tmp_ctx, usr_attrs, count, search_base, &result);
    if (ret != EOK) {
        goto done;
    }

    if (result == NULL) {
        ret = match_non_dc_comp(tmp_ctx, dom,
                                usr_attrs, count,
                                ldb_search_base, search_base,
                                domain_component_name,
                                &result);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;
    *_result = result;
done:
    return ret;
}

errno_t sysdb_try_to_find_expected_dn(struct sss_domain_info *dom,
                                      const char *domain_component_name,
                                      const char *domain_search_base,
                                      struct sysdb_attrs **usr_attrs,
                                      size_t count,
                                      struct sysdb_attrs **exp_usr)
{
    char *dom_basedn;
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *result = NULL;

    if (dom == NULL || domain_component_name == NULL
            || domain_search_base == NULL
            || usr_attrs == NULL || count == 0) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = domain_to_basedn(tmp_ctx, dom->name, &dom_basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "domain_to_basedn failed.\n");
        ret = EINVAL;
        goto done;
    }

    ret = match_cn_users(tmp_ctx, usr_attrs, count, dom_basedn, &result);
    if (ret != EOK) {
        goto done;
    }

    if (result == NULL) {
        ret = match_basedn(tmp_ctx, dom, usr_attrs,
                           count, dom_basedn, domain_component_name,
                           &result);
        if (ret != EOK) {
            goto done;
        }
    }

    if (result == NULL) {
        ret = match_search_base(tmp_ctx, dom, domain_component_name,
                                   domain_search_base, usr_attrs, count,
                                   &result);
        if (ret != EOK) {
            goto done;
        }
    }

    if (result == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No matching DN found.\n");
        ret = ENOENT;
        goto done;
    }

    *exp_usr = result;

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}
