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
#include "db/sysdb_domain_resolution_order.h"

static errno_t
check_subdom_config_file(struct confdb_ctx *confdb,
                         struct sss_domain_info *subdomain);

struct sss_domain_info *new_subdomain(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *parent,
                                      const char *name,
                                      const char *realm,
                                      const char *flat_name,
                                      const char *dns_name,
                                      const char *id,
                                      enum sss_domain_mpg_mode mpg_mode,
                                      bool enumerate,
                                      const char *forest,
                                      const char **upn_suffixes,
                                      uint32_t trust_direction,
                                      uint32_t trust_type,
                                      struct confdb_ctx *confdb,
                                      bool enabled)
{
    struct sss_domain_info *dom;
    bool inherit_option;
    errno_t ret;

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

    if (dns_name != NULL) {
        dom->dns_name = talloc_strdup(dom, dns_name);
        if (dom->dns_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy dns name.\n");
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

    if (upn_suffixes != NULL) {
        dom->upn_suffixes = dup_string_list(dom, upn_suffixes);
        if (dom->upn_suffixes == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy UPN upn_suffixes.\n");
            goto fail;
        }
    }

    dom->hostname = talloc_strdup(dom, parent->hostname);
    if (dom->hostname == NULL && parent->hostname != NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy hostname.\n");
        goto fail;
    }

    dom->krb5_keytab = talloc_strdup(dom, parent->krb5_keytab);
    if (dom->krb5_keytab == NULL && parent->krb5_keytab != NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy krb5_keytab.\n");
        goto fail;
    }

    dom->enumerate = enumerate;
    dom->fqnames = true;
    dom->mpg_mode = mpg_mode;
    dom->state = enabled ? DOM_ACTIVE : DOM_DISABLED;

    /* use fully qualified names as output in order to avoid causing
     * conflicts with users who have the same name and either the
     * shortname user resolution is enabled or the trusted domain has
     * been explicitly set to use non-fully qualified names as input.
     */
    dom->output_fqnames = true;

    /* If the parent domain filters out group members, the subdomain should
     * as well if configured */
    inherit_option = string_in_list(CONFDB_DOMAIN_IGNORE_GROUP_MEMBERS,
                                    parent->sd_inherit, false);
    if (inherit_option) {
        dom->ignore_group_members = parent->ignore_group_members;
    }

    /* Inherit case_sensitive. All subdomains are always case insensitive,
     * but we want to inherit case preserving which is set with
     * case_sensitive=Preserving. */
    inherit_option = string_in_list(CONFDB_DOMAIN_CASE_SENSITIVE,
                                    parent->sd_inherit, false);
    dom->case_sensitive = false;
    dom->case_preserve = inherit_option ? parent->case_preserve : false;

    dom->trust_direction = trust_direction;
    dom->trust_type = trust_type;
    /* If the parent domain explicitly limits ID ranges, the subdomain
     * should honour the limits as well.
     */
    dom->id_min = parent->id_min ? parent->id_min : 0;
    dom->id_max = parent->id_max ? parent->id_max : 0xffffffff;
    dom->pwd_expiration_warning = parent->pwd_expiration_warning;
    dom->cache_credentials = parent->cache_credentials;
    dom->cache_credentials_min_ff_length =
                                        parent->cache_credentials_min_ff_length;
    dom->cached_auth_timeout = parent->cached_auth_timeout;
    dom->user_timeout = parent->user_timeout;
    dom->group_timeout = parent->group_timeout;
    dom->netgroup_timeout = parent->netgroup_timeout;
    dom->service_timeout = parent->service_timeout;
    dom->resolver_timeout = parent->resolver_timeout;
    dom->names = parent->names;
    dom->override_homedir = parent->override_homedir;
    dom->fallback_homedir = parent->fallback_homedir;
    dom->subdomain_homedir = parent->subdomain_homedir;
    dom->override_shell = parent->override_shell;
    dom->default_shell = parent->default_shell;
    dom->homedir_substr = parent->homedir_substr;
    dom->override_gid = parent->override_gid;

    dom->gssapi_services = parent->gssapi_services;
    dom->gssapi_indicators_map = parent->gssapi_indicators_map;

    dom->not_found_counter = 0;

    if (parent->sysdb == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing sysdb context in parent domain.\n");
        goto fail;
    }
    dom->sysdb = parent->sysdb;

    if (confdb != NULL) {
        /* If confdb was provided, also check for sssd.conf */
        ret = check_subdom_config_file(confdb, dom);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to read subdomain configuration [%d]: %s",
                   ret, sss_strerror(ret));
            goto fail;
        }
    }

    return dom;

fail:
    talloc_free(dom);
    return NULL;
}

static errno_t
check_subdom_config_file(struct confdb_ctx *confdb,
                         struct sss_domain_info *subdomain)
{
    char *sd_conf_path;
    char *case_sensitive_opt;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    sd_conf_path = subdomain_create_conf_path(tmp_ctx, subdomain);
    if (sd_conf_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* use_fully_qualified_names */
    ret = confdb_get_bool(confdb, sd_conf_path, CONFDB_DOMAIN_FQ,
                          true, &subdomain->fqnames);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get %s option for the subdomain: %s\n",
              CONFDB_DOMAIN_FQ, subdomain->name);
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "%s/%s has value %s\n",
          sd_conf_path, CONFDB_DOMAIN_FQ,
          subdomain->fqnames ? "TRUE" : "FALSE");

    /* allow to set pam_gssapi_services */
    ret = confdb_get_string_as_list(confdb, subdomain, sd_conf_path,
                                    CONFDB_PAM_GSSAPI_SERVICES,
                                    &subdomain->gssapi_services);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get %s option for the subdomain: %s\n",
              CONFDB_PAM_GSSAPI_SERVICES, subdomain->name);
        goto done;
    }

    /* allow to set pam_gssapi_check_upn */
    ret = confdb_get_string(confdb, subdomain, sd_conf_path,
                            CONFDB_PAM_GSSAPI_CHECK_UPN,
                            subdomain->parent->gssapi_check_upn,
                            &subdomain->gssapi_check_upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get %s option for the subdomain: %s\n",
              CONFDB_PAM_GSSAPI_CHECK_UPN, subdomain->name);
        goto done;
    }

    /* allow to set pam_gssapi_indicators_map */
    ret = confdb_get_string_as_list(confdb, subdomain, sd_conf_path,
                                    CONFDB_PAM_GSSAPI_INDICATORS_MAP,
                                    &subdomain->gssapi_indicators_map);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get %s option for the subdomain: %s\n",
              CONFDB_PAM_GSSAPI_INDICATORS_MAP, subdomain->name);
        goto done;
    }

    /* case_sensitive=Preserving */
    ret = confdb_get_string(confdb, tmp_ctx, sd_conf_path,
                            CONFDB_DOMAIN_CASE_SENSITIVE, NULL,
                            &case_sensitive_opt);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get %s option for the subdomain: %s\n",
              CONFDB_DOMAIN_CASE_SENSITIVE, subdomain->name);
        goto done;
    }

    if (case_sensitive_opt != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "%s/%s has value %s\n", sd_conf_path,
              CONFDB_DOMAIN_CASE_SENSITIVE, case_sensitive_opt);
        if (strcasecmp(case_sensitive_opt, "true") == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Warning: subdomain can not be set as case-sensitive.\n");
            subdomain->case_sensitive = false;
            subdomain->case_preserve = false;
        } else if (strcasecmp(case_sensitive_opt, "false") == 0) {
            subdomain->case_sensitive = false;
            subdomain->case_preserve = false;
        } else if (strcasecmp(case_sensitive_opt, "preserving") == 0) {
            subdomain->case_sensitive = false;
            subdomain->case_preserve = true;
        } else {
            DEBUG(SSSDBG_FATAL_FAILURE,
                "Invalid value for %s\n", CONFDB_DOMAIN_CASE_SENSITIVE);
            goto done;
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
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

errno_t sysdb_update_subdomains(struct sss_domain_info *domain,
                                struct confdb_ctx *confdb)
{
    int i;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_DNS,
                           SYSDB_SUBDOMAIN_ID,
                           SYSDB_SUBDOMAIN_MPG,
                           SYSDB_SUBDOMAIN_ENUM,
                           SYSDB_SUBDOMAIN_FOREST,
                           SYSDB_SUBDOMAIN_TRUST_DIRECTION,
                           SYSDB_SUBDOMAIN_TRUST_TYPE,
                           SYSDB_UPN_SUFFIXES,
                           SYSDB_ENABLED,
                           NULL};
    struct sss_domain_info *dom;
    struct ldb_dn *basedn;
    const char *name;
    const char *realm;
    const char *flat;
    const char *dns;
    const char *id;
    const char *forest;
    const char *str_mpg_mode;
    bool enabled;
    enum sss_domain_mpg_mode mpg_mode;
    bool enumerate;
    uint32_t trust_direction;
    uint32_t trust_type;
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
                     basedn, LDB_SCOPE_SUBTREE,
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

        dns = ldb_msg_find_attr_as_string(res->msgs[i],
                                          SYSDB_SUBDOMAIN_DNS, NULL);

        id = ldb_msg_find_attr_as_string(res->msgs[i],
                                         SYSDB_SUBDOMAIN_ID, NULL);

        str_mpg_mode = ldb_msg_find_attr_as_string(res->msgs[i],
                                                   SYSDB_SUBDOMAIN_MPG, NULL);
        if (str_mpg_mode == NULL || *str_mpg_mode == '\0') {
            str_mpg_mode = "false";
        }
        mpg_mode = str_to_domain_mpg_mode(str_mpg_mode);

#ifdef BUILD_EXTENDED_ENUMERATION_SUPPORT
        enumerate = ldb_msg_find_attr_as_bool(res->msgs[i],
                                              SYSDB_SUBDOMAIN_ENUM, false);
#else
        enumerate = false;
#endif

        forest = ldb_msg_find_attr_as_string(res->msgs[i],
                                             SYSDB_SUBDOMAIN_FOREST, NULL);

        upn_suffixes = NULL;
        tmp_el = ldb_msg_find_element(res->msgs[i], SYSDB_UPN_SUFFIXES);
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

        trust_type = ldb_msg_find_attr_as_int(res->msgs[i],
                                              SYSDB_SUBDOMAIN_TRUST_TYPE,
                                              0);

        enabled = ldb_msg_find_attr_as_bool(res->msgs[i], SYSDB_ENABLED, true);

        for (dom = domain->subdomains; dom;
                dom = get_next_domain(dom, SSS_GND_INCLUDE_DISABLED)) {
            if (strcasecmp(dom->name, name) == 0) {
                if (enabled) {
                    sss_domain_set_state(dom, DOM_ACTIVE);
                }

                /* in theory these may change, but it should never happen */
                if ((dom->realm == NULL && realm != NULL)
                        || (dom->realm != NULL && realm != NULL
                            && strcasecmp(dom->realm, realm) != 0)) {
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
                if ((dom->flat_name == NULL && flat != NULL)
                        || (dom->flat_name != NULL && flat != NULL
                            && strcasecmp(dom->flat_name, flat) != 0)) {
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
                if ((dom->dns_name == NULL && dns != NULL)
                        || (dom->dns_name != NULL && dns != NULL
                            && strcasecmp(dom->dns_name, dns) != 0)) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "DNS name changed from [%s] to [%s]!\n",
                           dom->dns_name, dns);
                    talloc_zfree(dom->dns_name);
                    dom->dns_name = talloc_strdup(dom, dns);
                    if (dom->dns_name == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }
                if ((dom->domain_id == NULL && id != NULL)
                        || (dom->domain_id != NULL && id != NULL
                            && strcasecmp(dom->domain_id, id) != 0)) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Domain ID changed from [%s] to [%s]!\n",
                           dom->domain_id, id);
                    talloc_zfree(dom->domain_id);
                    dom->domain_id = talloc_strdup(dom, id);
                    if (dom->domain_id == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                }

                if (dom->mpg_mode != mpg_mode) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "MPG state change from [%s] to [%s]!\n",
                           dom->mpg_mode == MPG_ENABLED ? "true" : "false",
                           mpg_mode == MPG_ENABLED ? "true" : "false");
                    dom->mpg_mode = mpg_mode;
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

                if (dom->trust_type != trust_type) {
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Trust type change from [%d] to [%d]!\n",
                           dom->trust_type, trust_type);
                    dom->trust_type = trust_type;
                }
                break;
            }
        }
        /* If not found in loop it is a new subdomain */
        if (dom == NULL) {
            dom = new_subdomain(domain, domain, name, realm,
                                flat, dns, id, mpg_mode, enumerate, forest,
                                upn_suffixes, trust_direction, trust_type,
                                confdb, enabled);
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
    enum sss_domain_state state;
    bool enabled;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_DNS,
                           SYSDB_SUBDOMAIN_ID,
                           SYSDB_SUBDOMAIN_FOREST,
                           SYSDB_UPN_SUFFIXES,
                           SYSDB_ENABLED,
                           NULL};
    char *view_name = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    basedn = sysdb_domain_dn(tmp_ctx, domain);
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

    tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SUBDOMAIN_DNS,
                                          NULL);
    if (tmp_str != NULL &&
        (domain->dns_name == NULL ||
         strcasecmp(tmp_str, domain->dns_name) != 0)) {
        talloc_free(domain->dns_name);
        domain->dns_name = talloc_strdup(domain, tmp_str);
        if (domain->dns_name == NULL) {
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

    state = sss_domain_get_state(domain);
    enabled = ldb_msg_find_attr_as_bool(res->msgs[0], SYSDB_ENABLED, true);
    if (!enabled) {
        sss_domain_set_state(domain, DOM_DISABLED);
    } else if (state == DOM_DISABLED) {
        /* We do not want to enable INACTIVE or INCONSISTENT domain. This
         * is managed by data provider. */
        sss_domain_set_state(domain, DOM_ACTIVE);
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
                                     const char *dns,
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

    msg->dn = sysdb_domain_dn(tmp_ctx, domain);
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

    if (dns != NULL && (domain->dns_name == NULL ||
                         strcmp(domain->dns_name, dns) != 0)) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_DNS,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_DNS, dns);
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
                              const char *flat_name, const char *dns_name,
                              const char *domain_id,
                              enum sss_domain_mpg_mode mpg_mode,
                              bool enumerate, const char *forest,
                              uint32_t trust_direction,
                              uint32_t trust_type,
                              struct ldb_message_element *upn_suffixes)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    struct ldb_result *res;
    const char *attrs[] = {"cn",
                           SYSDB_SUBDOMAIN_REALM,
                           SYSDB_SUBDOMAIN_FLAT,
                           SYSDB_SUBDOMAIN_DNS,
                           SYSDB_SUBDOMAIN_ID,
                           SYSDB_SUBDOMAIN_MPG,
                           SYSDB_SUBDOMAIN_ENUM,
                           SYSDB_SUBDOMAIN_FOREST,
                           SYSDB_SUBDOMAIN_TRUST_DIRECTION,
                           SYSDB_SUBDOMAIN_TRUST_TYPE,
                           SYSDB_UPN_SUFFIXES,
                           NULL};
    const char *tmp_str;
    struct ldb_message_element *tmp_el;
    bool tmp_bool;
    bool store = false;
    int realm_flags = 0;
    int flat_flags = 0;
    int dns_flags = 0;
    int id_flags = 0;
    int mpg_flags = 0;
    int enum_flags = 0;
    int forest_flags = 0;
    int td_flags = 0;
    int tt_flags = 0;
    int upn_flags = 0;
    uint32_t tmp_td;
    uint32_t tmp_tt;
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
        if (dns_name) dns_flags = LDB_FLAG_MOD_ADD;
        if (domain_id) id_flags = LDB_FLAG_MOD_ADD;
        mpg_flags = LDB_FLAG_MOD_ADD;
        enum_flags = LDB_FLAG_MOD_ADD;
        if (forest) forest_flags = LDB_FLAG_MOD_ADD;
        if (trust_direction) td_flags = LDB_FLAG_MOD_ADD;
        if (trust_type) tt_flags = LDB_FLAG_MOD_ADD;
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
        if (dns_name) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_DNS, NULL);
            if (!tmp_str || strcasecmp(tmp_str, dns_name) != 0) {
                dns_flags = LDB_FLAG_MOD_REPLACE;
            }
        }
        if (domain_id) {
            tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_SUBDOMAIN_ID, NULL);
            if (!tmp_str || strcasecmp(tmp_str, domain_id) != 0) {
                id_flags = LDB_FLAG_MOD_REPLACE;
            }
        }

        tmp_str = ldb_msg_find_attr_as_string(res->msgs[0],
                                              SYSDB_SUBDOMAIN_MPG,
                                              "false");
        /* If mpg_mode changed we need to replace the old  value in sysdb */
        switch (mpg_mode) {
        case MPG_ENABLED:
            if (strcasecmp(tmp_str, "true") != 0) {
                mpg_flags = LDB_FLAG_MOD_REPLACE;
            }
            break;
        case MPG_DISABLED:
            if (strcasecmp(tmp_str, "false") != 0) {
                mpg_flags = LDB_FLAG_MOD_REPLACE;
            }
            break;
        case MPG_HYBRID:
            if (strcasecmp(tmp_str, "hybrid") != 0) {
                mpg_flags = LDB_FLAG_MOD_REPLACE;
            }
            break;
        case MPG_DEFAULT:
            if (strcasecmp(tmp_str, "default") != 0) {
                mpg_flags = LDB_FLAG_MOD_REPLACE;
            }
            break;
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

        tmp_tt = ldb_msg_find_attr_as_uint(res->msgs[0],
                                           SYSDB_SUBDOMAIN_TRUST_TYPE,
                                           0);
        if (tmp_tt != trust_type) {
            tt_flags = LDB_FLAG_MOD_REPLACE;
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

    if (!store && realm_flags == 0 && flat_flags == 0
            && dns_flags == 0 && id_flags == 0
            && mpg_flags == 0 && enum_flags == 0 && forest_flags == 0
            && td_flags == 0 && tt_flags == 0 && upn_flags == 0) {
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

    if (dns_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_DNS, dns_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_DNS, dns_name);
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

        tmp_str = str_domain_mpg_mode(mpg_mode);
        if (tmp_str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Couldn't convert mpg_mode to string\n");
            ret = EINVAL;
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_SUBDOMAIN_MPG, tmp_str);
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

    if (tt_flags) {
        ret = ldb_msg_add_empty(msg, SYSDB_SUBDOMAIN_TRUST_TYPE,
                                tt_flags, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_fmt(msg, SYSDB_SUBDOMAIN_TRUST_TYPE,
                              "%u", trust_type);
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

    ret = ldb_msg_add_empty(msg, SYSDB_ENABLED, LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_ENABLED, "TRUE");
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
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

static errno_t sysdb_subdomain_delete_with_filter(struct sysdb_ctx *sysdb,
                                                  const char *name,
                                                  const char *filter)
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

    ret = sysdb_delete_recursive_with_filter(sysdb, dn, true, filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_recursive failed.\n");
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_subdomain_delete(struct sysdb_ctx *sysdb, const char *name)
{
    return sysdb_subdomain_delete_with_filter(sysdb, name,
                                              "(distinguishedName=*)");
}

errno_t sysdb_subdomain_content_delete(struct sysdb_ctx *sysdb,
                                       const char *name)
{
    const char *filter = "(|("SYSDB_UC")("SYSDB_GC"))";

    return sysdb_subdomain_delete_with_filter(sysdb, name, filter);
}

errno_t
sysdb_subdomain_get_id_by_name(TALLOC_CTX *mem_ctx,
                               struct sysdb_ctx *sysdb,
                               const char *name,
                               const char **_id)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    const char *attrs[] = {SYSDB_DOMAIN_ID, NULL};
    struct ldb_message **msgs;
    const char *id;
    char *filter;
    size_t count;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    base_dn = sysdb_base_dn(sysdb, tmp_ctx);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx,
        "(&(" SYSDB_OBJECTCLASS "=" SYSDB_SUBDOMAIN_CLASS ")(cn=%s))", name);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, sysdb, base_dn, LDB_SCOPE_ONELEVEL,
                             filter, attrs, &count, &msgs);
    if (ret != EOK) {
        goto done;
    }

    if (count != 1) {
        ret = ERR_MULTIPLE_ENTRIES;
        goto done;
    }

    id = ldb_msg_find_attr_as_string(msgs[0], SYSDB_DOMAIN_ID, NULL);
    if (id == NULL) {
        ret = ENOENT;
        goto done;
    }

    *_id = talloc_steal(mem_ctx, id);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}


errno_t
sysdb_domain_get_domain_resolution_order(TALLOC_CTX *mem_ctx,
                                         struct sysdb_ctx *sysdb,
                                         const char *domain_name,
                                         const char **_domain_resolution_order)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE, domain_name);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_domain_resolution_order(mem_ctx, sysdb, dn,
                                            _domain_resolution_order);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_domain_update_domain_resolution_order(struct sysdb_ctx *sysdb,
                                            const char *domain_name,
                                            const char *domain_resolution_order)
{

    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_DOM_BASE, domain_name);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_update_domain_resolution_order(sysdb, dn,
                                               domain_resolution_order);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_update_domain_resolution_order() failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}


errno_t
sysdb_get_site(TALLOC_CTX *mem_ctx,
               struct sss_domain_info *dom,
               const char **_site)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *dn;
    const char *attrs[] = { SYSDB_SITE, NULL };
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = sysdb_domain_dn(tmp_ctx, dom);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(dom->sysdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                     attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (res->count == 0) {
        *_site = NULL;
        ret = EOK;
        goto done;
    } else if (res->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Got more than one reply for base search!\n");
        ret = EIO;
        goto done;
    }

    *_site = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SITE, NULL);
    talloc_steal(mem_ctx, *_site);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_set_site(struct sss_domain_info *dom,
               const char *site)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = sysdb_domain_dn(tmp_ctx, dom);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = dn;

    ret = ldb_msg_add_empty(msg, SYSDB_SITE, LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (site != NULL) {
        ret = ldb_msg_add_string(msg, SYSDB_SITE, site);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = ldb_modify(dom->sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_modify()_failed: [%s][%d][%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(dom->sysdb->ldb));
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_domain_set_enabled(struct sysdb_ctx *sysdb,
                         const char *name,
                         bool enabled)
{
    struct ldb_dn *dn;
    errno_t ret;

    dn = ldb_dn_new_fmt(NULL, sysdb->ldb, SYSDB_DOM_BASE, name);
    if (dn == NULL) {
        return ENOMEM;
    }

    ret = sysdb_set_bool(sysdb, dn, NULL, SYSDB_ENABLED, enabled);
    talloc_free(dn);

    return ret;
}

errno_t
sysdb_list_subdomains(TALLOC_CTX *mem_ctx,
                      struct sysdb_ctx *sysdb,
                      const char ***_names)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    const char *attrs[] = {"cn", NULL};
    struct ldb_message **msgs;
    const char *name;
    size_t count;
    const char **names;
    errno_t ret;
    size_t i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    base_dn = sysdb_base_dn(sysdb, tmp_ctx);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }


    ret = sysdb_search_entry(tmp_ctx, sysdb, base_dn, LDB_SCOPE_ONELEVEL,
                             "("SYSDB_OBJECTCLASS"="SYSDB_SUBDOMAIN_CLASS")",
                             attrs, &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    names = talloc_zero_array(tmp_ctx, const char *, count + 1);
    if (names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        name = ldb_msg_find_attr_as_string(msgs[i], "cn", NULL);
        if (name == NULL) {
            ret = EINVAL;
            goto done;
        }

        names[i] = talloc_steal(names, name);
    }

    *_names = talloc_steal(mem_ctx, names);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
