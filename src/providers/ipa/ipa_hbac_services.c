/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include "util/util.h"
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ldap/sdap_async.h"

struct ipa_hbac_service_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    struct sdap_options *opts;
    const char *search_base;
    const char **attrs;

    /* Return values */
    size_t service_count;
    struct sysdb_attrs **services;

    size_t servicegroup_count;
    struct sysdb_attrs **servicegroups;
};

static void
ipa_hbac_service_info_done(struct tevent_req *subreq);
static void
ipa_hbac_servicegroup_info_done(struct tevent_req *subreq);

struct tevent_req *
ipa_hbac_service_info_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sysdb_ctx *sysdb,
                           struct sss_domain_info *dom,
                           struct sdap_handle *sh,
                           struct sdap_options *opts,
                           const char *search_base)
{
    errno_t ret;
    struct ipa_hbac_service_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    char *service_filter;

    req = tevent_req_create(mem_ctx, &state, struct ipa_hbac_service_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->opts = opts;
    state->search_base = search_base;

    service_filter = talloc_asprintf(state, "(objectClass=%s)",
                                     IPA_HBAC_SERVICE);
    if (service_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    state->attrs = talloc_array(state, const char *, 6);
    if (state->attrs == NULL) {
        DEBUG(1, ("Failed to allocate service attribute list.\n"));
        ret = ENOMEM;
        goto immediate;
    }
    state->attrs[0] = OBJECTCLASS;
    state->attrs[1] = IPA_CN;
    state->attrs[2] = IPA_UNIQUE_ID;
    state->attrs[3] = IPA_MEMBER;
    state->attrs[4] = IPA_MEMBEROF;
    state->attrs[5] = NULL;

    subreq = sdap_get_generic_send(state, ev, opts, sh, search_base,
                                   LDAP_SCOPE_SUB, service_filter,
                                   state->attrs, NULL, 0,
                                   dp_opt_get_int(opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT));
    if (subreq == NULL) {
        DEBUG(1, ("Error requesting service info\n"));
        ret = EIO;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ipa_hbac_service_info_done, req);

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void
ipa_hbac_service_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_service_state *state =
            tevent_req_data(req, struct ipa_hbac_service_state);
    char *servicegroup_filter;

    ret = sdap_get_generic_recv(subreq, state,
                                &state->service_count,
                                &state->services);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    if (ret == ENOENT || state->service_count == 0) {
        /* If there are no services, we'll shortcut out
         * This is still valid, as rules can apply to
         * all services
         *
         * There's no reason to try to process groups
         */

        state->service_count = 0;
        state->services = NULL;
        ret = EOK;
        goto done;
    }

    ret = replace_attribute_name(IPA_MEMBEROF, SYSDB_ORIG_MEMBEROF,
                                 state->service_count,
                                 state->services);
    if (ret != EOK) {
        DEBUG(1, ("Could not replace attribute names\n"));
        goto done;
    }

    servicegroup_filter = talloc_asprintf(state, "(objectClass=%s)",
                                          IPA_HBAC_SERVICE_GROUP);
    if (servicegroup_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Look up service groups */
    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   state->search_base, LDAP_SCOPE_SUB,
                                   servicegroup_filter, state->attrs, NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT));
    if (subreq == NULL) {
        DEBUG(1, ("Error requesting host info\n"));
        ret = EIO;
        goto done;
    }
    tevent_req_set_callback(subreq, ipa_hbac_servicegroup_info_done, req);

    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static void
ipa_hbac_servicegroup_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_service_state *state =
            tevent_req_data(req, struct ipa_hbac_service_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->servicegroup_count,
                                &state->servicegroups);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = replace_attribute_name(IPA_MEMBER, SYSDB_ORIG_MEMBER,
                                 state->servicegroup_count,
                                 state->servicegroups);
    if (ret != EOK) {
        DEBUG(1, ("Could not replace attribute names\n"));
        goto done;
    }

    ret = replace_attribute_name(IPA_MEMBEROF, SYSDB_ORIG_MEMBEROF,
                                 state->servicegroup_count,
                                 state->servicegroups);
    if (ret != EOK) {
        DEBUG(1, ("Could not replace attribute names\n"));
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(3, ("Error [%d][%s]\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
    }
}

errno_t
ipa_hbac_service_info_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *service_count,
                           struct sysdb_attrs ***services,
                           size_t *servicegroup_count,
                           struct sysdb_attrs ***servicegroups)
{
    size_t c;
    struct ipa_hbac_service_state *state =
            tevent_req_data(req, struct ipa_hbac_service_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *service_count = state->service_count;
    *services = talloc_steal(mem_ctx, state->services);
    for (c = 0; c < state->service_count; c++) {
        /* Guarantee the memory heirarchy of the list */
        talloc_steal(state->services, state->services[c]);
    }

    *servicegroup_count = state->servicegroup_count;
    *servicegroups = talloc_steal(mem_ctx, state->servicegroups);

    return EOK;
}

errno_t
hbac_service_attrs_to_rule(TALLOC_CTX *mem_ctx,
                           struct sysdb_ctx *sysdb,
                           struct sss_domain_info *domain,
                           const char *rule_name,
                           struct sysdb_attrs *rule_attrs,
                           struct hbac_rule_element **services)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct hbac_rule_element *new_services;
    const char *attrs[] = { IPA_CN, NULL };
    struct ldb_message_element *el;
    size_t num_services = 0;
    size_t num_servicegroups = 0;
    size_t i;
    char *member_dn;
    char *filter;
    size_t count;
    struct ldb_message **msgs;
    const char *name;

    DEBUG(7, ("Processing PAM services for rule [%s]\n", rule_name));

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    new_services = talloc_zero(tmp_ctx, struct hbac_rule_element);
    if (new_services == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* First check for service category */
    ret = hbac_get_category(rule_attrs, IPA_SERVICE_CATEGORY,
                            &new_services->category);
    if (ret != EOK) {
        DEBUG(1, ("Could not identify service categories\n"));
        goto done;
    }
    if (new_services->category & HBAC_CATEGORY_ALL) {
        /* Short-cut to the exit */
        ret = EOK;
        goto done;
    }

    /* Get the list of DNs from the member attr */
    ret = sysdb_attrs_get_el(rule_attrs, IPA_MEMBER_SERVICE, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        goto done;
    }
    if (ret == ENOENT || el->num_values == 0) {
        el->num_values = 0;
        DEBUG(4, ("No services specified, rule will never apply.\n"));
    }

    /* Assume maximum size; We'll trim it later */
    new_services->names = talloc_array(new_services,
                                       const char *,
                                       el->num_values +1);
    if (new_services->names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    new_services->groups = talloc_array(new_services,
                                        const char *,
                                        el->num_values + 1);
    if (new_services->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < el->num_values; i++) {
        ret = sss_filter_sanitize(tmp_ctx,
                                  (const char *)el->values[i].data,
                                  &member_dn);
        if (ret != EOK) goto done;

        filter = talloc_asprintf(member_dn, "(%s=%s)",
                                 SYSDB_ORIG_DN, member_dn);
        if (filter == NULL) {
            ret = ENOMEM;
            goto done;
        }

        /* First check if this is a specific service */
        ret = sysdb_search_custom(tmp_ctx, sysdb, domain, filter,
                                  HBAC_SERVICES_SUBDIR, attrs,
                                  &count, &msgs);
        if (ret != EOK && ret != ENOENT) goto done;
        if (ret == EOK && count == 0) {
            ret = ENOENT;
        }

        if (ret == EOK) {
            if (count > 1) {
                DEBUG(1, ("Original DN matched multiple services. "
                          "Skipping \n"));
                talloc_zfree(member_dn);
                continue;
            }

            /* Original DN matched a single service. Get the service name */
            name = ldb_msg_find_attr_as_string(msgs[0], IPA_CN, NULL);
            if (name == NULL) {
                DEBUG(1, ("Attribute is missing!\n"));
                ret = EFAULT;
                goto done;
            }

            new_services->names[num_services] =
                    talloc_strdup(new_services->names, name);
            if (new_services->names[num_services] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            DEBUG(8, ("Added service [%s] to rule [%s]\n",
                      name, rule_name));
            num_services++;
        } else { /* ret == ENOENT */
            /* Check if this is a service group */
            ret = sysdb_search_custom(tmp_ctx, sysdb, domain, filter,
                                      HBAC_SERVICEGROUPS_SUBDIR, attrs,
                                      &count, &msgs);
            if (ret != EOK && ret != ENOENT) goto done;
            if (ret == EOK && count == 0) {
                ret = ENOENT;
            }

            if (ret == EOK) {
                if (count > 1) {
                    DEBUG(1, ("Original DN matched multiple service groups. "
                              "Skipping\n"));
                    talloc_zfree(member_dn);
                    continue;
                }

                /* Original DN matched a single group. Get the groupname */
                name = ldb_msg_find_attr_as_string(msgs[0], IPA_CN, NULL);
                if (name == NULL) {
                    DEBUG(1, ("Attribute is missing!\n"));
                    ret = EFAULT;
                    goto done;
                }

                new_services->groups[num_servicegroups] =
                        talloc_strdup(new_services->groups, name);
                if (new_services->groups[num_servicegroups] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }

                DEBUG(8, ("Added service group [%s] to rule [%s]\n",
                          name, rule_name));
                num_servicegroups++;
            } else { /* ret == ENOENT */
                /* Neither a service nor a service group? Skip it */
                DEBUG(1, ("[%s] does not map to either a service or "
                          "service group. Skipping\n", member_dn));
            }
        }
        talloc_zfree(member_dn);
    }
    new_services->names[num_services] = NULL;
    new_services->groups[num_servicegroups] = NULL;

    /* Shrink the arrays down to their real sizes */
    new_services->names = talloc_realloc(new_services, new_services->names,
                                         const char *, num_services + 1);
    if (new_services->names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    new_services->groups = talloc_realloc(new_services, new_services->groups,
                                          const char *, num_servicegroups + 1);
    if (new_services->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *services = talloc_steal(mem_ctx, new_services);
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
get_ipa_servicegroupname(TALLOC_CTX *mem_ctx,
                         struct sysdb_ctx *sysdb,
                         const char *service_dn,
                         char **servicegroupname)
{
    errno_t ret;
    struct ldb_dn *dn;
    const char *rdn_name;
    const char *svc_comp_name;
    const char *hbac_comp_name;
    const struct ldb_val *rdn_val;
    const struct ldb_val *svc_comp_val;
    const struct ldb_val *hbac_comp_val;

    /* This is an IPA-specific hack. It may not
     * work for non-IPA servers and will need to
     * be changed if SSSD ever supports HBAC on
     * a non-IPA server.
     */
    *servicegroupname = NULL;

    dn = ldb_dn_new(mem_ctx, sysdb_ctx_get_ldb(sysdb), service_dn);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (!ldb_dn_validate(dn)) {
        ret = EINVAL;
        goto done;
    }

    if (ldb_dn_get_comp_num(dn) < 4) {
        /* RDN, services, hbac, and at least one DC= */
        /* If it's fewer, it's not a group DN */
        ret = ENOENT;
        goto done;
    }

    /* If the RDN name is 'cn' */
    rdn_name = ldb_dn_get_rdn_name(dn);
    if (rdn_name == NULL) {
        /* Shouldn't happen if ldb_dn_validate()
         * passed, but we'll be careful.
         */
        ret = EINVAL;
        goto done;
    }

    if (strcasecmp("cn", rdn_name) != 0) {
        /* RDN has the wrong attribute name.
         * It's not a service.
         */
        ret = ENOENT;
        goto done;
    }

    /* and the second component is "cn=hbacservicegroups" */
    svc_comp_name = ldb_dn_get_component_name(dn, 1);
    if (strcasecmp("cn", svc_comp_name) != 0) {
        /* The second component name is not "cn" */
        ret = ENOENT;
        goto done;
    }

    svc_comp_val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp("hbacservicegroups",
                    (const char *) svc_comp_val->data,
                    svc_comp_val->length) != 0) {
        /* The second component value is not "hbacservicegroups" */
        ret = ENOENT;
        goto done;
    }

    /* and the third component is "hbac" */
    hbac_comp_name = ldb_dn_get_component_name(dn, 2);
    if (strcasecmp("cn", hbac_comp_name) != 0) {
        /* The third component name is not "cn" */
        ret = ENOENT;
        goto done;
    }

    hbac_comp_val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp("hbac",
                    (const char *) hbac_comp_val->data,
                    hbac_comp_val->length) != 0) {
        /* The third component value is not "hbac" */
        ret = ENOENT;
        goto done;
    }

    /* Then the value of the RDN is the group name */
    rdn_val = ldb_dn_get_rdn_val(dn);
    *servicegroupname = talloc_strndup(mem_ctx,
                                       (const char *)rdn_val->data,
                                       rdn_val->length);
    if (*servicegroupname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(dn);
    return ret;
}
