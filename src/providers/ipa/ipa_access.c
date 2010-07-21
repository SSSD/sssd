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

#include <sys/param.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_timerules.h"

#define OBJECTCLASS "objectclass"
#define IPA_MEMBEROF "memberOf"
#define IPA_HOST_SERVERHOSTNAME "serverHostName"
#define IPA_HOST_FQDN "fqdn"
#define IPA_ACCESS_RULE_TYPE "accessRuleType"
#define IPA_MEMBER_USER "memberUser"
#define IPA_USER_CATEGORY "userCategory"
#define IPA_SERVICE_NAME "serviceName"
#define IPA_SOURCE_HOST "sourceHost"
#define IPA_SOURCE_HOST_CATEGORY "sourceHostCategory"
#define IPA_EXTERNAL_HOST "externalHost"
#define IPA_ACCESS_TIME "accessTime"
#define IPA_UNIQUE_ID "ipauniqueid"
#define IPA_ENABLED_FLAG "ipaenabledflag"
#define IPA_MEMBER_HOST "memberHost"
#define IPA_HOST_CATEGORY "hostCategory"
#define IPA_CN "cn"
#define IPA_MEMBER_SERVICE "memberService"
#define IPA_SERVICE_CATEGORY "serviceCategory"

#define IPA_HOST_BASE_TMPL "cn=computers,cn=accounts,%s"
#define IPA_HBAC_BASE_TMPL "cn=hbac,%s"
#define IPA_SERVICES_BASE_TMPL "cn=hbacservices,cn=accounts,%s"

#define SYSDB_HBAC_BASE_TMPL "cn=hbac,"SYSDB_TMPL_CUSTOM_BASE

#define HBAC_RULES_SUBDIR "hbac_rules"
#define HBAC_HOSTS_SUBDIR "hbac_hosts"
#define HBAC_SERVICES_SUBDIR "hbac_services"

static errno_t msgs2attrs_array(TALLOC_CTX *mem_ctx, size_t count,
                                struct ldb_message **msgs,
                                struct sysdb_attrs ***attrs)
{
    int i;
    struct sysdb_attrs **a;

    a = talloc_array(mem_ctx, struct sysdb_attrs *, count);
    if (a == NULL) {
        DEBUG(1, ("talloc_array failed.\n"));
        return ENOMEM;
    }

    for (i = 0; i < count; i++) {
        a[i] = talloc(a, struct sysdb_attrs);
        if (a[i] == NULL) {
            DEBUG(1, ("talloc_array failed.\n"));
            talloc_free(a);
            return ENOMEM;
        }
        a[i]->num = msgs[i]->num_elements;
        a[i]->a = talloc_steal(a[i], msgs[i]->elements);
    }

    *attrs = a;

    return EOK;
}

static errno_t replace_attribute_name(const char *old_name,
                                      const char *new_name, const size_t count,
                                      struct sysdb_attrs **list)
{
    int ret;
    int i;

    for (i = 0; i < count; i++) {
        ret = sysdb_attrs_replace_name(list[i], old_name, new_name);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_replace_name failed.\n"));
            return ret;
        }
    }

    return EOK;
}

static errno_t hbac_sdap_data_recv(struct tevent_req *subreq,
                                   TALLOC_CTX *mem_ctx, size_t *count,
                                   struct sysdb_attrs ***attrs)
{
    int ret;

    ret = sdap_get_generic_recv(subreq, mem_ctx, count, attrs);
    if (ret != EOK) {
        DEBUG(1, ("sdap_get_generic_recv failed.\n"));
        return ret;
    }

    ret = replace_attribute_name(IPA_MEMBEROF, SYSDB_ORIG_MEMBEROF,
                                 *count, *attrs);
    if (ret != EOK) {
        DEBUG(1, ("replace_attribute_name failed.\n"));
        return ret;
    }

    return EOK;
}

static errno_t hbac_sysdb_data_recv(TALLOC_CTX *mem_ctx,
                                    struct sysdb_ctx *sysdb,
                                    struct sss_domain_info *domain,
                                    const char *filter,
                                    const char *subtree_name,
                                    const char **search_attrs,
                                    size_t *count,
                                    struct sysdb_attrs ***reply_attrs)
{
    int ret;
    struct ldb_message **msgs;

    ret = sysdb_search_custom(mem_ctx, sysdb, domain, filter, subtree_name,
                              search_attrs, count, &msgs);
    if (ret != EOK) {
        if (ret == ENOENT) {
            *count = 0;
            *reply_attrs = NULL;
            return EOK;
        }
        DEBUG(1, ("sysdb_search_custom failed.\n"));
        return ret;
    }

    ret = msgs2attrs_array(mem_ctx, *count, msgs, reply_attrs);
    talloc_zfree(msgs);
    if (ret != EOK) {
        DEBUG(1, ("msgs2attrs_array failed.\n"));
        return ret;
    }

    return EOK;
}

static void ipa_access_reply(struct hbac_ctx *hbac_ctx, int pam_status)
{
    struct be_req *be_req = hbac_ctx->be_req;
    struct pam_data *pd;
    pd = talloc_get_type(be_req->req_data, struct pam_data);
    pd->pam_status = pam_status;

    /* destroy HBAC context now to release all used resources and LDAP connection */
    talloc_zfree(hbac_ctx);

    if (pam_status == PAM_SUCCESS || pam_status == PAM_PERM_DENIED) {
        be_req->fn(be_req, DP_ERR_OK, pam_status, NULL);
    } else {
        be_req->fn(be_req, DP_ERR_FATAL, pam_status, NULL);
    }
}

struct hbac_get_service_data_state {
    struct hbac_ctx *hbac_ctx;
    const char *basedn;
    bool offline;

    char *services_filter;
    char *services_search_base;
    const char **services_attrs;
    struct sysdb_attrs **services_reply_list;
    size_t services_reply_count;

    size_t current_item;
};

static void hbac_services_get_done(struct tevent_req *subreq);

struct tevent_req *hbac_get_service_data_send(TALLOC_CTX *memctx,
                                              struct hbac_ctx *hbac_ctx,
                                              const char *basedn)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct hbac_get_service_data_state *state;
    struct sdap_handle *sdap_handle;
    int ret;

    req = tevent_req_create(memctx, &state, struct hbac_get_service_data_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->hbac_ctx = hbac_ctx;
    state->basedn = basedn;

    state->services_reply_list = NULL;
    state->services_reply_count = 0;

    state->current_item = 0;

    state->services_search_base = talloc_asprintf(state, IPA_SERVICES_BASE_TMPL,
                                              basedn);
    if (state->services_search_base == NULL) {
        DEBUG(1, ("Failed to create service search base.\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->services_attrs = talloc_array(state, const char *, 7);
    if (state->services_attrs == NULL) {
        DEBUG(1, ("Failed to allocate service attribute list.\n"));
        ret = ENOMEM;
        goto fail;
    }
    state->services_attrs[0] = IPA_CN;
    state->services_attrs[1] = SYSDB_ORIG_DN;
    state->services_attrs[2] = IPA_UNIQUE_ID;
    state->services_attrs[3] = IPA_MEMBEROF;
    state->services_attrs[4] = SYSDB_ORIG_MEMBEROF;
    state->services_attrs[5] = OBJECTCLASS;
    state->services_attrs[6] = NULL;

    state->services_filter = talloc_asprintf(state,
                                            "(objectclass=ipaHBACService)");
    if (state->services_filter == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(9, ("Services filter: [%s].\n", state->services_filter));

    if (hbac_ctx_is_offline(state->hbac_ctx)) {
        ret = hbac_sysdb_data_recv(state,
                                   hbac_ctx_sysdb(state->hbac_ctx),
                                   hbac_ctx_be(state->hbac_ctx)->domain,
                                   state->services_filter, HBAC_SERVICES_SUBDIR,
                                   state->services_attrs,
                                   &state->services_reply_count,
                                   &state->services_reply_list);
        if (ret) {
            DEBUG(1, ("hbac_sysdb_data_recv failed.\n"));
            goto fail;
        }

        tevent_req_done(req);
        tevent_req_post(req, hbac_ctx_ev(state->hbac_ctx));
        return req;
    }

    sdap_handle = sdap_id_op_handle(hbac_ctx_sdap_id_op(state->hbac_ctx));
    if (sdap_handle == NULL) {
        DEBUG(1, ("Bug: sdap_id_op is disconnected.\n"));
        ret = EIO;
        goto fail;
    }
    subreq = sdap_get_generic_send(state,
                                   hbac_ctx_ev(state->hbac_ctx),
                                   hbac_ctx_sdap_id_ctx(state->hbac_ctx)->opts,
                                   sdap_handle,
                                   state->services_search_base,
                                   LDAP_SCOPE_SUB,
                                   state->services_filter,
                                   state->services_attrs,
                                   NULL, 0);

    if (subreq == NULL) {
        DEBUG(1, ("sdap_get_generic_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, hbac_services_get_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, hbac_ctx_ev(state->hbac_ctx));
    return req;
}

static void hbac_services_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_service_data_state *state = tevent_req_data(req,
                                            struct hbac_get_service_data_state);
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    int ret;
    bool in_transaction = false;
    struct ldb_dn *base_dn;
    int i;
    struct ldb_message_element *el;
    char *object_name;


    ret = hbac_sdap_data_recv(subreq, state, &state->services_reply_count,
                              &state->services_reply_list);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->offline) {
        tevent_req_done(req);
        return;
    }

    sysdb = hbac_ctx_sysdb(state->hbac_ctx);
    domain = hbac_ctx_be(state->hbac_ctx)->domain;

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_transaction_start failed.\n"));
        tevent_req_error(req, ret);
        return;
    }
    in_transaction = true;

    base_dn = sysdb_custom_subtree_dn(sysdb, state,
                                      domain->name,
                                      HBAC_SERVICES_SUBDIR);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_delete_recursive(state, sysdb, base_dn, true);
    if (ret) {
        DEBUG(1, ("sysdb_delete_recursive failed.\n"));
        goto fail;
    }

    for (i = 0; i < state->services_reply_count; i++) {
        ret = sysdb_attrs_get_el(state->services_reply_list[i], IPA_UNIQUE_ID,
                                 &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto fail;
        }
        if (el->num_values == 0) {
            ret = EINVAL;
            goto fail;
        }
        object_name = talloc_strndup(state, (const char *)el->values[0].data,
                                     el->values[0].length);
        if (object_name == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        DEBUG(9, ("Object name: [%s].\n", object_name));

        ret = sysdb_store_custom(state, sysdb,
                                 domain, object_name,
                                 HBAC_SERVICES_SUBDIR,
                                 state->services_reply_list[i]);
        if (ret) {
            DEBUG(1, ("sysdb_store_custom failed.\n"));
            goto fail;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(1, ("sysdb_transaction_commit failed.\n"));
        goto fail;
    }
    in_transaction = false;

    tevent_req_done(req);
    return;

fail:
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }
    tevent_req_error(req, ret);
    return;
}

static int hbac_get_service_data_recv(struct tevent_req *req,
                                  TALLOC_CTX *memctx,
                                  size_t *hbac_services_count,
                                  struct sysdb_attrs ***hbac_services_list)
{
    struct hbac_get_service_data_state *state = tevent_req_data(req,
                                            struct hbac_get_service_data_state);
    int i;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *hbac_services_count = state->services_reply_count;
    *hbac_services_list = talloc_steal(memctx, state->services_reply_list);
    for (i = 0; i < state->services_reply_count; i++) {
        talloc_steal(memctx, state->services_reply_list[i]);
    }

    return EOK;
}

static int hbac_get_user_info(TALLOC_CTX *memctx,
                              struct be_ctx *be_ctx,
                              const char *user,
                              const char **user_dn,
                              size_t *groups_count,
                              const char ***_groups)
{
    TALLOC_CTX *tmpctx;
    const char *attrs[] = { SYSDB_ORIG_DN, NULL };
    struct ldb_message *user_msg;
    const char *user_orig_dn;
    struct ldb_message **msgs;
    size_t count;
    const char **groups;
    int ret;
    int i;

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sysdb_search_user_by_name(tmpctx, be_ctx->sysdb,
                                    be_ctx->domain, user, attrs, &user_msg);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(9, ("Found user info for user [%s].\n", user));
    user_orig_dn = ldb_msg_find_attr_as_string(user_msg, SYSDB_ORIG_DN, NULL);
    if (user_orig_dn == NULL) {
        DEBUG(1, ("Original DN of user [%s] not available.\n", user));
        ret = EINVAL;
        goto fail;
    }
    DEBUG(9, ("Found original DN [%s] for user [%s].\n",
              user_orig_dn, user));

    ret = sysdb_asq_search(tmpctx, be_ctx->sysdb, be_ctx->domain,
                           user_msg->dn, NULL, SYSDB_MEMBEROF, attrs,
                           &count, &msgs);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_asq_search on user %s failed.\n", user));
        goto fail;
    }

    if (count == 0) {
        *user_dn = talloc_strdup(memctx, user_orig_dn);
        if (*user_dn == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        *groups_count = 0;
        *_groups = NULL;
        talloc_zfree(tmpctx);
        return EOK;
    }

    groups = talloc_array(tmpctx, const char *, count);
    if (groups == NULL) {
        DEBUG(1, ("talloc_groups failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    for(i = 0; i < count; i++) {
        if (msgs[i]->num_elements != 1) {
            DEBUG(1, ("Unexpected number of elements.\n"));
            ret = EINVAL;
            goto fail;
        }

        if (msgs[i]->elements[0].num_values != 1) {
            DEBUG(1, ("Unexpected number of values.\n"));
            ret = EINVAL;
            goto fail;
        }

        groups[i] = talloc_strndup(groups,
                        (const char *)msgs[i]->elements[0].values[0].data,
                        msgs[i]->elements[0].values[0].length);
        if (groups[i] == NULL) {
            DEBUG(1, ("talloc_strndup failed.\n"));
            ret = ENOMEM;
            goto fail;
        }

        DEBUG(9, ("Found group [%s].\n", groups[i]));
    }

    *user_dn = talloc_strdup(memctx, user_orig_dn);
    if (*user_dn == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    *groups_count = count;
    *_groups = talloc_steal(memctx, groups);

    talloc_zfree(tmpctx);
    return EOK;

fail:
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
    talloc_zfree(tmpctx);
    return ret;
}


struct hbac_get_host_info_state {
    struct hbac_ctx *hbac_ctx;

    char *host_filter;
    char *host_search_base;
    const char **host_attrs;

    struct sysdb_attrs **host_reply_list;
    size_t host_reply_count;
    size_t current_item;
    struct hbac_host_info **hbac_host_info;
};

static void hbac_get_host_memberof(struct tevent_req *req, bool offline);
static void hbac_get_host_memberof_done(struct tevent_req *subreq);

static struct tevent_req *hbac_get_host_info_send(TALLOC_CTX *memctx,
                                                  struct hbac_ctx *hbac_ctx,
                                                  const char *basedn,
                                                  const char **hostnames)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct hbac_get_host_info_state *state;
    struct sdap_handle *sdap_handle;
    int ret;
    int i;

    if (hostnames == NULL || basedn == NULL) {
        DEBUG(1, ("Missing hostnames or domain.\n"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct hbac_get_host_info_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->hbac_ctx = hbac_ctx;

    state->host_reply_list = NULL;
    state->host_reply_count = 0;
    state->current_item = 0;
    state->hbac_host_info = NULL;

    state->host_filter = talloc_asprintf(state, "(|");
    if (state->host_filter == NULL) {
        DEBUG(1, ("Failed to create filter.\n"));
        ret = ENOMEM;
        goto fail;
    }
    for (i = 0; hostnames[i] != NULL; i++) {
        state->host_filter = talloc_asprintf_append(state->host_filter,
                                             "(&(objectclass=ipaHost)"
                                             "(|(fqdn=%s)(serverhostname=%s)))",
                                             hostnames[i], hostnames[i]);
        if (state->host_filter == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }
    state->host_filter = talloc_asprintf_append(state->host_filter, ")");
    if (state->host_filter == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    state->host_search_base = talloc_asprintf(state, IPA_HOST_BASE_TMPL,
                                              basedn);
    if (state->host_search_base == NULL) {
        DEBUG(1, ("Failed to create host search base.\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->host_attrs = talloc_array(state, const char *, 7);
    if (state->host_attrs == NULL) {
        DEBUG(1, ("Failed to allocate host attribute list.\n"));
        ret = ENOMEM;
        goto fail;
    }
    state->host_attrs[0] = IPA_MEMBEROF;
    state->host_attrs[1] = IPA_HOST_SERVERHOSTNAME;
    state->host_attrs[2] = IPA_HOST_FQDN;
    state->host_attrs[3] = "objectClass";
    state->host_attrs[4] = SYSDB_ORIG_DN;
    state->host_attrs[5] = SYSDB_ORIG_MEMBEROF;
    state->host_attrs[6] = NULL;

    if (hbac_ctx_is_offline(state->hbac_ctx)) {
        ret = hbac_sysdb_data_recv(state, hbac_ctx_sysdb(state->hbac_ctx),
                                   hbac_ctx_be(state->hbac_ctx)->domain,
                                   state->host_filter, HBAC_HOSTS_SUBDIR,
                                   state->host_attrs,
                                   &state->host_reply_count,
                                   &state->host_reply_list);
        if (ret) {
            DEBUG(1, ("hbac_sysdb_data_recv failed.\n"));
            goto fail;
        }
        hbac_get_host_memberof(req, true);
        tevent_req_post(req, hbac_ctx_ev(state->hbac_ctx));
        return req;
    }

    sdap_handle = sdap_id_op_handle(hbac_ctx_sdap_id_op(state->hbac_ctx));
    if (sdap_handle == NULL) {
        DEBUG(1, ("Bug: sdap_id_op is disconnected.\n"));
        ret = EIO;
        goto fail;
    }
    subreq = sdap_get_generic_send(state, hbac_ctx_ev(state->hbac_ctx),
                                   hbac_ctx_sdap_id_ctx(state->hbac_ctx)->opts,
                                   sdap_handle,
                                   state->host_search_base,
                                   LDAP_SCOPE_SUB,
                                   state->host_filter,
                                   state->host_attrs,
                                   NULL, 0);

    if (subreq == NULL) {
        DEBUG(1, ("sdap_get_generic_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, hbac_get_host_memberof_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, hbac_ctx_ev(state->hbac_ctx));
    return req;
}

static void hbac_get_host_memberof_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_host_info_state *state = tevent_req_data(req,
                                               struct hbac_get_host_info_state);
    int ret;

    ret = hbac_sdap_data_recv(subreq, state, &state->host_reply_count,
                              &state->host_reply_list);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    hbac_get_host_memberof(req, false);
}

static bool hbac_is_known_host(struct hbac_host_info **hhi, const char *fqdn)
{
    if (!hhi || !fqdn) {
        return false;
    }

    int i;
    for (i = 0; hhi[i] != NULL; i++) {
        if(strcmp(hhi[i]->fqdn, fqdn) == 0) {
            return true;
        }
    }

    return false;
}

static void hbac_get_host_memberof(struct tevent_req *req, bool offline)
{
    struct hbac_get_host_info_state *state =
                    tevent_req_data(req, struct hbac_get_host_info_state);
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    bool in_transaction = false;
    int ret;
    int i;
    struct ldb_message_element *el;
    struct hbac_host_info **hhi;
    char *object_name;
    const char *fqdn_attrs[] = { IPA_HOST_FQDN, NULL };
    const char *fqdn;

    size_t cached_count;
    struct ldb_message **cached_entries = 0;

    hhi = talloc_array(state, struct hbac_host_info *, state->host_reply_count + 1);
    if (hhi == NULL) {
        DEBUG(1, ("talloc_array failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    memset(hhi, 0,
           sizeof(struct hbac_host_info *) * (state->host_reply_count + 1));

    if (state->host_reply_count == 0) {
        DEBUG(1, ("No hosts not found in IPA server.\n"));
    }

    for (i = 0; i < state->host_reply_count; i++) {
        hhi[i] = talloc_zero(hhi, struct hbac_host_info);
        if (hhi[i] == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        ret = sysdb_attrs_get_el(state->host_reply_list[i], SYSDB_ORIG_DN, &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto fail;
        }
        if (el->num_values == 0) {
            ret = EINVAL;
            goto fail;
        }
        DEBUG(9, ("OriginalDN: [%.*s].\n", el->values[0].length,
                                           (char *)el->values[0].data));
        hhi[i]->dn = talloc_strndup(hhi, (char *)el->values[0].data,
                                   el->values[0].length);
        if (hhi[i]->dn == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        ret = sysdb_attrs_get_el(state->host_reply_list[i],
                                 IPA_HOST_SERVERHOSTNAME, &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto fail;
        }
        if (el->num_values == 0) {
            ret = EINVAL;
            goto fail;
        }
        DEBUG(9, ("ServerHostName: [%.*s].\n", el->values[0].length,
                                               (char *)el->values[0].data));
        hhi[i]->serverhostname = talloc_strndup(hhi, (char *)el->values[0].data,
                                               el->values[0].length);
        if (hhi[i]->serverhostname == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        ret = sysdb_attrs_get_el(state->host_reply_list[i],
                                 IPA_HOST_FQDN, &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto fail;
        }
        if (el->num_values == 0) {
            ret = EINVAL;
            goto fail;
        }
        DEBUG(9, ("FQDN: [%.*s].\n", el->values[0].length,
                                     (char *)el->values[0].data));
        hhi[i]->fqdn = talloc_strndup(hhi, (char *)el->values[0].data,
                                               el->values[0].length);
        if (hhi[i]->fqdn == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        ret = sysdb_attrs_get_string_array(state->host_reply_list[i],
                                          offline ? SYSDB_ORIG_MEMBEROF :
                                                    IPA_MEMBEROF,
                                          hhi, &(hhi[i]->memberof));
        if (ret != EOK) {
            if (ret != ENOENT) {
                DEBUG(1, ("sysdb_attrs_get_string_array failed.\n"));
                goto fail;
            }

            hhi[i]->memberof = talloc_array(hhi, const char *, 1);
            if (hhi[i]->memberof == NULL) {
                DEBUG(1, ("talloc_array failed.\n"));
                ret = ENOMEM;
                goto fail;
            }
            hhi[i]->memberof[0] = NULL;
        }
    }

    state->hbac_host_info = hhi;

    if (offline) {
        tevent_req_done(req);
        return;
    }

    sysdb = hbac_ctx_sysdb(state->hbac_ctx);
    domain = hbac_ctx_be(state->hbac_ctx)->domain;

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    in_transaction = true;

    ret = sysdb_search_custom(state, sysdb, domain,
                              state->host_filter, HBAC_HOSTS_SUBDIR,
                              fqdn_attrs,
                              &cached_count,
                              &cached_entries);

    if (ret == ENOENT) {
        cached_count = 0;
        ret = EOK;
    }

    if (ret) {
        DEBUG(1, ("sysdb_search_custom failed: [%d](%s)\n", ret, strerror(ret)));
        goto fail;
    }

    for (i = 0; i < cached_count; i++) {
        fqdn = ldb_msg_find_attr_as_string(cached_entries[i], IPA_HOST_FQDN, NULL);
        if (!fqdn) {
            DEBUG(1, ("missing FQDN in cached HBAC host record\n"));
        } else if (hbac_is_known_host(hhi, fqdn)) {
            continue;
        } else {
            DEBUG(9, ("deleting obsolete HBAC host record for %s\n", fqdn));
        }

        ret = sysdb_delete_entry(sysdb, cached_entries[i]->dn, true);
        if (ret) {
            DEBUG(1, ("sysdb_delete_entry failed: [%d](%s)\n", ret, strerror(ret)));
            goto fail;
        }
    }

    talloc_zfree(cached_entries);

    for (i = 0; i < state->host_reply_count; i++) {

        ret = sysdb_attrs_get_el(state->host_reply_list[i],
                                 IPA_HOST_FQDN, &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto fail;
        }
        if (el->num_values == 0) {
            ret = EINVAL;
            goto fail;
        }
        object_name = talloc_strndup(state, (const char *)el->values[0].data,
                                     el->values[0].length);
        if (object_name == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        DEBUG(9, ("Fqdn [%s].\n", object_name));

        ret = sysdb_store_custom(state, sysdb,
                                 domain,
                                 object_name,
                                 HBAC_HOSTS_SUBDIR,
                                 state->host_reply_list[i]);

        if (ret) {
            DEBUG(1, ("sysdb_store_custom failed.\n"));
            goto fail;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(1, ("sysdb_transaction_commit failed.\n"));
        goto fail;
    }
    in_transaction = false;

    tevent_req_done(req);
    return;

fail:
    talloc_zfree(cached_entries);

    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }
    tevent_req_error(req, ret);
    return;
}

static int hbac_get_host_info_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                                   struct hbac_host_info ***hhi)
{
    struct hbac_get_host_info_state *state = tevent_req_data(req,
                                               struct hbac_get_host_info_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *hhi = talloc_steal(memctx, state->hbac_host_info);
    return EOK;
}


struct hbac_get_rules_state {
    struct hbac_ctx *hbac_ctx;

    const char *host_dn;
    const char **memberof;
    char *hbac_filter;
    char *hbac_search_base;
    const char **hbac_attrs;

    struct ldb_message *old_rules;
    struct sysdb_attrs **hbac_reply_list;
    size_t hbac_reply_count;
    int current_item;
};

static void hbac_rule_get(struct tevent_req *req, bool offline);
static void hbac_rule_get_done(struct tevent_req *subreq);

static struct tevent_req *hbac_get_rules_send(TALLOC_CTX *memctx,
                                              struct hbac_ctx *hbac_ctx,
                                              const char *basedn,
                                              const char *host_dn,
                                              const char **memberof)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct hbac_get_rules_state *state;
    struct sdap_handle *sdap_handle;
    int ret;
    int i;

    if (host_dn == NULL || basedn == NULL) {
        DEBUG(1, ("Missing host_dn or domain.\n"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct hbac_get_rules_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->hbac_ctx = hbac_ctx;
    state->host_dn = host_dn;
    state->memberof = memberof;

    state->old_rules = NULL;
    state->hbac_reply_list = NULL;
    state->hbac_reply_count = 0;
    state->current_item = 0;

    state->hbac_search_base = talloc_asprintf(state, IPA_HBAC_BASE_TMPL,
                                              basedn);
    if (state->hbac_search_base == NULL) {
        DEBUG(1, ("Failed to create HBAC search base.\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->hbac_attrs = talloc_array(state, const char *, 18);
    if (state->hbac_attrs == NULL) {
        DEBUG(1, ("Failed to allocate HBAC attribute list.\n"));
        ret = ENOMEM;
        goto fail;
    }
    state->hbac_attrs[0] = IPA_ACCESS_RULE_TYPE;
    state->hbac_attrs[1] = IPA_MEMBER_USER;
    state->hbac_attrs[2] = IPA_USER_CATEGORY;
    state->hbac_attrs[3] = IPA_SERVICE_NAME;
    state->hbac_attrs[4] = IPA_SOURCE_HOST;
    state->hbac_attrs[5] = IPA_SOURCE_HOST_CATEGORY;
    state->hbac_attrs[6] = IPA_EXTERNAL_HOST;
    state->hbac_attrs[7] = IPA_ACCESS_TIME;
    state->hbac_attrs[8] = IPA_UNIQUE_ID;
    state->hbac_attrs[9] = IPA_ENABLED_FLAG;
    state->hbac_attrs[10] = IPA_CN;
    state->hbac_attrs[11] = OBJECTCLASS;
    state->hbac_attrs[12] = IPA_MEMBER_HOST;
    state->hbac_attrs[13] = IPA_HOST_CATEGORY;
    state->hbac_attrs[14] = IPA_MEMBER_SERVICE;
    state->hbac_attrs[15] = IPA_SERVICE_CATEGORY;
    state->hbac_attrs[16] = SYSDB_ORIG_DN;
    state->hbac_attrs[17] = NULL;

    state->hbac_filter = talloc_asprintf(state,
                                         "(&(objectclass=ipaHBACRule)"
                                           "(|(%s=%s)(%s=%s)",
                                         IPA_HOST_CATEGORY, "all",
                                         IPA_MEMBER_HOST, host_dn);
    if (state->hbac_filter == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    for (i = 0; memberof[i] != NULL; i++) {
        state->hbac_filter = talloc_asprintf_append(state->hbac_filter,
                                                    "(%s=%s)",
                                                    IPA_MEMBER_HOST,
                                                    memberof[i]);
        if (state->hbac_filter == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }
    state->hbac_filter = talloc_asprintf_append(state->hbac_filter, "))");
    if (state->hbac_filter == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(9, ("HBAC rule filter: [%s].\n", state->hbac_filter));

    if (hbac_ctx_is_offline(state->hbac_ctx)) {
        ret = hbac_sysdb_data_recv(state, hbac_ctx_sysdb(state->hbac_ctx),
                                   hbac_ctx_be(state->hbac_ctx)->domain,
                                   state->hbac_filter, HBAC_RULES_SUBDIR,
                                   state->hbac_attrs,
                                   &state->hbac_reply_count,
                                   &state->hbac_reply_list);
        if (ret) {
            DEBUG(1, ("hbac_sysdb_data_recv failed.\n"));
            goto fail;
        }
        hbac_rule_get(req, true);
        tevent_req_post(req, hbac_ctx_ev(state->hbac_ctx));
        return req;
    }

    sdap_handle = sdap_id_op_handle(hbac_ctx_sdap_id_op(state->hbac_ctx));
    if (sdap_handle == NULL) {
        DEBUG(1, ("Bug: sdap_id_op is disconnected.\n"));
        ret = EIO;
        goto fail;
    }
    subreq = sdap_get_generic_send(state, hbac_ctx_ev(state->hbac_ctx),
                                   hbac_ctx_sdap_id_ctx(state->hbac_ctx)->opts,
                                   sdap_handle,
                                   state->hbac_search_base,
                                   LDAP_SCOPE_SUB,
                                   state->hbac_filter,
                                   state->hbac_attrs,
                                   NULL, 0);

    if (subreq == NULL) {
        DEBUG(1, ("sdap_get_generic_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, hbac_rule_get_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, hbac_ctx_ev(state->hbac_ctx));
    return req;
}

static void hbac_rule_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);
    int ret;

    ret = hbac_sdap_data_recv(subreq, state, &state->hbac_reply_count,
                              &state->hbac_reply_list);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    hbac_rule_get(req, false);
}

static void hbac_rule_get(struct tevent_req *req, bool offline)
{
    struct hbac_get_rules_state *state =
                        tevent_req_data(req, struct hbac_get_rules_state);
    bool in_transaction = false;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    int ret;
    int i;
    struct ldb_message_element *el;
    struct ldb_dn *hbac_base_dn;
    char *object_name;

    for (i = 0; i < state->hbac_reply_count; i++) {
        ret = sysdb_attrs_get_el(state->hbac_reply_list[i], SYSDB_ORIG_DN, &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto fail;
        }
        if (el->num_values == 0) {
            DEBUG(1, ("Missing original DN.\n"));
            ret = EINVAL;
            goto fail;
        }
        DEBUG(9, ("OriginalDN: [%s].\n", (const char *)el->values[0].data));
    }

    if (offline) {
        tevent_req_done(req);
        return;
    }

    sysdb = hbac_ctx_sysdb(state->hbac_ctx);
    domain = hbac_ctx_be(state->hbac_ctx)->domain;

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    in_transaction = true;

    hbac_base_dn = sysdb_custom_subtree_dn(sysdb, state,
                                           domain->name,
                                           HBAC_RULES_SUBDIR);
    if (hbac_base_dn == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    ret = sysdb_delete_recursive(state, sysdb, hbac_base_dn, true);
    if (ret) {
        DEBUG(1, ("sysdb_delete_recursive_send failed.\n"));
        goto fail;
    }


    for (i = 0; i < state->hbac_reply_count; i++) {

        ret = sysdb_attrs_get_el(state->hbac_reply_list[i],
                                 IPA_UNIQUE_ID, &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto fail;
        }
        if (el->num_values == 0) {
            ret = EINVAL;
            goto fail;
        }
        object_name = talloc_strndup(state, (const char *)el->values[0].data,
                                     el->values[0].length);
        if (object_name == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        DEBUG(9, ("IPAUniqueId: [%s].\n", object_name));

        ret = sysdb_store_custom(state, sysdb,
                                 domain,
                                 object_name,
                                 HBAC_RULES_SUBDIR,
                                 state->hbac_reply_list[i]);

        if (ret) {
            DEBUG(1, ("sysdb_store_custom_send failed.\n"));
            goto fail;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(1, ("sysdb_transaction_commit failed.\n"));
        goto fail;
    }
    in_transaction = false;

    tevent_req_done(req);
    return;

fail:
    if (in_transaction) {
        sysdb_transaction_cancel(sysdb);
    }
    tevent_req_error(req, ret);
    return;
}

static int hbac_get_rules_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                               size_t *hbac_rule_count,
                               struct sysdb_attrs ***hbac_rule_list)
{
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *hbac_rule_count = state->hbac_reply_count;
    *hbac_rule_list = talloc_steal(memctx, state->hbac_reply_list);
    /* we do not need to steal each hbac_reply_list[i]
     * as it belongs to hbac_reply_list memory block */
    return EOK;
}

enum hbac_result {
    HBAC_ALLOW = 1,
    HBAC_DENY,
    HBAC_NOT_APPLICABLE
};

enum check_result {
    RULE_APPLICABLE = 0,
    RULE_NOT_APPLICABLE,
    RULE_ERROR
};

static errno_t get_service_data(const char *cn, size_t count,
                                struct sysdb_attrs **list, const char **dn,
                                struct ldb_message_element **mof)
{
    int ret;
    int i;
    int j;
    struct ldb_message_element *el;

    for (i = 0; i < count; i++) {
        ret = sysdb_attrs_get_el(list[i], IPA_CN, &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            return ENOENT;
        }
        if (el->num_values == 0) {
            DEBUG(9, ("No cn found.\n"));
            return ENOENT;
        } else {
            for (j = 0; j < el->num_values; j++) {
                if (strlen(cn) == el->values[j].length &&
                    strncmp(cn, (const char *) el->values[j].data,
                            el->values[j].length) == 0) {

                    ret = sysdb_attrs_get_string(list[i], SYSDB_ORIG_DN, dn);
                    if (ret != EOK) {
                        DEBUG(1, ("sysdb_attrs_get_string failed.\n"));
                        return ret;
                    }

                    ret = sysdb_attrs_get_el(list[i], SYSDB_ORIG_MEMBEROF, mof);
                    if (ret != EOK) {
                        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
                        return ret;
                    }

                    return EOK;
                }
            }
        }
    }

    return ENOENT;
}

enum check_result check_service(struct hbac_ctx *hbac_ctx,
                                struct sysdb_attrs *rule_attrs)
{
    int ret;
    int i;
    int g;
    struct ldb_message_element *el;
    const char *service_dn;
    struct ldb_message_element *service_memberof;

    if (hbac_ctx->pd->service == NULL) {
        DEBUG(1, ("No service in pam data, assuming error.\n"));
        return RULE_ERROR;
    }

    ret = sysdb_attrs_get_el(rule_attrs, IPA_SERVICE_CATEGORY, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }
    if (el->num_values == 0) {
        DEBUG(9, ("Service category is not set.\n"));
    } else {
        for (i = 0; i < el->num_values; i++) {
            if (strncasecmp("all", (const char *) el->values[i].data,
                            el->values[i].length) == 0) {
                DEBUG(9, ("Service category is set to 'all', rule applies.\n"));
                return RULE_APPLICABLE;
            }
            DEBUG(9, ("Unsupported service category [%.*s].\n",
                      el->values[i].length,
                      (char *) el->values[i].data));
        }
    }

    ret = get_service_data(hbac_ctx->pd->service, hbac_ctx->hbac_services_count,
                           hbac_ctx->hbac_services_list, &service_dn,
                           &service_memberof);
    if (ret != EOK) {
        DEBUG(1, ("Cannot find original DN for service [%s].\n",
                  hbac_ctx->pd->service));
        return RULE_ERROR;
    }
    DEBUG(9, ("OriginalDN for service [%s]: [%s].\n", hbac_ctx->pd->service,
              service_dn));

    ret = sysdb_attrs_get_el(rule_attrs, IPA_MEMBER_SERVICE, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }
    if (el->num_values == 0) {
        DEBUG(9, ("No service or service group specified, rule does not apply.\n"));
        return RULE_NOT_APPLICABLE;
    }

    for (i = 0; i < el->num_values; i++) {
        if (strncmp(service_dn, (const char *) el->values[i].data,
                    el->values[i].length) == 0) {
            DEBUG(9, ("Service [%s] found in the list of allowed "
                      "services.\n", hbac_ctx->pd->service));
            return RULE_APPLICABLE;
        }

        for (g = 0; g < service_memberof->num_values; g++) {
            if (service_memberof->values[g].length == el->values[i].length &&
                strncmp((const char *) service_memberof->values[g].data,
                        (const char *) el->values[i].data,
                        el->values[i].length) == 0) {
                DEBUG(9, ("Service [%s] is a member of a group in the list of "
                          "allowed service groups.\n", hbac_ctx->pd->service));
                return RULE_APPLICABLE;
            }
        }
    }

    DEBUG(9, ("Service [%s] was not found in the list of allowed services and "
              "service groups.\n", hbac_ctx->pd->service));
    return RULE_NOT_APPLICABLE;
}

enum check_result check_access_time(struct time_rules_ctx *tr_ctx,
                                    struct sysdb_attrs *rule_attrs)
{
    int ret;
    int i;
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message_element *el;
    char *rule;
    time_t now;
    bool result;

    now = time(NULL);
    if (now == (time_t) -1) {
        DEBUG(1, ("time failed [%d][%s].\n", errno, strerror(errno)));
        return RULE_ERROR;
    }

    ret = sysdb_attrs_get_el(rule_attrs, IPA_ACCESS_TIME, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }
    if (el->num_values == 0) {
        DEBUG(9, ("No access time specified, assuming rule applies.\n"));
        return RULE_APPLICABLE;
    } else {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(1, ("talloc_new failed.\n"));
            return RULE_ERROR;
        }

        for (i = 0; i < el->num_values; i++) {
            rule = talloc_strndup(tmp_ctx, (const char *) el->values[i].data,
                                  el->values[i].length);
            ret = check_time_rule(tmp_ctx, tr_ctx, rule, now, &result);
            if (ret != EOK) {
                DEBUG(1, ("check_time_rule failed.\n"));
                ret = RULE_ERROR;
                goto done;
            }

            if (result) {
                DEBUG(9, ("Current time [%d] matches rule [%s].\n", now, rule));
                ret = RULE_APPLICABLE;
                goto done;
            }
        }
    }

    ret = RULE_NOT_APPLICABLE;

done:
    talloc_free(tmp_ctx);
    return ret;
}

enum check_result check_user(struct hbac_ctx *hbac_ctx,
                             struct sysdb_attrs *rule_attrs)
{
    int ret;
    int i;
    int g;
    struct ldb_message_element *el;

    if (hbac_ctx->user_dn == NULL) {
        DEBUG(1, ("No user DN available, this should never happen.\n"));
        return RULE_ERROR;
    }

    ret = sysdb_attrs_get_el(rule_attrs, IPA_USER_CATEGORY, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }
    if (el->num_values == 0) {
        DEBUG(9, ("User category is not set.\n"));
    } else {
        for (i = 0; i < el->num_values; i++) {
            if (strncasecmp("all", (const char *) el->values[i].data,
                            el->values[i].length) == 0) {
                DEBUG(9, ("User category is set to 'all', rule applies.\n"));
                return RULE_APPLICABLE;
            }
            DEBUG(9, ("Unsupported user category [%.*s].\n",
                      el->values[i].length,
                      (char *) el->values[i].data));
        }
    }

    ret = sysdb_attrs_get_el(rule_attrs, IPA_MEMBER_USER, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }
    if (el->num_values == 0) {
        DEBUG(9, ("No user specified, rule does not apply.\n"));
        return RULE_NOT_APPLICABLE;
    } else {
        for (i = 0; i < el->num_values; i++) {
            DEBUG(9, ("Searching matches for [%.*s].\n", el->values[i].length,
                                           (const char *) el->values[i].data));
            DEBUG(9, ("Checking user [%s].\n", hbac_ctx->user_dn));
            if (strncmp(hbac_ctx->user_dn, (const char *) el->values[i].data,
                       el->values[i].length) == 0) {
                DEBUG(9, ("User [%s] found, rule applies.\n",
                          hbac_ctx->user_dn));
                return RULE_APPLICABLE;
            }

            for (g = 0; g < hbac_ctx->groups_count; g++) {
                DEBUG(9, ("Checking group [%s].\n", hbac_ctx->groups[g]));
                if (strncmp(hbac_ctx->groups[g],
                           (const char *) el->values[i].data,
                           el->values[i].length) == 0) {
                    DEBUG(9, ("Group [%s] found, rule applies.\n",
                              hbac_ctx->groups[g]));
                    return RULE_APPLICABLE;
                }
            }
        }
        DEBUG(9, ("No matching user found, rule does not apply.\n"));
        return RULE_NOT_APPLICABLE;
    }

    return RULE_ERROR;
}

enum check_result check_remote_hosts(const char *rhost,
                                     struct hbac_host_info *hhi,
                                     struct sysdb_attrs *rule_attrs)
{
    int ret;
    int i;
    int m;
    struct ldb_message_element *cat_el;
    struct ldb_message_element *src_el;
    struct ldb_message_element *ext_el;

    if (hhi == NULL && (rhost == NULL || *rhost == '\0')) {
        DEBUG(1, ("No remote host information specified, assuming error.\n"));
        return RULE_ERROR;
    }

    ret = sysdb_attrs_get_el(rule_attrs, IPA_SOURCE_HOST_CATEGORY, &cat_el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }
    if (cat_el->num_values == 0) {
        DEBUG(9, ("Source host category not set.\n"));
    } else {
        for(i = 0; i < cat_el->num_values; i++) {
            if (strncasecmp("all", (const char *) cat_el->values[i].data,
                            cat_el->values[i].length) == 0) {
                DEBUG(9, ("Source host category is set to 'all', "
                          "rule applies.\n"));
                return RULE_APPLICABLE;
            }
            DEBUG(9, ("Unsupported source hosts category [%.*s].\n",
                      cat_el->values[i].length,
                      (char *) cat_el->values[i].data));
        }
    }

    ret = sysdb_attrs_get_el(rule_attrs, IPA_SOURCE_HOST, &src_el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }
    ret = sysdb_attrs_get_el(rule_attrs, IPA_EXTERNAL_HOST, &ext_el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }

    if (src_el->num_values == 0 && ext_el->num_values == 0) {
        DEBUG(9, ("No remote host specified in rule, rule does not apply.\n"));
        return RULE_NOT_APPLICABLE;
    } else {
        if (hhi != NULL) {
            for (i = 0; i < src_el->num_values; i++) {
                if (strncasecmp(hhi->dn, (const char *) src_el->values[i].data,
                                src_el->values[i].length) == 0) {
                    DEBUG(9, ("Source host [%s] found, rule applies.\n",
                              hhi->dn));
                    return RULE_APPLICABLE;
                }
                for (m = 0; hhi->memberof[m] != NULL; m++) {
                    if (strncasecmp(hhi->memberof[m],
                                    (const char *) src_el->values[i].data,
                                    src_el->values[i].length) == 0) {
                        DEBUG(9, ("Source host group [%s] found, rule applies.\n",
                                  hhi->memberof[m]));
                        return RULE_APPLICABLE;
                    }
                }
            }
        }

        if (rhost != NULL && *rhost != '\0') {
            for (i = 0; i < ext_el->num_values; i++) {
                if (strncasecmp(rhost, (const char *) ext_el->values[i].data,
                                ext_el->values[i].length) == 0) {
                    DEBUG(9, ("External host [%s] found, rule applies.\n",
                              rhost));
                    return RULE_APPLICABLE;
                }
            }
        }
        DEBUG(9, ("No matching remote host found.\n"));
        return RULE_NOT_APPLICABLE;
    }

    return RULE_ERROR;
}

static errno_t check_if_rule_applies(struct hbac_ctx *hbac_ctx,
                                     struct sysdb_attrs *rule_attrs,
                                     enum hbac_result *result) {
    int ret;
    struct ldb_message_element *el;
    enum hbac_result rule_type;
    char *rule_name;
    struct pam_data *pd = hbac_ctx->pd;

    ret = sysdb_attrs_get_el(rule_attrs, IPA_CN, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return ret;
    }
    if (el->num_values == 0) {
        DEBUG(4, ("rule has no name, assuming '(none)'.\n"));
        rule_name = talloc_strdup(rule_attrs, "(none)");
    } else {
        rule_name = talloc_strndup(rule_attrs, (const char*) el->values[0].data,
                                   el->values[0].length);
    }
    if (rule_name == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        return ENOMEM;
    }
    DEBUG(9, ("Processsing rule [%s].\n", rule_name));

    ret = sysdb_attrs_get_el(rule_attrs, IPA_ENABLED_FLAG, &el);
    if (ret != EOK) {
        DEBUG(1, ("Failed to find out if rule is enabled or not, "
                  "assuming it is enabled.\n"));
    } else {
        if (el->num_values == 0) {
            DEBUG(1, ("Failed to find out if rule is enabled or not, "
                      "assuming it is enabled.\n"));
        } else {
            if (strncasecmp("false", (const char*) el->values[0].data,
                            el->values[0].length) == 0) {
                DEBUG(7, ("Rule is disabled.\n"));
                *result = HBAC_NOT_APPLICABLE;
                return EOK;
            }
        }
    }

    /* rule type */
    ret = sysdb_attrs_get_el(rule_attrs, IPA_ACCESS_RULE_TYPE, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return ret;
    }
    if (el->num_values == 0) {
        DEBUG(4, ("rule has no type, assuming 'deny'.\n"));
        rule_type = HBAC_DENY;
    } else if (el->num_values == 1) {
        if (strncasecmp((const char *) el->values[0].data, "allow",
                        el->values[0].length) == 0) {
            rule_type = HBAC_ALLOW;
        } else {
            rule_type = HBAC_DENY;
        }
    } else {
        DEBUG(1, ("rule has an unsupported number of values [%d].\n",
                  el->num_values));
        return EINVAL;
    }

    ret = check_service(hbac_ctx, rule_attrs);
    if (ret != RULE_APPLICABLE) {
        goto not_applicable;
    }

    ret = check_user(hbac_ctx, rule_attrs);
    if (ret != RULE_APPLICABLE) {
        goto not_applicable;
    }

    ret = check_access_time(hbac_ctx->tr_ctx, rule_attrs);
    if (ret != RULE_APPLICABLE) {
        goto not_applicable;
    }

    ret = check_remote_hosts(pd->rhost, hbac_ctx->remote_hhi, rule_attrs);
    if (ret != RULE_APPLICABLE) {
        goto not_applicable;
    }

    *result = rule_type;

    return EOK;

not_applicable:
    if (ret == RULE_NOT_APPLICABLE) {
        *result = HBAC_NOT_APPLICABLE;
    } else {
        *result = HBAC_DENY;
    }
    return EOK;
}

static int evaluate_ipa_hbac_rules(struct hbac_ctx *hbac_ctx,
                                   bool *access_allowed)
{
    bool allow_matched = false;
    enum hbac_result result;
    int ret;
    int i;

    *access_allowed = false;

    for (i = 0; i < hbac_ctx->hbac_rule_count ; i++) {

        ret = check_if_rule_applies(hbac_ctx, hbac_ctx->hbac_rule_list[i],
                                    &result);
        if (ret != EOK) {
            DEBUG(1, ("check_if_rule_applies failed.\n"));
            return ret;
        }

        switch (result) {
            case HBAC_DENY:
                DEBUG(3, ("Access denied by single rule.\n"));
                return EOK;
                break;
            case HBAC_ALLOW:
                allow_matched = true;
                DEBUG(9, ("Current rule allows access.\n"));
                break;
            default:
                DEBUG(9, ("Current rule does not apply.\n"));
        }

    }

    *access_allowed = allow_matched;

    return EOK;
}

static int hbac_retry(struct hbac_ctx *hbac_ctx);
static void hbac_connect_done(struct tevent_req *subreq);
static bool hbac_check_step_result(struct hbac_ctx *hbac_ctx, int ret);

static int hbac_get_host_info_step(struct hbac_ctx *hbac_ctx);
static void hbac_get_host_info_done(struct tevent_req *req);
static void hbac_get_rules_done(struct tevent_req *req);
static void hbac_get_service_data_done(struct tevent_req *req);

void ipa_access_handler(struct be_req *be_req)
{
    struct pam_data *pd;
    struct hbac_ctx *hbac_ctx;
    int pam_status = PAM_SYSTEM_ERR;
    struct ipa_access_ctx *ipa_access_ctx;
    bool offline;
    int ret;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    hbac_ctx = talloc_zero(be_req, struct hbac_ctx);
    if (hbac_ctx == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        goto fail;
    }
    hbac_ctx->be_req = be_req;
    hbac_ctx->pd = pd;
    ipa_access_ctx = talloc_get_type(
                              be_req->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                              struct ipa_access_ctx);
    hbac_ctx->sdap_ctx = ipa_access_ctx->sdap_ctx;
    hbac_ctx->ipa_options = ipa_access_ctx->ipa_options;
    hbac_ctx->tr_ctx = ipa_access_ctx->tr_ctx;
    ret = domain_to_basedn(hbac_ctx,
                           dp_opt_get_string(hbac_ctx->ipa_options, IPA_DOMAIN),
                           &hbac_ctx->ldap_basedn);
    if (ret != EOK) {
        DEBUG(1, ("domain_to_basedn failed.\n"));
        goto fail;
    }

    offline = be_is_offline(be_req->be_ctx);
    DEBUG(9, ("Connection status is [%s].\n", offline ? "offline" : "online"));

    if (!offline) {
        hbac_ctx->sdap_op = sdap_id_op_create(hbac_ctx,
                                    hbac_ctx_sdap_id_ctx(hbac_ctx)->conn_cache);
        if (!hbac_ctx->sdap_op) {
            DEBUG(1, ("sdap_id_op_create failed.\n"));
            goto fail;
        }
    }

    ret = hbac_retry(hbac_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    ipa_access_reply(hbac_ctx, pam_status);
}

static int hbac_retry(struct hbac_ctx *hbac_ctx)
{
    struct tevent_req *subreq;
    int ret;

    if (hbac_ctx_is_offline(hbac_ctx)) {
        return hbac_get_host_info_step(hbac_ctx);
    }

    subreq = sdap_id_op_connect_send(hbac_ctx_sdap_id_op(hbac_ctx), hbac_ctx, &ret);
    if (!subreq) {
        DEBUG(1, ("sdap_id_op_connect_send failed: %d(%s).\n", ret, strerror(ret)));
        return ret;
    }

    tevent_req_set_callback(subreq, hbac_connect_done, hbac_ctx);
    return EOK;
}

static void hbac_connect_done(struct tevent_req *subreq)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(subreq, struct hbac_ctx);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        /* switching to offline mode */
        talloc_zfree(hbac_ctx->sdap_op);
    } else if (ret != EOK) {
        goto fail;
    }

    ret = hbac_get_host_info_step(hbac_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

/* Check the step result code and continue, retry, get offline result or abort accordingly */
static bool hbac_check_step_result(struct hbac_ctx *hbac_ctx, int ret)
{
    int dp_error;

    if (ret == EOK) {
        return true;
    }

    if (hbac_ctx_is_offline(hbac_ctx)) {
        /* already offline => the error is fatal */
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return false;
    }

    ret = sdap_id_op_done(hbac_ctx_sdap_id_op(hbac_ctx), ret, &dp_error);
    if (dp_error == DP_ERR_OFFLINE) {
        /* switching to offline mode */
        talloc_zfree(hbac_ctx->sdap_op);
        dp_error = DP_ERR_OK;
    }

    if (dp_error == DP_ERR_OK) {
        /* retry */
        ret = hbac_retry(hbac_ctx);
        if (ret == EOK) {
            return false;
        }

        dp_error = DP_ERR_FATAL;
    }

    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
    return false;
}

static int hbac_get_host_info_step(struct hbac_ctx *hbac_ctx)
{
    struct pam_data *pd = hbac_ctx->pd;
    const char *hostlist[3];
    struct tevent_req *subreq;

    hostlist[0] = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (hostlist[0] == NULL) {
        DEBUG(1, ("ipa_hostname not available.\n"));
        return EINVAL;
    }
    if (pd->rhost != NULL && *pd->rhost != '\0') {
        hostlist[1] = pd->rhost;
        hostlist[2] = NULL;
    } else {
        hostlist[1] = NULL;
        pd->rhost = discard_const_p(char, hostlist[0]);
    }

    subreq = hbac_get_host_info_send(hbac_ctx, hbac_ctx,
                                     hbac_ctx->ldap_basedn,
                                     hostlist);
    if (!subreq) {
        DEBUG(1, ("hbac_get_host_info_send failed.\n"));
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, hbac_get_host_info_done, hbac_ctx);
    return EOK;
}

static void hbac_get_host_info_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    const char *ipa_hostname;
    struct hbac_host_info *local_hhi = NULL;
    int i;

    talloc_zfree(hbac_ctx->hbac_host_info);
    ret = hbac_get_host_info_recv(req, hbac_ctx, &hbac_ctx->hbac_host_info);
    talloc_zfree(req);

    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    ipa_hostname = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        DEBUG(1, ("Missing ipa_hostname, this should never happen.\n"));
        ret = EINVAL;
        goto fail;
    }

    for (i = 0; hbac_ctx->hbac_host_info[i] != NULL; i++) {
        if (strcmp(hbac_ctx->hbac_host_info[i]->fqdn, ipa_hostname) == 0 ||
            strcmp(hbac_ctx->hbac_host_info[i]->serverhostname,
                   ipa_hostname) == 0) {
            local_hhi = hbac_ctx->hbac_host_info[i];
        }
        if (hbac_ctx->pd->rhost != NULL && *hbac_ctx->pd->rhost != '\0') {
            if (strcmp(hbac_ctx->hbac_host_info[i]->fqdn,
                       hbac_ctx->pd->rhost) == 0 ||
                strcmp(hbac_ctx->hbac_host_info[i]->serverhostname,
                       hbac_ctx->pd->rhost) == 0) {
                hbac_ctx->remote_hhi = hbac_ctx->hbac_host_info[i];
            }
        }
    }
    if (local_hhi == NULL) {
        DEBUG(1, ("Missing host info for [%s].\n", ipa_hostname));
        ret = EOK;
        pam_status = PAM_PERM_DENIED;
        goto fail;
    }
    req = hbac_get_rules_send(hbac_ctx, hbac_ctx,
                              hbac_ctx->ldap_basedn, local_hhi->dn,
                              local_hhi->memberof);
    if (req == NULL) {
        DEBUG(1, ("hbac_get_rules_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(req, hbac_get_rules_done, hbac_ctx);
    return;

fail:
    ipa_access_reply(hbac_ctx, pam_status);
}

static void hbac_get_rules_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;

    hbac_ctx->hbac_rule_count = 0;
    talloc_zfree(hbac_ctx->hbac_rule_list);

    ret = hbac_get_rules_recv(req, hbac_ctx, &hbac_ctx->hbac_rule_count,
                              &hbac_ctx->hbac_rule_list);
    talloc_zfree(req);

    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    req = hbac_get_service_data_send(hbac_ctx, hbac_ctx,
                                     hbac_ctx->ldap_basedn);
    if (req == NULL) {
        DEBUG(1, ("hbac_get_service_data_send failed.\n"));
        goto failed;
    }

    tevent_req_set_callback(req, hbac_get_service_data_done, hbac_ctx);
    return;

failed:
    ipa_access_reply(hbac_ctx, pam_status);
}

static void hbac_get_service_data_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    struct pam_data *pd = hbac_ctx->pd;
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    bool access_allowed = false;

    hbac_ctx->hbac_services_count = 0;
    talloc_zfree(hbac_ctx->hbac_services_list);

    ret = hbac_get_service_data_recv(req, hbac_ctx,
                                     &hbac_ctx->hbac_services_count,
                                     &hbac_ctx->hbac_services_list);
    talloc_zfree(req);

    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    if (hbac_ctx->user_dn) {
        talloc_free(discard_const_p(TALLOC_CTX, hbac_ctx->user_dn));
        hbac_ctx->user_dn = 0;
    }

    hbac_ctx->groups_count = 0;
    talloc_zfree(hbac_ctx->groups);

    ret = hbac_get_user_info(hbac_ctx, hbac_ctx_be(hbac_ctx),
                             pd->user, &hbac_ctx->user_dn,
                             &hbac_ctx->groups_count, &hbac_ctx->groups);
    if (ret != EOK) {
        goto failed;
    }

    ret = evaluate_ipa_hbac_rules(hbac_ctx, &access_allowed);
    if (ret != EOK) {
        DEBUG(1, ("evaluate_ipa_hbac_rules failed.\n"));
        goto failed;
    }

    if (access_allowed) {
        pam_status = PAM_SUCCESS;
        DEBUG(5, ("Access allowed.\n"));
    } else {
        pam_status = PAM_PERM_DENIED;
        DEBUG(3, ("Access denied.\n"));
    }

failed:
    ipa_access_reply(hbac_ctx, pam_status);
}
