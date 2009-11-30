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

#define IPA_HOST_MEMBEROF "memberOf"
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

#define IPA_HOST_BASE_TMPL "cn=computers,cn=accounts,dc=%s"
#define IPA_HBAC_BASE_TMPL "cn=hbac,dc=%s"

#define SYSDB_HBAC_BASE_TMPL "cn=hbac,"SYSDB_TMPL_CUSTOM_BASE

#define HBAC_RULES_SUBDIR "hbac_rules"
#define HBAC_HOSTS_SUBDIR "hbac_hosts"

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

static void ipa_access_reply(struct be_req *be_req, int pam_status)
{
    struct pam_data *pd;
    pd = talloc_get_type(be_req->req_data, struct pam_data);
    pd->pam_status = pam_status;

    if (pam_status == PAM_SUCCESS) {
        be_req->fn(be_req, DP_ERR_OK, pam_status, NULL);
    } else {
        be_req->fn(be_req, DP_ERR_FATAL, pam_status, NULL);
    }
}

struct hbac_get_user_info_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;;
    struct sysdb_handle *handle;

    const char *user;
    const char *user_orig_dn;
    struct ldb_dn *user_dn;
    size_t groups_count;
    const char **groups;
};

static void search_user_done(struct tevent_req *subreq);
static void search_groups_done(struct tevent_req *subreq);

struct tevent_req *hbac_get_user_info_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct be_ctx *be_ctx,
                                           const char *user)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct hbac_get_user_info_state *state;
    int ret;
    const char **attrs;

    req = tevent_req_create(memctx, &state, struct hbac_get_user_info_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->handle = NULL;
    state->user = user;
    state->user_orig_dn = NULL;
    state->user_dn = NULL;
    state->groups_count = 0;
    state->groups = NULL;

    attrs = talloc_array(state, const char *, 2);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    attrs[0] = SYSDB_ORIG_DN;
    attrs[1] = NULL;

    subreq = sysdb_search_user_by_name_send(state, ev, be_ctx->sysdb, NULL,
                                            be_ctx->domain, user, attrs);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_search_user_by_name_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, search_user_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void search_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_user_info_state *state = tevent_req_data(req,
                                               struct hbac_get_user_info_state);
    int ret;
    const char **attrs;
    const char *dummy;
    struct ldb_message *user_msg;


    ret = sysdb_search_user_recv(subreq, state, &user_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(9, ("Found user info for user [%s].\n", state->user));
    state->user_dn = talloc_steal(state, user_msg->dn);
    dummy = ldb_msg_find_attr_as_string(user_msg, SYSDB_ORIG_DN, NULL);
    if (dummy == NULL) {
        DEBUG(1, ("Original DN of user [%s] not available.\n", state->user));
        ret = EINVAL;
        goto failed;
    }
    state->user_orig_dn = talloc_strdup(state, dummy);
    if (state->user_dn == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        ret = ENOMEM;
        goto failed;
    }
    DEBUG(9, ("Found original DN [%s] for user [%s].\n", state->user_orig_dn,
                                                         state->user));

    attrs = talloc_array(state, const char *, 2);
    if (attrs == NULL) {
        DEBUG(1, ("talloc_array failed.\n"));
        ret = ENOMEM;
        goto failed;
    }
    attrs[0] = SYSDB_ORIG_DN;
    attrs[1] = NULL;

    subreq = sysdb_asq_search_send(state, state->ev, state->be_ctx->sysdb, NULL,
                                   state->be_ctx->domain, state->user_dn, NULL,
                                   SYSDB_MEMBEROF, attrs);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_asq_search_send failed.\n"));
        ret = ENOMEM;
        goto failed;
    }

    tevent_req_set_callback(subreq, search_groups_done, req);
    return;

failed:
    tevent_req_error(req, ret);
    return;
}

static void search_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_user_info_state *state = tevent_req_data(req,
                                               struct hbac_get_user_info_state);
    int ret;
    int i;
    struct ldb_message **msg;

    ret = sysdb_asq_search_recv(subreq, state, &state->groups_count, &msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->groups_count == 0) {
        tevent_req_done(req);
        return;
    }

    state->groups = talloc_array(state, const char *, state->groups_count);
    if (state->groups == NULL) {
        DEBUG(1, ("talloc_groups failed.\n"));
        ret = ENOMEM;
        goto failed;
    }

    for(i = 0; i < state->groups_count; i++) {
        if (msg[i]->num_elements != 1) {
            DEBUG(1, ("Unexpected number of elements.\n"));
            ret = EINVAL;
            goto failed;
        }

        if (msg[i]->elements[0].num_values != 1) {
            DEBUG(1, ("Unexpected number of values.\n"));
            ret = EINVAL;
            goto failed;
        }

        state->groups[i] = talloc_strndup(state->groups,
                                          (const char *) msg[i]->elements[0].values[0].data,
                                          msg[i]->elements[0].values[0].length);
        if (state->groups[i] == NULL) {
            DEBUG(1, ("talloc_strndup failed.\n"));
            ret = ENOMEM;
            goto failed;
        }

        DEBUG(9, ("Found group [%s].\n", state->groups[i]));
    }

    tevent_req_done(req);
    return;

failed:
    talloc_free(state->groups);
    tevent_req_error(req, ret);
    return;
}

static int hbac_get_user_info_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                                   const char **user_dn, size_t *groups_count,
                                   const char ***groups)
{
    struct hbac_get_user_info_state *state = tevent_req_data(req,
                                               struct hbac_get_user_info_state);
    int i;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *user_dn = talloc_steal(memctx, state->user_orig_dn);
    *groups_count = state->groups_count;
    for (i = 0; i < state->groups_count; i++) {
        talloc_steal(memctx, state->groups[i]);
    }
    *groups = talloc_steal(memctx, state->groups);

    return EOK;
}


struct hbac_get_host_info_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *sdap_ctx;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    bool offline;

    char *host_filter;
    char *host_search_base;
    const char **host_attrs;

    struct sysdb_attrs **host_reply_list;
    size_t host_reply_count;
    size_t current_item;
    struct hbac_host_info **hbac_host_info;
};

static void hbac_get_host_info_connect_done(struct tevent_req *subreq);
static void hbac_get_host_memberof_done(struct tevent_req *subreq);
static void hbac_get_host_info_sysdb_transaction_started(struct tevent_req *subreq);
static void hbac_get_host_info_store_prepare(struct tevent_req *req);
static void hbac_get_host_info_store_done(struct tevent_req *subreq);

static struct tevent_req *hbac_get_host_info_send(TALLOC_CTX *memctx,
                                                  struct tevent_context *ev,
                                                  bool offline,
                                                  struct sdap_id_ctx *sdap_ctx,
                                                  struct sysdb_ctx *sysdb,
                                                  const char *ipa_domain,
                                                  const char **hostnames)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct hbac_get_host_info_state *state;
    int ret;
    int i;

    if (hostnames == NULL || ipa_domain == NULL) {
        DEBUG(1, ("Missing hostnames or domain.\n"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct hbac_get_host_info_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->sdap_ctx = sdap_ctx;
    state->sysdb = sysdb;
    state->handle = NULL;
    state->offline = offline;

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
                                              ipa_domain);
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
    state->host_attrs[0] = IPA_HOST_MEMBEROF;
    state->host_attrs[1] = IPA_HOST_SERVERHOSTNAME;
    state->host_attrs[2] = IPA_HOST_FQDN;
    state->host_attrs[3] = "objectClass";
    state->host_attrs[4] = SYSDB_ORIG_DN;
    state->host_attrs[5] = SYSDB_ORIG_MEMBEROF;
    state->host_attrs[6] = NULL;

    if (offline) {
        subreq = sysdb_search_custom_send(state, state->ev, state->sysdb, NULL,
                                          state->sdap_ctx->be->domain,
                                          state->host_filter, HBAC_HOSTS_SUBDIR,
                                          state->host_attrs);
        if (subreq == NULL) {
            DEBUG(1, ("sysdb_search_custom_send.\n"));
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, hbac_get_host_memberof_done, req);

        return req;
    }

    if (sdap_ctx->gsh == NULL || ! sdap_ctx->gsh->connected) {
        if (sdap_ctx->gsh != NULL) {
            talloc_zfree(sdap_ctx->gsh);
        }

        subreq = sdap_cli_connect_send(state, ev, sdap_ctx->opts,
                                       sdap_ctx->be, sdap_ctx->service, NULL);
        if (!subreq) {
            DEBUG(1, ("sdap_cli_connect_send failed.\n"));
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, hbac_get_host_info_connect_done, req);

        return req;
    }

    subreq = sdap_get_generic_send(state, state->ev,
                                   state->sdap_ctx->opts,
                                   state->sdap_ctx->gsh,
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
    tevent_req_post(req, ev);
    return req;
}

static void hbac_get_host_info_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_host_info_state *state = tevent_req_data(req,
                                               struct hbac_get_host_info_state);
    int ret;

    ret = sdap_cli_connect_recv(subreq, state->sdap_ctx, &state->sdap_ctx->gsh,
                                NULL);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_generic_send(state, state->ev,
                                   state->sdap_ctx->opts,
                                   state->sdap_ctx->gsh,
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

    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void hbac_get_host_memberof_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_host_info_state *state = tevent_req_data(req,
                                               struct hbac_get_host_info_state);
    int ret;
    int i;
    int v;
    struct ldb_message_element *el;
    struct hbac_host_info **hhi;
    struct ldb_message **msgs;

    if (state->offline) {
        ret = sysdb_search_custom_recv(subreq, state, &state->host_reply_count,
                                       &msgs);
    } else {
        ret = sdap_get_generic_recv(subreq, state, &state->host_reply_count,
                                    &state->host_reply_list);
    }
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->host_reply_count == 0) {
        DEBUG(1, ("No hosts not found in IPA server.\n"));
        ret = ENOENT;
        goto fail;
    }

    if (state->offline) {
        ret = msgs2attrs_array(state, state->host_reply_count, msgs,
                               &state->host_reply_list);
        talloc_zfree(msgs);
        if (ret != EOK) {
            DEBUG(1, ("msgs2attrs_array failed.\n"));
            goto fail;
        }
    }

    hhi = talloc_array(state, struct hbac_host_info *, state->host_reply_count + 1);
    if (hhi == NULL) {
        DEBUG(1, ("talloc_array failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    memset(hhi, 0,
           sizeof(struct hbac_host_info *) * (state->host_reply_count + 1));

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

        ret = sysdb_attrs_get_el(state->host_reply_list[i],
                                 state->offline ? SYSDB_ORIG_MEMBEROF :
                                                  IPA_HOST_MEMBEROF,
                                 &el);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
            goto fail;
        }

        hhi[i]->memberof = talloc_array(hhi, const char *, el->num_values + 1);
        if (hhi[i]->memberof == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        memset(hhi[i]->memberof, 0,
               sizeof(const char *) * (el->num_values + 1));

        for(v = 0; v < el->num_values; v++) {
            DEBUG(9, ("%s: [%.*s].\n", IPA_HOST_MEMBEROF, el->values[v].length,
                                     (const char *)el->values[v].data));
            hhi[i]->memberof[v] = talloc_strndup(hhi,
                                               (const char *)el->values[v].data,
                                               el->values[v].length);
            if (hhi[i]->memberof[v] == NULL) {
                ret = ENOMEM;
                goto fail;
            }
        }
    }

    state->hbac_host_info = hhi;

    if (state->offline) {
        tevent_req_done(req);
        return;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_transaction_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, hbac_get_host_info_sysdb_transaction_started, req);
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void hbac_get_host_info_sysdb_transaction_started(
                                                      struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_host_info_state *state = tevent_req_data(req,
                                               struct hbac_get_host_info_state);
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->current_item = 0;
    hbac_get_host_info_store_prepare(req);
    return;
}

static void hbac_get_host_info_store_prepare(struct tevent_req *req)
{
    struct hbac_get_host_info_state *state = tevent_req_data(req,
                                               struct hbac_get_host_info_state);
    int ret;
    char *object_name;
    struct ldb_message_element *el;
    struct tevent_req *subreq;

    if (state->current_item < state->host_reply_count) {
        ret = sysdb_attrs_get_el(state->host_reply_list[state->current_item],
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


        ret = sysdb_attrs_replace_name(
                                    state->host_reply_list[state->current_item],
                                    IPA_HOST_MEMBEROF, SYSDB_ORIG_MEMBEROF);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_replace_name failed.\n"));
            goto fail;
        }

        subreq = sysdb_store_custom_send(state, state->ev,
                                         state->handle,
                                         state->sdap_ctx->be->domain,
                                         object_name,
                                         HBAC_HOSTS_SUBDIR,
                                         state->host_reply_list[state->current_item]);

        if (subreq == NULL) {
            DEBUG(1, ("sysdb_store_custom_send failed.\n"));
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, hbac_get_host_info_store_done, req);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_transaction_commit_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_transaction_complete, req);

    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void hbac_get_host_info_store_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_host_info_state *state = tevent_req_data(req,
                                               struct hbac_get_host_info_state);
    int ret;

    ret = sysdb_store_custom_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->current_item++;
    hbac_get_host_info_store_prepare(req);
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
    struct tevent_context *ev;
    struct sdap_id_ctx *sdap_ctx;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    bool offline;

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

static void hbac_get_rules_connect_done(struct tevent_req *subreq);
static void hbac_rule_get_done(struct tevent_req *subreq);
static void hbac_rule_sysdb_transaction_started(struct tevent_req *subreq);
static void hbac_rule_sysdb_delete_done(struct tevent_req *subreq);
static void hbac_rule_store_prepare(struct tevent_req *req);
static void hbac_rule_store_done(struct tevent_req *subreq);

static struct tevent_req *hbac_get_rules_send(TALLOC_CTX *memctx,
                                             struct tevent_context *ev,
                                             bool offline,
                                             struct sdap_id_ctx *sdap_ctx,
                                             struct sysdb_ctx *sysdb,
                                             const char *ipa_domain,
                                             const char *host_dn,
                                             const char **memberof)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct hbac_get_rules_state *state;
    int ret;
    int i;

    if (host_dn == NULL || ipa_domain == NULL) {
        DEBUG(1, ("Missing host_dn or domain.\n"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct hbac_get_rules_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->offline = offline;
    state->sdap_ctx = sdap_ctx;
    state->sysdb = sysdb;
    state->handle = NULL;
    state->host_dn = host_dn;
    state->memberof = memberof;

    state->old_rules = NULL;
    state->hbac_reply_list = NULL;
    state->hbac_reply_count = 0;
    state->current_item = 0;

    state->hbac_search_base = talloc_asprintf(state, IPA_HBAC_BASE_TMPL,
                                              ipa_domain);
    if (state->hbac_search_base == NULL) {
        DEBUG(1, ("Failed to create HBAC search base.\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->hbac_attrs = talloc_array(state, const char *, 16);
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
    state->hbac_attrs[11] = "objectclass";
    state->hbac_attrs[12] = IPA_MEMBER_HOST;
    state->hbac_attrs[13] = IPA_HOST_CATEGORY;
    state->hbac_attrs[14] = SYSDB_ORIG_DN;
    state->hbac_attrs[15] = NULL;

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

    if (offline) {
        subreq = sysdb_search_custom_send(state, state->ev, state->sysdb, NULL,
                                          state->sdap_ctx->be->domain,
                                          state->hbac_filter, HBAC_RULES_SUBDIR,
                                          state->hbac_attrs);
        if (subreq == NULL) {
            DEBUG(1, ("sysdb_search_custom_send failed.\n"));
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, hbac_rule_get_done, req);

        return req;
    }

    if (sdap_ctx->gsh == NULL || ! sdap_ctx->gsh->connected) {
        if (sdap_ctx->gsh != NULL) {
            talloc_zfree(sdap_ctx->gsh);
        }

        subreq = sdap_cli_connect_send(state, ev, sdap_ctx->opts,
                                       sdap_ctx->be, sdap_ctx->service, NULL);
        if (!subreq) {
            DEBUG(1, ("sdap_cli_connect_send failed.\n"));
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, hbac_get_rules_connect_done, req);

        return req;
    }

    subreq = sdap_get_generic_send(state, state->ev,
                                   state->sdap_ctx->opts,
                                   state->sdap_ctx->gsh,
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
    tevent_req_post(req, ev);
    return req;
}

static void hbac_get_rules_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);
    int ret;

    ret = sdap_cli_connect_recv(subreq, state->sdap_ctx, &state->sdap_ctx->gsh,
                                NULL);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_generic_send(state, state->ev,
                                   state->sdap_ctx->opts,
                                   state->sdap_ctx->gsh,
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
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void hbac_rule_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);
    int ret;
    int i;
    struct ldb_message_element *el;
    struct ldb_message **msgs;

    if (state->offline) {
        ret = sysdb_search_custom_recv(subreq, state, &state->hbac_reply_count,
                                       &msgs);
    } else {
        ret = sdap_get_generic_recv(subreq, state, &state->hbac_reply_count,
                                    &state->hbac_reply_list);
    }
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->offline) {
        ret = msgs2attrs_array(state, state->hbac_reply_count, msgs,
                               &state->hbac_reply_list);
        talloc_zfree(msgs);
        if (ret != EOK) {
            DEBUG(1, ("msgs2attrs_array failed.\n"));
            goto fail;
        }
    }

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

    if (state->hbac_reply_count == 0 || state->offline) {
        tevent_req_done(req);
        return;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_transaction_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, hbac_rule_sysdb_transaction_started, req);
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void hbac_rule_sysdb_transaction_started(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);
    int ret;
    struct ldb_dn *hbac_base_dn;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    hbac_base_dn = sysdb_custom_subtree_dn(state->sysdb, state,
                                           state->sdap_ctx->be->domain->name,
                                           HBAC_RULES_SUBDIR);
    if (hbac_base_dn == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    subreq = sysdb_delete_recursive_send(state, state->ev, state->handle,
                                         hbac_base_dn, true);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_delete_recursive_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, hbac_rule_sysdb_delete_done, req);
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void hbac_rule_sysdb_delete_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);
    int ret;

    ret = sysdb_delete_recursive_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->current_item = 0;
    hbac_rule_store_prepare(req);
}

static void hbac_rule_store_prepare(struct tevent_req *req)
{
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);
    int ret;
    struct ldb_message_element *el;
    struct tevent_req *subreq;
    char *object_name;

    if (state->current_item < state->hbac_reply_count) {

        ret = sysdb_attrs_get_el(state->hbac_reply_list[state->current_item],
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

        subreq = sysdb_store_custom_send(state, state->ev,
                                         state->handle,
                                         state->sdap_ctx->be->domain,
                                         object_name,
                                         HBAC_RULES_SUBDIR,
                                         state->hbac_reply_list[state->current_item]);

        if (subreq == NULL) {
            DEBUG(1, ("sysdb_store_custom_send failed.\n"));
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, hbac_rule_store_done, req);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_transaction_commit_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_transaction_complete, req);

    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void hbac_rule_store_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);
    int ret;

    ret = sysdb_store_custom_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->current_item++;
    hbac_rule_store_prepare(req);
}

static int hbac_get_rules_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                               size_t *hbac_rule_count,
                               struct sysdb_attrs ***hbac_rule_list)
{
    struct hbac_get_rules_state *state = tevent_req_data(req,
                                                     struct hbac_get_rules_state);
    int i;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *hbac_rule_count = state->hbac_reply_count;
    *hbac_rule_list = talloc_steal(memctx, state->hbac_reply_list);
    for (i = 0; i < state->hbac_reply_count; i++) {
        talloc_steal(memctx, state->hbac_reply_list[i]);
    }
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

enum check_result check_service(struct pam_data *pd,
                                struct sysdb_attrs *rule_attrs)
{
    int ret;
    int i;
    struct ldb_message_element *el;

    if (pd->service == NULL) {
        DEBUG(1, ("No service in pam data, assuming error.\n"));
        return RULE_ERROR;
    }

    ret = sysdb_attrs_get_el(rule_attrs, IPA_SERVICE_NAME, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el failed.\n"));
        return RULE_ERROR;
    }
    if (el->num_values == 0) {
        DEBUG(9, ("No services in rule specified, assuming rule applies.\n"));
        return RULE_APPLICABLE;
    } else {
        for (i = 0; i < el->num_values; i++) {
            if (strncasecmp(pd->service, (const char *) el->values[i].data,
                            el->values[i].length) == 0) {
                DEBUG(9, ("Service [%s] found, rule applies.\n",
                          pd->service));
                return RULE_APPLICABLE;
            }
        }
        DEBUG(9, ("No matching service found, rule does not apply.\n"));
        return RULE_NOT_APPLICABLE;
    }

    return RULE_ERROR;
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
        DEBUG(9, ("USer category is not set.\n"));
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
        return RULE_APPLICABLE;
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

static errno_t check_if_rule_applies(enum hbac_result *result,
                                     struct hbac_ctx *hbac_ctx,
                                     struct sysdb_attrs *rule_attrs) {
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

    ret = check_service(pd, rule_attrs);
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

        ret = check_if_rule_applies(&result, hbac_ctx,
                                    hbac_ctx->hbac_rule_list[i]);
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

static void hbac_get_host_info_done(struct tevent_req *req);
static void hbac_get_rules_done(struct tevent_req *req);
static void hbac_get_user_info_done(struct tevent_req *req);

void ipa_access_handler(struct be_req *be_req)
{
    struct tevent_req *req;
    struct pam_data *pd;
    struct hbac_ctx *hbac_ctx;
    int pam_status = PAM_SYSTEM_ERR;
    struct ipa_access_ctx *ipa_access_ctx;
    const char *hostlist[3];

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
    hbac_ctx->offline = be_is_offline(be_req->be_ctx);

    DEBUG(9, ("Connection status is [%s].\n", hbac_ctx->offline ? "offline" :
                                                                  "online"));


    hostlist[0] = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (hostlist[0] == NULL) {
        DEBUG(1, ("ipa_hostname not available.\n"));
        goto fail;
    }
    if (pd->rhost != NULL && *pd->rhost != '\0') {
        hostlist[1] = pd->rhost;
    } else {
        hostlist[1] = NULL;
        pd->rhost = dp_opt_get_string(hbac_ctx->ipa_options, IPA_HOSTNAME);
        if (pd->rhost == NULL) {
            DEBUG(1, ("ipa_hostname not available.\n"));
            goto fail;
        }
    }
    hostlist[2] = NULL;

    req = hbac_get_host_info_send(hbac_ctx, be_req->be_ctx->ev,
                                  hbac_ctx->offline,
                                  hbac_ctx->sdap_ctx, be_req->be_ctx->sysdb,
                                  dp_opt_get_string(hbac_ctx->ipa_options,
                                                    IPA_DOMAIN),
                                  hostlist);
    if (req == NULL) {
        DEBUG(1, ("hbac_get_host_info_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(req, hbac_get_host_info_done, hbac_ctx);
    return;

fail:
    ipa_access_reply(be_req, pam_status);
}

static void hbac_get_host_info_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    struct be_req *be_req = hbac_ctx->be_req;
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    const char *ipa_hostname;
    struct hbac_host_info *local_hhi = NULL;
    int i;

    ret = hbac_get_host_info_recv(req, hbac_ctx, &hbac_ctx->hbac_host_info);
    talloc_zfree(req);
    if (ret != EOK) {
        goto fail;
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
        ret = EINVAL;
        goto fail;
    }
    req = hbac_get_rules_send(hbac_ctx, be_req->be_ctx->ev, hbac_ctx->offline,
                              hbac_ctx->sdap_ctx, be_req->be_ctx->sysdb,
                              dp_opt_get_string(hbac_ctx->ipa_options,
                                                IPA_DOMAIN),
                              local_hhi->dn, local_hhi->memberof);
    if (req == NULL) {
        DEBUG(1, ("hbac_get_rules_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(req, hbac_get_rules_done, hbac_ctx);
    return;

fail:
    ipa_access_reply(be_req, pam_status);
}

static void hbac_get_rules_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    struct pam_data *pd = hbac_ctx->pd;
    struct be_req *be_req = hbac_ctx->be_req;
    int ret;
    int pam_status = PAM_SYSTEM_ERR;

    ret = hbac_get_rules_recv(req, hbac_ctx, &hbac_ctx->hbac_rule_count,
                              &hbac_ctx->hbac_rule_list);
    talloc_zfree(req);
    if (ret != EOK) {
        goto fail;
    }

    req = hbac_get_user_info_send(hbac_ctx, be_req->be_ctx->ev, be_req->be_ctx,
                                  pd->user);
    if (req == NULL) {
        DEBUG(1, ("hbac_get_user_info_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(req, hbac_get_user_info_done, hbac_ctx);
    return;

fail:
    ipa_access_reply(be_req, pam_status);
}

static void hbac_get_user_info_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    struct be_req *be_req = hbac_ctx->be_req;
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    bool access_allowed = false;

    ret = hbac_get_user_info_recv(req, hbac_ctx, &hbac_ctx->user_dn,
                                  &hbac_ctx->groups_count,
                                  &hbac_ctx->groups);
    talloc_zfree(req);
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
    ipa_access_reply(be_req, pam_status);
}
