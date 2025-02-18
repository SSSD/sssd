/*
    SSSD

    IPA Identity Backend Module for views and overrides

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

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
#include "util/strtonum.h"
#include "util/cert.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_id.h"
#include "db/sysdb.h"

#define MAX_USER_AND_GROUP_REPLIES 2

static errno_t get_user_or_group(TALLOC_CTX *mem_ctx,
                                 struct ipa_options *ipa_opts,
                                 struct sysdb_attrs *attrs,
                                 enum sysdb_obj_type *_what_is)
{
    errno_t ret;
    const char **values;
    const char **value;
    bool is_user = false;
    bool is_group = false;
    const char *ov_user_name = ipa_opts->override_map[IPA_OC_OVERRIDE_USER].name;
    const char *ov_group_name = ipa_opts->override_map[IPA_OC_OVERRIDE_GROUP].name;

    ret = sysdb_attrs_get_string_array(attrs, SYSDB_ORIG_OBJECTCLASS, mem_ctx, &values);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve attribute [%s].\n",
              SYSDB_ORIG_OBJECTCLASS);
        return ret;
    }

    /* We assume an entry can be a user or a group override but not both.
     * So we leave as soon as we identify one of them. */
    if (values != NULL) {
        for (value = values; *value != NULL; value++) {
            if (strcasecmp(*value, ov_user_name) == 0) {
                is_user = true;
                break;
            } else if (strcasecmp(*value, ov_group_name) == 0) {
                is_group = true;
                break;
            }
        }
        talloc_free(values);
    }

    /* We also assume it must be necessarily a user or a group. */
    if (!is_user && !is_group) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected override found.\n");
        return EINVAL;
    }

    if (_what_is != NULL) {
        *_what_is = is_user ? SYSDB_USER : SYSDB_GROUP;
    }

    return EOK;
}

/* Verify there are exactly 1 user and 1 group override. Any other combination
 * is wrong. Then keep only the group override. */
static errno_t check_and_filter_user_and_group(struct ipa_options *ipa_opts,
                                               struct sysdb_attrs **reply,
                                               size_t *reply_count)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    enum sysdb_obj_type entry_is[MAX_USER_AND_GROUP_REPLIES];
    int i;

    if (*reply_count != MAX_USER_AND_GROUP_REPLIES) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Expected %i replies but got %lu\n",
              MAX_USER_AND_GROUP_REPLIES, *reply_count);
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate memory.\n");
        return ENOMEM;
    }

    for (i = 0; i < MAX_USER_AND_GROUP_REPLIES; i++) {
        ret = get_user_or_group(tmp_ctx, ipa_opts, reply[i], &entry_is[i]);
        if (ret != EOK) {
            goto done;
        }
    }

    if (entry_is[0] == SYSDB_USER && entry_is[1] == SYSDB_USER) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Found 2 user overrides.\n");
        ret = EINVAL;
        goto done;
    } else if (entry_is[0] == SYSDB_GROUP && entry_is[1] == SYSDB_GROUP) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Found 2 group overrides.\n");
        ret = EINVAL;
        goto done;
    }

    /* We have one user and one group override. Keep only the group override. */
    DEBUG(SSSDBG_TRACE_INTERNAL, "Keeping only the group override.\n");
    if (entry_is[0] == SYSDB_USER) {
        talloc_free(reply[0]);
        reply[0] = reply[1];
    } else {
        talloc_free(reply[1]);
    }
    reply[1] = NULL;
    *reply_count = 1;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t dp_id_data_to_override_filter(TALLOC_CTX *mem_ctx,
                                              struct ipa_options *ipa_opts,
                                              struct dp_id_data *ar,
                                              char **override_filter)
{
    char *filter;
    uint32_t id;
    char *endptr;
    char *cert_filter;
    int ret;
    char *shortname;
    char *sanitized_name;

    switch (ar->filter_type) {
    case BE_FILTER_NAME:
        ret = sss_parse_internal_fqname(mem_ctx, ar->filter_value,
                                        &shortname, NULL);
        if (ret != EOK) {
            return ret;
        }

        ret = sss_filter_sanitize(mem_ctx, shortname, &sanitized_name);
        talloc_free(shortname);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_filter_sanitize failed.\n");
            return ret;
        }

        switch ((ar->entry_type & BE_REQ_TYPE_MASK)) {
        case BE_REQ_USER:
        case BE_REQ_INITGROUPS:
            filter = talloc_asprintf(mem_ctx, "(&(objectClass=%s)(%s=%s))",
                         ipa_opts->override_map[IPA_OC_OVERRIDE_USER].name,
                         ipa_opts->override_map[IPA_AT_OVERRIDE_USER_NAME].name,
                         sanitized_name);
            break;

         case BE_REQ_GROUP:
            filter = talloc_asprintf(mem_ctx, "(&(objectClass=%s)(%s=%s))",
                        ipa_opts->override_map[IPA_OC_OVERRIDE_GROUP].name,
                        ipa_opts->override_map[IPA_AT_OVERRIDE_GROUP_NAME].name,
                        sanitized_name);
            break;

         case BE_REQ_USER_AND_GROUP:
            filter = talloc_asprintf(mem_ctx,
                        "(|(&(objectClass=%s)(%s=%s))(&(objectClass=%s)(%s=%s)))",
                        ipa_opts->override_map[IPA_OC_OVERRIDE_USER].name,
                        ipa_opts->override_map[IPA_AT_OVERRIDE_USER_NAME].name,
                        sanitized_name,
                        ipa_opts->override_map[IPA_OC_OVERRIDE_GROUP].name,
                        ipa_opts->override_map[IPA_AT_OVERRIDE_GROUP_NAME].name,
                        sanitized_name);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected entry type [%d] for name filter.\n",
                                       ar->entry_type);
            talloc_free(sanitized_name);
            return EINVAL;
        }
        talloc_free(sanitized_name);
        break;

    case BE_FILTER_IDNUM:
        id = strtouint32(ar->filter_value, &endptr, 10);
        if (errno != 0|| *endptr != '\0' || (ar->filter_value == endptr)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid id value [%s].\n",
                                       ar->filter_value);
            return EINVAL;
        }
        switch ((ar->entry_type & BE_REQ_TYPE_MASK)) {
        case BE_REQ_USER:
        case BE_REQ_INITGROUPS:
            filter = talloc_asprintf(mem_ctx, "(&(objectClass=%s)(%s=%"PRIu32"))",
                        ipa_opts->override_map[IPA_OC_OVERRIDE_USER].name,
                        ipa_opts->override_map[IPA_AT_OVERRIDE_UID_NUMBER].name,
                        id);
            break;

         case BE_REQ_GROUP:
            filter = talloc_asprintf(mem_ctx,
                  "(&(objectClass=%s)(%s=%"PRIu32"))",
                  ipa_opts->override_map[IPA_OC_OVERRIDE_GROUP].name,
                  ipa_opts->override_map[IPA_AT_OVERRIDE_GROUP_GID_NUMBER].name,
                  id);
            break;

         case BE_REQ_USER_AND_GROUP:
            filter = talloc_asprintf(mem_ctx,
                  "(|(&(objectClass=%s)(%s=%"PRIu32"))(&(objectClass=%s)(%s=%"PRIu32")))",
                  ipa_opts->override_map[IPA_OC_OVERRIDE_USER].name,
                  ipa_opts->override_map[IPA_AT_OVERRIDE_UID_NUMBER].name,
                  id,
                  ipa_opts->override_map[IPA_OC_OVERRIDE_GROUP].name,
                  ipa_opts->override_map[IPA_AT_OVERRIDE_GROUP_GID_NUMBER].name,
                  id);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected entry type [%d] for id filter.\n",
                  ar->entry_type);
            return EINVAL;
        }
        break;

    case BE_FILTER_SECID:
        if ((ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_BY_SECID) {
            filter = talloc_asprintf(mem_ctx, "(&(objectClass=%s)(%s=:SID:%s))",
                       ipa_opts->override_map[IPA_OC_OVERRIDE].name,
                       ipa_opts->override_map[IPA_AT_OVERRIDE_ANCHOR_UUID].name,
                       ar->filter_value);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected entry type [%d] for SID filter.\n",
                  ar->entry_type);
            return EINVAL;
        }
        break;

    case BE_FILTER_UUID:
        if ((ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_BY_UUID) {
            filter = talloc_asprintf(mem_ctx, "(&(objectClass=%s)(%s=:IPA:%s:%s))",
                       ipa_opts->override_map[IPA_OC_OVERRIDE].name,
                       ipa_opts->override_map[IPA_AT_OVERRIDE_ANCHOR_UUID].name,
                       dp_opt_get_string(ipa_opts->basic, IPA_DOMAIN),
                       ar->filter_value);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected entry type [%d] for UUID filter.\n",
                  ar->entry_type);
            return EINVAL;
        }
        break;

    case BE_FILTER_CERT:
        if ((ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_BY_CERT) {
            ret = sss_cert_derb64_to_ldap_filter(mem_ctx, ar->filter_value,
                         ipa_opts->override_map[IPA_AT_OVERRIDE_USER_CERT].name,
                         NULL, NULL, &cert_filter);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sss_cert_derb64_to_ldap_filter failed.\n");
                return ret;
            }
            filter = talloc_asprintf(mem_ctx, "(&(objectClass=%s)%s)",
                        ipa_opts->override_map[IPA_OC_OVERRIDE_USER].name,
                        cert_filter);
            talloc_free(cert_filter);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected entry type [%d] for certificate filter.\n",
                  ar->entry_type);
            return EINVAL;
        }
        break;

    default:
        DEBUG(SSSDBG_OP_FAILURE, "Invalid sub-domain filter type.\n");
        return EINVAL;
    }

    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        return ENOMEM;
    }

    *override_filter = filter;

    return EOK;
}

static errno_t get_dp_id_data_for_xyz(TALLOC_CTX *mem_ctx, const char *val,
                                       const char *domain_name,
                                       int type,
                                       struct dp_id_data **_ar)
{
    struct dp_id_data *ar;

    ar = talloc_zero(mem_ctx, struct dp_id_data);
    if (ar == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    switch (type) {
    case BE_REQ_BY_SECID:
        ar->entry_type = BE_REQ_BY_SECID;
        ar->filter_type = BE_FILTER_SECID;
        break;
    case BE_REQ_BY_UUID:
        ar->entry_type = BE_REQ_BY_UUID;
        ar->filter_type = BE_FILTER_UUID;
        break;
    case BE_REQ_USER:
        ar->entry_type = BE_REQ_USER;
        ar->filter_type = BE_FILTER_NAME;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported request type [%d].\n", type);
        talloc_free(ar);
        return EINVAL;
    }

    ar->filter_value = talloc_strdup(ar, val);
    ar->domain = talloc_strdup(ar, domain_name);
    if (ar->filter_value == NULL || ar->domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
        talloc_free(ar);
        return ENOMEM;
    }


    *_ar = ar;

    return EOK;
}

errno_t get_dp_id_data_for_sid(TALLOC_CTX *mem_ctx, const char *sid,
                                const char *domain_name,
                                struct dp_id_data **_ar)
{
    return get_dp_id_data_for_xyz(mem_ctx, sid, domain_name, BE_REQ_BY_SECID,
                                   _ar);
}

errno_t get_dp_id_data_for_uuid(TALLOC_CTX *mem_ctx, const char *uuid,
                                 const char *domain_name,
                                 struct dp_id_data **_ar)
{
    return get_dp_id_data_for_xyz(mem_ctx, uuid, domain_name, BE_REQ_BY_UUID,
                                   _ar);
}

errno_t get_dp_id_data_for_user_name(TALLOC_CTX *mem_ctx,
                                      const char *user_name,
                                      const char *domain_name,
                                      struct dp_id_data **_ar)
{
    return get_dp_id_data_for_xyz(mem_ctx, user_name, domain_name, BE_REQ_USER,
                                   _ar);
}

struct ipa_get_trusted_override_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *sdap_id_ctx;
    struct ipa_options *ipa_options;
    const char *ipa_realm;
    const char *ipa_view_name;
    struct dp_id_data *ar;

    struct sdap_id_op *sdap_op;
    int dp_error;
    struct sysdb_attrs *override_attrs;
    char *filter;
};

static void ipa_get_trusted_override_connect_done(struct tevent_req *subreq);
static errno_t ipa_get_trusted_override_qualify_name(
                                struct ipa_get_trusted_override_state *state);
static void ipa_get_trusted_override_done(struct tevent_req *subreq);

struct tevent_req *ipa_get_trusted_override_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sdap_id_ctx *sdap_id_ctx,
                                            struct ipa_options *ipa_options,
                                            const char *ipa_realm,
                                            const char *view_name,
                                            struct dp_id_data *ar)
{
    int ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_get_trusted_override_state *state;

    req = tevent_req_create(mem_ctx, &state, struct ipa_get_trusted_override_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->sdap_id_ctx = sdap_id_ctx;
    state->ipa_options = ipa_options;
    state->ipa_realm = ipa_realm;
    state->ar = ar;
    state->dp_error = -1;
    state->override_attrs = NULL;
    state->filter = NULL;

    if (view_name == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "View not defined, nothing to do.\n");
        ret = EOK;
        goto done;
    }

    if (is_default_view(view_name)) {
        state->ipa_view_name = IPA_DEFAULT_VIEW_NAME;
    } else {
        state->ipa_view_name = view_name;
    }

    state->sdap_op = sdap_id_op_create(state,
                                       state->sdap_id_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_get_trusted_override_connect_done, req);

    return req;

done:
    if (ret != EOK) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
    } else {
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
    }
    tevent_req_post(req, state->ev);

    return req;
}

static void ipa_get_trusted_override_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_trusted_override_state *state = tevent_req_data(req,
                                              struct ipa_get_trusted_override_state);
    int ret;
    char *basedn;
    char *search_base;
    struct ipa_options *ipa_opts = state->ipa_options;

    ret = sdap_id_op_connect_recv(subreq, &state->dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (state->dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No IPA server is available, going offline\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to IPA server: [%d](%s)\n",
                   ret, strerror(ret));
        }

        goto fail;
    }

    ret = domain_to_basedn(state, state->ipa_realm, &basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "domain_to_basedn failed.\n");
        goto fail;
    }

    search_base = talloc_asprintf(state, "cn=%s,%s", state->ipa_view_name,
                                       ipa_opts->views_search_bases[0]->basedn);
    if (search_base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = dp_id_data_to_override_filter(state, state->ipa_options, state->ar,
                                         &state->filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "dp_id_data_to_override_filter failed.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Searching for overrides in view [%s] with filter [%s].\n",
          state->ipa_view_name, state->filter);

    subreq = sdap_get_generic_send(state, state->ev, state->sdap_id_ctx->opts,
                                 sdap_id_op_handle(state->sdap_op), search_base,
                                 LDAP_SCOPE_SUBTREE,
                                 state->filter, NULL,
                                 state->ipa_options->override_map,
                                 IPA_OPTS_OVERRIDE,
                                 dp_opt_get_int(state->sdap_id_ctx->opts->basic,
                                                SDAP_SEARCH_TIMEOUT),
                                 false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_get_trusted_override_done, req);
    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    return;
}

static void ipa_get_trusted_override_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_trusted_override_state *state = tevent_req_data(req,
                                              struct ipa_get_trusted_override_state);
    int ret;
    size_t reply_count = 0;
    struct sysdb_attrs **reply = NULL;

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_trusted_override request failed.\n");
        goto fail;
    }

    if (reply_count == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "No override found with filter [%s].\n",
                                state->filter);
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
        return;
    } else if (reply_count == MAX_USER_AND_GROUP_REPLIES &&
               (state->ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_USER_AND_GROUP) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Found two overrides with BE_REQ_USER_AND_GROUP filter [%s].\n",
              state->filter);
        ret = check_and_filter_user_and_group(state->ipa_options, reply,
                                              &reply_count);
        if (ret != EOK) {
            goto fail;
        }
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found [%zu] overrides with filter [%s], expected only 1.\n",
              reply_count, state->filter);
        ret = EINVAL;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Found override for object with filter [%s].\n",
                            state->filter);
    state->override_attrs = reply[0];

    ret = ipa_get_trusted_override_qualify_name(state);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot qualify object name\n");
        goto fail;
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    return;
}

static errno_t ipa_get_trusted_override_qualify_name(
                                struct ipa_get_trusted_override_state *state)
{
    int ret;
    struct ldb_message_element *name;
    char *fqdn;

    ret = sysdb_attrs_get_el_ext(state->override_attrs, SYSDB_NAME,
                                 false, &name);
    if (ret == ENOENT) {
        return EOK; /* Does not override name */
    } else if (ret != EOK && ret != ENOENT) {
        return ret;
    }

    fqdn = sss_create_internal_fqname(name->values,
                                      (const char *) name->values[0].data,
                                      state->ar->domain);
    if (fqdn == NULL) {
        return ENOMEM;
    }

    name->values[0].data = (uint8_t *) fqdn;
    name->values[0].length = strlen(fqdn);
    return EOK;
}

errno_t ipa_get_trusted_override_recv(struct tevent_req *req, int *dp_error_out,
                                 TALLOC_CTX *mem_ctx,
                                 struct sysdb_attrs **override_attrs)
{
    struct ipa_get_trusted_override_state *state = tevent_req_data(req,
                                              struct ipa_get_trusted_override_state);

    if (dp_error_out != NULL) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (override_attrs != NULL) {
        *override_attrs = talloc_steal(mem_ctx, state->override_attrs);
    }

    return EOK;
}
