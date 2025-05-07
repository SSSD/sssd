/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2020 Red Hat

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

#include <errno.h>
#include <gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <ldb.h>

#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/pam/pamsrv.h"
#include "sss_client/sss_cli.h"
#include "util/util.h"
#include "util/sss_utf8.h"

static errno_t read_str(size_t body_len,
                        uint8_t *body,
                        size_t *pctr,
                        const char **_str)
{
    size_t i;

    for (i = *pctr; i < body_len && body[i] != 0; i++) {
        /* counting */
    }

    if (i >= body_len) {
        return EINVAL;
    }

    if (!sss_utf8_check(&body[*pctr], i - *pctr)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not UTF-8 string!\n");
        return EINVAL;
    }

    *_str = (const char *)&body[*pctr];
    *pctr = i + 1;

    return EOK;
}

static bool pam_gssapi_should_check_upn(struct pam_ctx *pam_ctx,
                                        struct sss_domain_info *domain)
{
    if (domain->gssapi_check_upn != NULL) {
        if (strcasecmp(domain->gssapi_check_upn, "true") == 0) {
            return true;
        }

        if (strcasecmp(domain->gssapi_check_upn, "false") == 0) {
            return false;
        }

        DEBUG(SSSDBG_MINOR_FAILURE, "Invalid value for %s: %s\n",
              CONFDB_PAM_GSSAPI_CHECK_UPN, domain->gssapi_check_upn);
        return false;
    }

    return pam_ctx->gssapi_check_upn;
}

static int pam_gssapi_check_indicators(TALLOC_CTX *mem_ctx,
                                       const char *pam_service,
                                       char **gssapi_indicators_map,
                                       char **indicators)
{
    char *authind = NULL;
    size_t pam_len = strlen(pam_service);
    char **map = gssapi_indicators_map;
    char **result = NULL;
    int res;

    authind = talloc_strdup(mem_ctx, "");
    if (authind == NULL) {
        return ENOMEM;
    }

    for (int i = 0; map[i]; i++) {
        if (map[i][0] == '-') {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Indicators aren't used for [%s]\n",
                  pam_service);
            talloc_free(authind);
            return EOK;
        }
        if (!strchr(map[i], ':')) {
            authind = talloc_asprintf_append(authind, "%s ", map[i]);
            if (authind == NULL) {
                /* Since we allocate on pam_ctx, caller will free it */
                return ENOMEM;
            }
            continue;
        }

        res = strncmp(map[i], pam_service, pam_len);
        if (res == 0) {
            if (strlen(map[i]) > pam_len) {
                if (map[i][pam_len] != ':') {
                    /* different PAM service, skip it */
                    continue;
                }

                if (map[i][pam_len + 1] == '-') {
                    DEBUG(SSSDBG_TRACE_FUNC,
                        "Indicators aren't used for [%s]\n",
                        pam_service);
                    talloc_free(authind);
                    return EOK;
                }

                authind = talloc_asprintf_append(authind, "%s ",
                                                 map[i] + (pam_len + 1));
                if (authind == NULL) {
                    /* Since we allocate on pam_ctx, caller will free it */
                    return ENOMEM;
                }
            } else {
                DEBUG(SSSDBG_MINOR_FAILURE, "Invalid value for %s: [%s]\n",
                      CONFDB_PAM_GSSAPI_INDICATORS_MAP, map[i]);
                talloc_free(authind);
                return EINVAL;
            }
        }
    }

    res = ENOENT;
    map = NULL;

    if (authind[0] == '\0') {
        /* empty list of per-service indicators -> skip */
        goto done;
    }

    /* trim a space after the final indicator
     * to prevent split_on_separator() to fail */
    authind[strlen(authind) - 1] = '\0';

    res = split_on_separator(mem_ctx, authind, ' ', true, true,
                             &map, NULL);
    if (res != 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
            "Cannot parse list of indicators: [%s]\n", authind);
        res = EINVAL;
        goto done;
    }

    res = diff_string_lists(mem_ctx, indicators, map, NULL, NULL, &result);
    if (res != 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Cannot diff lists of indicators\n");
        res = EINVAL;
        goto done;
    }

    if (result && result[0] != NULL) {
        for (int i = 0; result[i]; i++) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "indicator [%s] is allowed for PAM service [%s]\n",
                  result[i], pam_service);
        }
        res = EOK;
        goto done;
    }

    res = EPERM;

done:
    talloc_free(result);
    talloc_free(authind);
    talloc_free(map);
    return res;
}

static bool pam_gssapi_allowed(struct pam_ctx *pam_ctx,
                               struct sss_domain_info *domain,
                               const char *service)
{
    char **list = pam_ctx->gssapi_services;

    if (domain->gssapi_services != NULL) {
        list = domain->gssapi_services;
    }

    if (strcmp(service, "-") == 0) {
        /* Dash is used as a "not set" value to allow to explicitly disable
         * gssapi auth for specific domain. Disallow this service to be safe.
         */
        DEBUG(SSSDBG_TRACE_FUNC, "Dash - was used as a PAM service name. "
              "GSSAPI authentication is not allowed.\n");
        return false;
    }

    return string_in_list(service, list, true);
}

static char *pam_gssapi_target(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain)
{
    return talloc_asprintf(mem_ctx, "host@%s", domain->hostname);
}

static const char *pam_gssapi_get_upn(struct cache_req_result *result)
{
    if (result->count == 0) {
        return NULL;
    }

    /* Canonical UPN should be available if the user has kinited through SSSD.
     * Use it as a hint for GSSAPI. Default to empty string so it may be
     * more easily transffered over the wire. */
    return ldb_msg_find_attr_as_string(result->msgs[0], SYSDB_CANONICAL_UPN, "");
}

static const char *pam_gssapi_get_name(struct cache_req_result *result)
{
    if (result->count == 0) {
        return NULL;
    }

    /* Return username known to SSSD to make sure we authenticated as the same
     * user after GSSAPI handshake. */
    return ldb_msg_find_attr_as_string(result->msgs[0], SYSDB_NAME, NULL);
}

static errno_t pam_gssapi_init_parse(struct cli_protocol *pctx,
                                     const char **_service,
                                     const char **_username)
{
    size_t body_len;
    size_t pctr = 0;
    uint8_t *body;
    errno_t ret;

    sss_packet_get_body(pctx->creq->in, &body, &body_len);
    if (body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid input\n");
        return EINVAL;
    }

    ret = read_str(body_len, body, &pctr, _service);
    if (ret != EOK) {
        return ret;
    }

    ret = read_str(body_len, body, &pctr, _username);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static errno_t pam_gssapi_init_reply(struct cli_protocol *pctx,
                                     const char *domain,
                                     const char *target,
                                     const char *upn,
                                     const char *username)
{
    size_t reply_len;
    size_t body_len;
    size_t pctr;
    uint8_t *body;
    errno_t ret;

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create a new packet [%d]; %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    reply_len =  strlen(username) + 1;
    reply_len += strlen(domain) + 1;
    reply_len += strlen(target) + 1;
    reply_len += strlen(upn) + 1;

    ret = sss_packet_grow(pctx->creq->out, reply_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create response: %s\n",
              sss_strerror(ret));
        return ret;
    }

    sss_packet_get_body(pctx->creq->out, &body, &body_len);

    pctr = 0;
    SAFEALIGN_SETMEM_STRING(&body[pctr], username, strlen(username) + 1, &pctr);
    SAFEALIGN_SETMEM_STRING(&body[pctr], domain, strlen(domain) + 1, &pctr);
    SAFEALIGN_SETMEM_STRING(&body[pctr], target, strlen(target) + 1, &pctr);
    SAFEALIGN_SETMEM_STRING(&body[pctr], upn, strlen(upn) + 1, &pctr);

    return EOK;
}

struct gssapi_init_state {
    struct cli_ctx *cli_ctx;
    const char *username;
    const char *service;
};

static void pam_cmd_gssapi_init_done(struct tevent_req *req);

int pam_cmd_gssapi_init(struct cli_ctx *cli_ctx)
{
    struct gssapi_init_state *state;
    struct cli_protocol *pctx;
    struct tevent_req *req;
    const char *username;
    const char *service;
    const char *attrs[] = { SYSDB_NAME, SYSDB_CANONICAL_UPN, NULL };
    errno_t ret;

    state = talloc_zero(cli_ctx, struct gssapi_init_state);
    if (state == NULL) {
        return ENOMEM;
    }

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    ret = pam_gssapi_init_parse(pctx, &service, &username);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse input [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    state->cli_ctx = cli_ctx;
    state->service = service;
    state->username = username;

    DEBUG(SSSDBG_TRACE_ALL,
          "Requesting GSSAPI authentication of [%s] in service [%s]\n",
          username, service);

    req = cache_req_user_by_name_attrs_send(cli_ctx, cli_ctx->ev, cli_ctx->rctx,
                                            cli_ctx->rctx->ncache, 0,
                                            NULL, username, attrs);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, pam_cmd_gssapi_init_done, state);

    ret = EOK;

done:
    if (ret != EOK) {
        sss_cmd_send_error(cli_ctx, ret);
        sss_cmd_done(cli_ctx, NULL);
    }

    return EOK;
}

static void pam_cmd_gssapi_init_done(struct tevent_req *req)
{
    struct gssapi_init_state *state;
    struct cache_req_result *result;
    struct cli_protocol *pctx;
    struct pam_ctx *pam_ctx;
    const char *username;
    const char *upn;
    char *target;
    errno_t ret;

    state = tevent_req_callback_data(req, struct gssapi_init_state);
    pctx = talloc_get_type(state->cli_ctx->protocol_ctx, struct cli_protocol);
    pam_ctx = talloc_get_type(state->cli_ctx->rctx->pvt_ctx, struct pam_ctx);

    ret = cache_req_user_by_name_attrs_recv(state, req, &result);
    talloc_zfree(req);
    if (ret == ENOENT || ret == ERR_DOMAIN_NOT_FOUND) {
        ret = ENOENT;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    if (!pam_gssapi_allowed(pam_ctx, result->domain, state->service)) {
        ret = ENOTSUP;
        goto done;
    }

    username = pam_gssapi_get_name(result);
    if (username == NULL) {
        /* User with no name? */
        ret = ERR_INTERNAL;
        goto done;
    }

    upn = pam_gssapi_get_upn(result);
    if (upn == NULL) {
        /* UPN hint may be an empty string, but not NULL. */
        ret = ERR_INTERNAL;
        goto done;
    }

    target = pam_gssapi_target(state, result->domain);
    if (target == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Trying GSSAPI auth: User[%s], Domain[%s], UPN[%s], Target[%s]\n",
          username, result->domain->name, upn, target);

    ret = pam_gssapi_init_reply(pctx, result->domain->name, target, upn,
                                username);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to construct reply [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    DEBUG(SSSDBG_TRACE_FUNC, "Returning [%d]: %s\n", ret, sss_strerror(ret));

    if (ret == EOK) {
        sss_packet_set_error(pctx->creq->out, EOK);
    } else {
        sss_cmd_send_error(state->cli_ctx, ret);
    }

    sss_cmd_done(state->cli_ctx, state);
}

static void gssapi_log_status(int type, OM_uint32 status_code)
{
    OM_uint32 message_context = 0;
    gss_buffer_desc buf;
    OM_uint32 minor;

    do {
        gss_display_status(&minor, status_code, type, GSS_C_NO_OID,
                           &message_context, &buf);
        DEBUG(SSSDBG_OP_FAILURE, "GSSAPI: %.*s\n", (int)buf.length,
              (char *)buf.value);
        gss_release_buffer(&minor, &buf);
    } while (message_context != 0);
}

static void gssapi_log_error(OM_uint32 major, OM_uint32 minor)
{
    gssapi_log_status(GSS_C_GSS_CODE, major);
    gssapi_log_status(GSS_C_MECH_CODE, minor);
}

static char *gssapi_get_name(TALLOC_CTX *mem_ctx, gss_name_t gss_name)
{
    gss_buffer_desc buf;
    OM_uint32 major;
    OM_uint32 minor;
    char *exported;

    major = gss_display_name(&minor, gss_name, &buf, NULL);
    if (major != GSS_S_COMPLETE) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to export name\n");
        return NULL;
    }

    exported = talloc_strndup(mem_ctx, buf.value, buf.length);
    gss_release_buffer(&minor, &buf);

    if (exported == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    return exported;
}

#define AUTH_INDICATORS_TAG "auth-indicators"

static char **gssapi_get_indicators(TALLOC_CTX *mem_ctx, gss_name_t gss_name)
{
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    int is_mechname;
    OM_uint32 major;
    OM_uint32 minor;
    gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc display_value = GSS_C_EMPTY_BUFFER;
    char *exported = NULL;
    char **map = NULL;
    int res;

    major = gss_inquire_name(&minor, gss_name, &is_mechname, NULL, &attrs);
    if (major != GSS_S_COMPLETE) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to inquire name\n");
        return NULL;
    }

    if (attrs == GSS_C_NO_BUFFER_SET) {
        DEBUG(SSSDBG_TRACE_FUNC, "No krb5 attributes in the ticket\n");
        return NULL;
    }

    exported = talloc_strdup(mem_ctx, "");
    if (exported == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to pre-allocate indicators\n");
        goto done;
    }

    for (int i = 0; i < attrs->count; i++) {
        int authenticated = 0;
        int complete = 0;
        int more = -1;

        /* skip anything but auth-indicators */
        if (strncmp(AUTH_INDICATORS_TAG, attrs->elements[i].value,
                    sizeof(AUTH_INDICATORS_TAG) - 1) != 0)
            continue;

        /* retrieve all indicators */
        while (more != 0) {
            value.value = NULL;
            display_value.value = NULL;

            major = gss_get_name_attribute(&minor, gss_name,
                                            &attrs->elements[i],
                                            &authenticated,
                                            &complete, &value,
                                            &display_value,
                                            &more);
            if (major != GSS_S_COMPLETE) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                        "Unable to retrieve an attribute\n");
                goto done;
            }

            if ((value.value != NULL) && authenticated) {
                DEBUG(SSSDBG_TRACE_FUNC,
                        "attribute's [%.*s] value [%.*s] authenticated\n",
                        (int) attrs->elements[i].length,
                        (char*) attrs->elements[i].value,
                        (int) value.length,
                        (char*) value.value);
                exported = talloc_asprintf_append(exported, "%.*s ",
                                                (int) value.length,
                                                (char*) value.value);
            }

            if (exported == NULL) {
                /* Since we allocate on mem_ctx, caller will free
                 * the previous version of 'exported' */
                DEBUG(SSSDBG_CRIT_FAILURE,
                        "Unable to collect an attribute value\n");
                goto done;
            }
            (void) gss_release_buffer(&minor, &value);
            (void) gss_release_buffer(&minor, &display_value);
        }
    }

    if (exported[0] != '\0') {
        /* trim a space after the final indicator
         * to prevent split_on_separator() to fail */
        exported[strlen(exported) - 1] = '\0';
    } else {
        /* empty list */
        goto done;
    }

    res = split_on_separator(mem_ctx, exported, ' ', true, true,
                            &map, NULL);
    if (res != 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
            "Cannot parse list of indicators: [%s]\n", exported);
        goto done;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "authentication indicators: [%s]\n",
              exported);
    }

done:
    (void) gss_release_buffer(&minor, &value);
    (void) gss_release_buffer(&minor, &display_value);
    (void) gss_release_buffer_set(&minor, &attrs);

    talloc_free(exported);
    return map;
}


struct gssapi_state {
    struct cli_ctx *cli_ctx;
    struct sss_domain_info *domain;
    const char *username;

    char *authenticated_upn;
    char **auth_indicators;
    bool established;
    gss_ctx_id_t ctx;
};

int gssapi_state_destructor(struct gssapi_state *state)
{
    OM_uint32 minor;

    gss_delete_sec_context(&minor, &state->ctx, NULL);

    return 0;
}

static struct gssapi_state *gssapi_get_state(struct cli_ctx *cli_ctx,
                                             const char *username,
                                             struct sss_domain_info *domain)
{
    struct gssapi_state *state;

    state = talloc_get_type(cli_ctx->state_ctx, struct gssapi_state);
    if (state != NULL) {
        return state;
    }

    state = talloc_zero(cli_ctx, struct gssapi_state);
    if (state == NULL) {
        return NULL;
    }

    state->username = talloc_strdup(state, username);
    if (state == NULL) {
        talloc_free(state);
        return NULL;
    }

    state->domain = domain;
    state->cli_ctx = cli_ctx;
    state->ctx = GSS_C_NO_CONTEXT;
    talloc_set_destructor(state, gssapi_state_destructor);

    cli_ctx->state_ctx = state;

    return state;
}

static errno_t gssapi_get_creds(const char *keytab,
                                const char *target,
                                gss_cred_id_t *_creds)
{
    gss_key_value_set_desc cstore = {0, NULL};
    gss_key_value_element_desc el;
    gss_buffer_desc name_buf;
    gss_name_t name = GSS_C_NO_NAME;
    OM_uint32 major;
    OM_uint32 minor;
    errno_t ret;

    if (keytab != NULL) {
        el.key = "keytab";
        el.value = keytab;
        cstore.count = 1;
        cstore.elements = &el;
    }

    if (target != NULL) {
        name_buf.value = discard_const(target);
        name_buf.length = strlen(target);

        major = gss_import_name(&minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
                                &name);
        if (GSS_ERROR(major)) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not import name [%s] "
                 "[maj:0x%x, min:0x%x]\n", target, major, minor);

            gssapi_log_error(major, minor);

            ret = EIO;
            goto done;
        }
    }

    ret = sss_set_cap_effective(CAP_DAC_READ_SEARCH, true);
    if (ret != 0) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Failed to elevate CAP_DAC_READ_SEARCH to effective set\n");
    }
    major = gss_acquire_cred_from(&minor, name, GSS_C_INDEFINITE,
                                  GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cstore,
                                  _creds, NULL, NULL);
    ret = sss_set_cap_effective(CAP_DAC_READ_SEARCH, false);
    if (ret != 0) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Failed to drop CAP_DAC_READ_SEARCH from effective set\n");
    }
    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to read credentials from [%s] "
              "[maj:0x%x, min:0x%x]\n", keytab ? keytab : "default",
              major, minor);

        gssapi_log_error(major, minor);

        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    gss_release_name(&minor, &name);

    return ret;
}

static errno_t
gssapi_handshake(struct gssapi_state *state,
                 struct cli_protocol *pctx,
                 const char *keytab,
                 const char *target,
                 uint8_t *gss_data,
                 size_t gss_data_len)
{
    OM_uint32 flags = GSS_C_MUTUAL_FLAG;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc input;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_cred_id_t creds;
    OM_uint32 ret_flags;
    gss_OID mech_type;
    OM_uint32 major;
    OM_uint32 minor;
    errno_t ret;

    input.value = gss_data;
    input.length = gss_data_len;

    ret = gssapi_get_creds(keytab, target, &creds);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_set_cap_effective(CAP_DAC_READ_SEARCH, true);
    if (ret != 0) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Failed to elevate CAP_DAC_READ_SEARCH to effective set\n");
    }
    major = gss_accept_sec_context(&minor, &state->ctx, creds,
                                   &input, NULL, &client_name, &mech_type,
                                   &output, &ret_flags, NULL, NULL);
    ret = sss_set_cap_effective(CAP_DAC_READ_SEARCH, false);
    if (ret != 0) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Failed to drop CAP_DAC_READ_SEARCH from effective set\n");
    }
    if (major == GSS_S_CONTINUE_NEEDED || output.length > 0) {
        ret = sss_packet_set_body(pctx->creq->out, output.value, output.length);
        if (ret != EOK) {
            goto done;
        }
    }

    if (GSS_ERROR(major)) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to establish GSS context "
              "[maj:0x%x, min:0x%x]\n", major, minor);

        gssapi_log_error(major, minor);
        ret = EIO;
        goto done;
    }

    if (major == GSS_S_CONTINUE_NEEDED) {
        ret = EOK;
        goto done;
    } else if (major != GSS_S_COMPLETE) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to establish GSS context, unexpected "
              "value: 0x%x\n", major);
        ret = EIO;
        goto done;
    }

    if ((ret_flags & flags) != flags) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "Negotiated context does not support requested flags\n");
        state->established = false;
        ret = EIO;
        goto done;
    }

    state->authenticated_upn = gssapi_get_name(state, client_name);
    if (state->authenticated_upn == NULL) {
        state->established = false;
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Security context established with [%s]\n",
          state->authenticated_upn);

    state->auth_indicators = gssapi_get_indicators(state, client_name);

    state->established = true;
    ret = EOK;

done:
    gss_release_cred(&minor, &creds);
    gss_release_buffer(&minor, &output);
    gss_release_name(&minor, &client_name);

    return ret;
}

static errno_t pam_cmd_gssapi_sec_ctx_parse(struct cli_protocol *pctx,
                                            const char **_pam_service,
                                            const char **_username,
                                            const char **_domain,
                                            uint8_t **_gss_data,
                                            size_t *_gss_data_len)
{
    size_t body_len;
    uint8_t *body;
    size_t pctr;
    errno_t ret;

    sss_packet_get_body(pctx->creq->in, &body, &body_len);
    if (body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid input\n");
        return EINVAL;
    }

    pctr = 0;
    ret = read_str(body_len, body, &pctr, _pam_service);
    if (ret != EOK) {
        return ret;
    }

    ret = read_str(body_len, body, &pctr, _username);
    if (ret != EOK) {
        return ret;
    }

    ret = read_str(body_len, body, &pctr, _domain);
    if (ret != EOK) {
        return ret;
    }

    *_gss_data = (pctr == body_len) ? NULL : body + pctr;
    *_gss_data_len = body_len - pctr;

    return EOK;
}

static void pam_cmd_gssapi_sec_ctx_done(struct tevent_req *req);

int
pam_cmd_gssapi_sec_ctx(struct cli_ctx *cli_ctx)
{
    struct sss_domain_info *domain;
    struct gssapi_state *state;
    struct cli_protocol *pctx;
    struct pam_ctx *pam_ctx;
    struct tevent_req *req;
    const char *pam_service;
    const char *domain_name;
    const char *username;
    char *target;
    char **indicators_map = NULL;
    size_t gss_data_len;
    uint8_t *gss_data;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);
    pam_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct pam_ctx);

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create a new packet [%d]; %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = pam_cmd_gssapi_sec_ctx_parse(pctx, &pam_service, &username,
                                       &domain_name, &gss_data, &gss_data_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to parse input data [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    domain = find_domain_by_name(cli_ctx->rctx->domains, domain_name, false);
    if (domain == NULL) {
        ret = EINVAL;
        goto done;
    }

    if (!pam_gssapi_allowed(pam_ctx, domain, pam_service)) {
        ret = ENOTSUP;
        goto done;
    }

    target = pam_gssapi_target(cli_ctx, domain);
    if (target == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state = gssapi_get_state(cli_ctx, username, domain);
    if (state == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (strcmp(username, state->username) != 0 || state->domain != domain) {
        /* This should not happen, but be paranoid. */
        DEBUG(SSSDBG_CRIT_FAILURE, "Different input user then who initiated "
              "the request!\n");
        ret = EPERM;
        goto done;
    }

    if (state->established) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Security context is already established\n");
        ret = EPERM;
        goto done;
    }

    ret = gssapi_handshake(state, pctx, domain->krb5_keytab, target, gss_data,
                           gss_data_len);
    if (ret != EOK || !state->established) {
        goto done;
    }

    /* Use map for auth-indicators from the domain, if defined and
     * fallback to the [pam] section otherwise */
    indicators_map = domain->gssapi_indicators_map ?
                     domain->gssapi_indicators_map :
                     (pam_ctx->gssapi_indicators_map ?
                      pam_ctx->gssapi_indicators_map : NULL);
    if (indicators_map != NULL) {
        ret = pam_gssapi_check_indicators(state,
                                          pam_service,
                                          indicators_map,
                                          state->auth_indicators);
        DEBUG(SSSDBG_TRACE_FUNC,
              "Check if acquired service ticket has req. indicators: %d\n",
              ret);
        if ((ret == EPERM) || (ret == ENOMEM) || (ret == EINVAL)) {
            /* skip further checks if denied or no memory,
             * ENOENT means the check is not applicable */
            goto done;
        }
    }

    if (!pam_gssapi_should_check_upn(pam_ctx, domain)) {
        /* We are done. */
        goto done;
    }

    /* We have established the security context. Now check the the principal
     * used for authorization can be associated with the user. We have
     * already done initgroups before so we could just search the sysdb
     * directly, but use cache req to avoid looking up a possible expired
     * object if the handshake took longer. */

    DEBUG(SSSDBG_TRACE_FUNC, "Checking that target user matches UPN\n");

    req = cache_req_user_by_upn_send(cli_ctx, cli_ctx->ev, cli_ctx->rctx,
                                     cli_ctx->rctx->ncache, 0,
                                     CACHE_REQ_POSIX_DOM,
                                     domain->name, state->authenticated_upn);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, pam_cmd_gssapi_sec_ctx_done, state);

    return EOK;

done:
    DEBUG(SSSDBG_TRACE_FUNC, "Returning [%d]: %s\n", ret, sss_strerror(ret));

    if (ret == EOK) {
        sss_packet_set_error(pctx->creq->out, EOK);
    } else {
        sss_cmd_send_error(cli_ctx, ret);
    }

    sss_cmd_done(cli_ctx, NULL);
    return EOK;
}

static void pam_cmd_gssapi_sec_ctx_done(struct tevent_req *req)
{
    struct gssapi_state *state;
    struct cache_req_result *result;
    struct cli_protocol *pctx;
    const char *name;
    errno_t ret;

    state = tevent_req_callback_data(req, struct gssapi_state);
    pctx = talloc_get_type(state->cli_ctx->protocol_ctx, struct cli_protocol);

    ret = cache_req_user_by_upn_recv(state, req, &result);
    talloc_zfree(req);
    if (ret == ENOENT || ret == ERR_DOMAIN_NOT_FOUND) {
        /* We have no match. Return failure. */
        DEBUG(SSSDBG_TRACE_FUNC, "User with UPN [%s] was not found. "
              "Authentication failed.\n", state->authenticated_upn);
        ret = EACCES;
        goto done;
    } else if (ret != EOK) {
        /* Generic error. Return failure. */
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup user by UPN [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Check that username match. */
    name = ldb_msg_find_attr_as_string(result->msgs[0], SYSDB_NAME, NULL);
    if (name == NULL || strcmp(name, state->username) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "UPN [%s] does not match target user [%s]. "
              "Authentication failed.\n", state->authenticated_upn,
              state->username);
        ret = EACCES;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "User [%s] match UPN [%s]. Authentication was "
          "successful.\n", state->username, state->authenticated_upn);

    ret = EOK;

done:
    DEBUG(SSSDBG_TRACE_FUNC, "Returning [%d]: %s\n", ret, sss_strerror(ret));

    if (ret == EOK) {
        sss_packet_set_error(pctx->creq->out, EOK);
    } else {
        sss_cmd_send_error(state->cli_ctx, ret);
    }

    sss_cmd_done(state->cli_ctx, state);
}
