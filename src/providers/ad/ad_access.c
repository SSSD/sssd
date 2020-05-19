/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <security/pam_modules.h>
#include <syslog.h>

#include "src/util/util.h"
#include "src/providers/data_provider.h"
#include "src/providers/backend.h"
#include "src/providers/ad/ad_access.h"
#include "providers/ad/ad_gpo.h"
#include "src/providers/ad/ad_common.h"
#include "src/providers/ldap/sdap_access.h"

/*
 * More advanced format can be used to restrict the filter to a specific
 * domain or a specific forest. This format is KEYWORD:NAME:FILTER
 *
 *  KEYWORD can be one of DOM or FOREST
 *      KEYWORD can be missing
 *  NAME is a label.
 *      - if KEYWORD equals DOM or missing completely, the filter is applied
 *        for users from domain named NAME only
 *      - if KEYWORD equals FOREST, the filter is applied on users from
 *        forest named NAME only
 *  examples of valid filters are:
 *      apply filter on domain called dom1 only:
 *          dom1:(memberOf=cn=admins,ou=groups,dc=dom1,dc=com)
 *      apply filter on domain called dom2 only:
 *          DOM:dom2:(memberOf=cn=admins,ou=groups,dc=dom2,dc=com)
 *      apply filter on forest called EXAMPLE.COM only:
 *          FOREST:EXAMPLE.COM:(memberOf=cn=admins,ou=groups,dc=example,dc=com)
 *
 * If any of the extended formats are used, the filter MUST be enclosed
 * already.
 */

/* From least specific */
#define AD_FILTER_GENERIC 0x01
#define AD_FILTER_FOREST  0x02
#define AD_FILTER_DOMAIN  0x04

#define KW_FOREST "FOREST"
#define KW_DOMAIN "DOM"

/* parse filter in the format domain_name:filter */
static errno_t
parse_sub_filter(TALLOC_CTX *mem_ctx, const char *full_filter,
                 char **filter, char **sub_name, int *flags,
                 const int flagconst)
{
    char *specdelim;

    specdelim = strchr(full_filter, ':');
    if (specdelim == NULL) return EINVAL;

    /* Make sure the filter is already enclosed in brackets */
    if (*(specdelim+1) != '(') return EINVAL;

    *sub_name = talloc_strndup(mem_ctx, full_filter, specdelim - full_filter);
    *filter = talloc_strdup(mem_ctx, specdelim+1);
    if (*sub_name == NULL || *filter == NULL) return ENOMEM;

    *flags = flagconst;
    return EOK;
}

static inline errno_t
parse_dom_filter(TALLOC_CTX *mem_ctx, const char *dom_filter,
                 char **filter, char **domname, int *flags)
{
    return parse_sub_filter(mem_ctx, dom_filter, filter, domname,
                            flags, AD_FILTER_DOMAIN);
}

static inline errno_t
parse_forest_filter(TALLOC_CTX *mem_ctx, const char *forest_filter,
                    char **filter, char **forest_name, int *flags)
{
    return parse_sub_filter(mem_ctx, forest_filter, filter, forest_name,
                            flags, AD_FILTER_FOREST);
}


static errno_t
parse_filter(TALLOC_CTX *mem_ctx, const char *full_filter,
             char **filter, char **spec, int *flags)
{
    char *kwdelim, *specdelim;

    if (filter == NULL || spec == NULL || flags == NULL) return EINVAL;

    kwdelim = strchr(full_filter, ':');
    if (kwdelim != NULL) {
        specdelim = strchr(kwdelim+1, ':');

        if (specdelim == NULL) {
            /* There is a single keyword. Treat it as a domain name */
            return parse_dom_filter(mem_ctx, full_filter, filter, spec, flags);
        } else if (strncmp(full_filter, "DOM", kwdelim-full_filter) == 0) {
            /* The format must be DOM:domain_name:filter */
            if (specdelim && specdelim-kwdelim <= 1) {
                /* Check if there is some domain_name */
                return EINVAL;
            }

            return parse_dom_filter(mem_ctx, kwdelim + 1, filter, spec, flags);
        } else if (strncmp(full_filter, "FOREST", kwdelim-full_filter) == 0) {
            /* The format must be FOREST:forest_name:filter */
            if (specdelim && specdelim-kwdelim <= 1) {
                /* Check if there is some domain_name */
                return EINVAL;
            }

            return parse_forest_filter(mem_ctx, kwdelim + 1,
                                       filter, spec, flags);
        }

        /* Malformed option */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Keyword in filter [%s] did not match expected format\n",
               full_filter);
        return EINVAL;
    }

    /* No keyword. Easy. */
    *filter = talloc_strdup(mem_ctx, full_filter);
    if (*filter == NULL) return ENOMEM;

    *spec = NULL;
    *flags = AD_FILTER_GENERIC;
    return EOK;
}

static errno_t
ad_parse_access_filter(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *dom,
                       const char *filter_list,
                       char **_filter)
{
    char **filters;
    int nfilters;
    errno_t ret;
    char *best_match;
    int best_flags;
    char *filter;
    char *spec;
    int flags;
    TALLOC_CTX *tmp_ctx;
    int i = 0;

    if (_filter == NULL) return EINVAL;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (filter_list == NULL) {
        *_filter = NULL;
        ret = EOK;
        goto done;
    }

    ret = split_on_separator(tmp_ctx, filter_list, '?', true, true,
                             &filters, &nfilters);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot parse the list of ad_access_filters\n");
        goto done;
    }

    best_match = NULL;
    best_flags = 0;
    for (i=0; i < nfilters; i++) {
        ret = parse_filter(tmp_ctx, filters[i], &filter, &spec, &flags);
        if (ret != EOK) {
            /* Skip the faulty filter. At worst, the user won't be
             * allowed access */
            DEBUG(SSSDBG_MINOR_FAILURE, "Access filter [%s] could not be "
                  "parsed, skipping\n", filters[i]);
            continue;
        }

        if (flags & AD_FILTER_DOMAIN && strcasecmp(spec, dom->name) != 0) {
            /* If the filter specifies a domain, it must match the
             * domain the user comes from
             */
            continue;
        }

        if (flags & AD_FILTER_FOREST && strcasecmp(spec, dom->forest) != 0) {
            /* If the filter specifies a forest, it must match the
             * forest the user comes from
             */
            continue;
        }

        if (flags > best_flags) {
            best_flags = flags;
            best_match = filter;
        }
    }

    ret = EOK;
    /* Make sure the result is enclosed in brackets */
    *_filter = sdap_get_access_filter(mem_ctx, best_match);
done:
    talloc_free(tmp_ctx);
    return ret;
}

struct ad_access_state {
    struct tevent_context *ev;
    struct ad_access_ctx *ctx;
    struct pam_data *pd;
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;

    char *filter;
    struct sdap_id_conn_ctx **clist;
    int cindex;
};

static errno_t
ad_sdap_access_step(struct tevent_req *req, struct sdap_id_conn_ctx *conn);
static void
ad_sdap_access_done(struct tevent_req *req);

static struct tevent_req *
ad_access_send(TALLOC_CTX *mem_ctx,
               struct tevent_context *ev,
               struct be_ctx *be_ctx,
               struct sss_domain_info *domain,
               struct ad_access_ctx *ctx,
               struct pam_data *pd)
{
    struct tevent_req *req;
    struct ad_access_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_access_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->ctx = ctx;
    state->pd = pd;
    state->be_ctx = be_ctx;
    state->domain = domain;

    ret = ad_parse_access_filter(state, domain, ctx->sdap_access_ctx->filter,
                                 &state->filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not determine the best filter\n");
        ret = ERR_ACCESS_DENIED;
        goto done;
    }

    state->clist = ad_gc_conn_list(state, ctx->ad_id_ctx, domain);
    if (state->clist == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ad_sdap_access_step(req, state->clist[state->cindex]);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);

        tevent_req_post(req, ev);
    }
    return req;
}

static errno_t
ad_sdap_access_step(struct tevent_req *req, struct sdap_id_conn_ctx *conn)
{
    struct tevent_req *subreq;
    struct ad_access_state *state;
    struct sdap_access_ctx *req_ctx;

    state = tevent_req_data(req, struct ad_access_state);

    req_ctx = talloc(state, struct sdap_access_ctx);
    if (req_ctx == NULL) {
        return ENOMEM;
    }
    req_ctx->id_ctx = state->ctx->sdap_access_ctx->id_ctx;
    req_ctx->filter = state->filter;
    memcpy(&req_ctx->access_rule,
           state->ctx->sdap_access_ctx->access_rule,
           sizeof(int) * LDAP_ACCESS_LAST);

    subreq = sdap_access_send(state, state->ev, state->be_ctx,
                              state->domain, req_ctx,
                              conn, state->pd);
    if (subreq == NULL) {
        talloc_free(req_ctx);
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ad_sdap_access_done, req);
    return EOK;
}

static void
ad_gpo_access_done(struct tevent_req *subreq);

static void
ad_sdap_access_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_access_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_access_state);

    ret = sdap_access_recv(subreq);
    talloc_zfree(subreq);

    if (ret != EOK) {
        switch (ret) {
        case ERR_ACCOUNT_EXPIRED:
            tevent_req_error(req, ret);
            return;

        case ERR_ACCESS_DENIED:
            /* Retry on ACCESS_DENIED, too, to make sure that we don't
             * miss out any attributes not present in GC
             * FIXME - this is slow. We should retry only if GC failed
             * and LDAP succeeded after the first ACCESS_DENIED
             */
            break;

        default:
            break;
        }

        /* If possible, retry with LDAP */
        state->cindex++;
        if (state->clist[state->cindex] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Error retrieving access check result: %s\n",
                  sss_strerror(ret));
            tevent_req_error(req, ret);
            return;
        }

        ret = ad_sdap_access_step(req, state->clist[state->cindex]);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        /* Another check in progress */

        return;
    }

    switch (state->ctx->gpo_access_control_mode) {
    case GPO_ACCESS_CONTROL_DISABLED:
        /* do not evaluate gpos; mark request done */
        tevent_req_done(req);
        return;
    case GPO_ACCESS_CONTROL_PERMISSIVE:
    case GPO_ACCESS_CONTROL_ENFORCING:
        /* continue on to evaluate gpos */
        break;
    default:
        tevent_req_error(req, EINVAL);
        return;
    }

    subreq = ad_gpo_access_send(state,
                                state->be_ctx->ev,
                                state->domain,
                                state->ctx,
                                state->pd->user,
                                state->pd->service);

    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ad_gpo_access_done, req);

}

static void
ad_gpo_access_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_access_state *state;
    errno_t ret;
    enum gpo_access_control_mode mode;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_access_state);
    mode = state->ctx->gpo_access_control_mode;

    ret = ad_gpo_access_recv(subreq);
    talloc_zfree(subreq);

    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "GPO-based access control successful.\n");
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "GPO-based access control failed.\n");
        if (mode == GPO_ACCESS_CONTROL_ENFORCING) {
            tevent_req_error(req, ret);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Ignoring error: [%d](%s); GPO-based access control failed, "
                  "but GPO is not in enforcing mode.\n",
                  ret, sss_strerror(ret));
            sss_log_ext(SSS_LOG_WARNING, LOG_AUTHPRIV, "Warning: user would "
                  "have been denied GPO-based logon access if the "
                  "ad_gpo_access_control option were set to enforcing mode.");
            tevent_req_done(req);
        }
    }
}

static errno_t
ad_access_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ad_pam_access_handler_state {
    struct pam_data *pd;
};

static void ad_pam_access_handler_done(struct tevent_req *subreq);

struct tevent_req *
ad_pam_access_handler_send(TALLOC_CTX *mem_ctx,
                           struct ad_access_ctx *access_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params)
{
    struct ad_pam_access_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_pam_access_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;

    subreq = ad_access_send(state, params->ev, params->be_ctx,
                            params->domain, access_ctx, pd);
    if (subreq == NULL) {
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_pam_access_handler_done, req);

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void ad_pam_access_handler_done(struct tevent_req *subreq)
{
    struct ad_pam_access_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_pam_access_handler_state);

    ret = ad_access_recv(subreq);
    talloc_free(subreq);
    switch (ret) {
    case EOK:
        state->pd->pam_status = PAM_SUCCESS;
        break;
    case ERR_ACCESS_DENIED:
        state->pd->pam_status = PAM_PERM_DENIED;
        break;
    case ERR_ACCOUNT_EXPIRED:
        state->pd->pam_status = PAM_ACCT_EXPIRED;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
        break;
    }

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
ad_pam_access_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data)
{
    struct ad_pam_access_handler_state *state = NULL;

    state = tevent_req_data(req, struct ad_pam_access_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
