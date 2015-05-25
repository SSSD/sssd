/*
    SSSD

    IPA Subdomains Module - server mode

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include "providers/ipa/ipa_id.h"

/* These constants are defined in MS-ADTS 6.1.6.7.1
 *  https://msdn.microsoft.com/en-us/library/cc223768.aspx
 */
#define LSA_TRUST_DIRECTION_INBOUND  0x00000001
#define LSA_TRUST_DIRECTION_OUTBOUND 0x00000002

static uint32_t default_direction(TALLOC_CTX *mem_ctx,
                                  struct ldb_context *ldb_ctx,
                                  struct sysdb_attrs *attrs)
{
    struct ldb_dn *dn = NULL;
    uint32_t direction;

    dn = ipa_subdom_ldb_dn(mem_ctx, ldb_ctx, attrs);
    if (dn == NULL) {
        /* Shouldn't happen, but let's try system keytab in this case */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot determine subdomain DN, falling back to two-way trust\n");
        return (LSA_TRUST_DIRECTION_INBOUND|LSA_TRUST_DIRECTION_OUTBOUND);
    }

    if (ipa_subdom_is_member_dom(dn) == true) {
        /* It's expected member domains do not have the direction */
        direction = 0;
    } else {
        /* Old server? Default to 2way trust */
        direction = (LSA_TRUST_DIRECTION_INBOUND|LSA_TRUST_DIRECTION_OUTBOUND);
    }

    talloc_free(dn);
    return direction;
}

errno_t ipa_server_get_trust_direction(struct sysdb_attrs *sd,
                                       struct ldb_context *ldb_ctx,
                                       uint32_t *_direction)
{
    uint32_t ipa_trust_direction = 0;
    uint32_t direction;
    int ret;

    ret = sysdb_attrs_get_uint32_t(sd, IPA_TRUST_DIRECTION,
                                   &ipa_trust_direction);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Raw %s value: %d\n", IPA_TRUST_DIRECTION, ipa_trust_direction);
    if (ret == ENOENT) {
        direction = default_direction(sd, ldb_ctx, sd);
    } else if (ret == EOK) {
        /* Just store the AD value in SYSDB, we will check it while we're
         * trying to use the trust */
        direction = ipa_trust_direction;
    } else {
        return ret;
    }

    *_direction = direction;
    return EOK;
}

const char *ipa_trust_dir2str(uint32_t direction)
{
    if ((direction & LSA_TRUST_DIRECTION_OUTBOUND)
            && (direction & LSA_TRUST_DIRECTION_INBOUND)) {
        return "two-way trust";
    } else if (direction & LSA_TRUST_DIRECTION_OUTBOUND) {
        return "one-way outbound: local domain is trusted by remote domain";
    } else if (direction & LSA_TRUST_DIRECTION_INBOUND) {
        return "one-way inbound: local domain trusts the remote domain";
    } else if (direction == 0) {
        return "trust direction not set";
    }

    return "unknown";
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
    const char *ad_site_override;
    struct sdap_domain *sdom;
    errno_t ret;
    const char *extra_attrs;

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

    extra_attrs = dp_opt_get_string(id_ctx->sdap_id_ctx->opts->basic,
                            SDAP_USER_EXTRA_ATTRS);
    if (extra_attrs != NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Setting extra attrs for subdomain [%s] to [%s].\n", ad_domain,
                                                                   extra_attrs);

        ret = dp_opt_set_string(ad_options->id->basic, SDAP_USER_EXTRA_ATTRS,
                                extra_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "dp_opt_get_string failed.\n");
            talloc_free(ad_options);
            return ret;
        }

        ret = sdap_extend_map_with_list(ad_options->id, ad_options->id,
                                        SDAP_USER_EXTRA_ATTRS,
                                        ad_options->id->user_map,
                                        SDAP_OPTS_USER,
                                        &ad_options->id->user_map,
                                        &ad_options->id->user_map_cnt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_extend_map_with_list failed.\n");
            talloc_free(ad_options);
            return ret;
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "No extra attrs set.\n");
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

    ad_site_override = dp_opt_get_string(ad_options->basic, AD_SITE);

    /* use AD plugin */
    srv_ctx = ad_srv_plugin_ctx_init(be_ctx, be_ctx->be_res,
                                     default_host_dbs,
                                     ad_id_ctx->ad_options->id,
                                     id_ctx->server_mode->hostname,
                                     ad_domain,
                                     ad_site_override);
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

    sdap_inherit_options(subdom->parent->sd_inherit,
                         id_ctx->sdap_id_ctx->opts,
                         ad_id_ctx->sdap_id_ctx->opts);

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

struct ipa_server_trust_add_state {
};

static struct tevent_req *
ipa_server_trust_add_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct be_ctx *be_ctx,
                          struct ipa_id_ctx *id_ctx,
                          struct sss_domain_info *subdom)
{
    struct tevent_req *req = NULL;
    struct ipa_server_trust_add_state *state = NULL;
    struct ipa_ad_server_ctx *trust_ctx;
    struct ad_id_ctx *ad_id_ctx;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ipa_server_trust_add_state);
    if (req == NULL) {
        return NULL;
    }

    ret = ipa_ad_ctx_new(be_ctx, id_ctx, subdom, &ad_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot create ad_id_ctx for subdomain %s\n", subdom->name);
        goto immediate;
    }

    trust_ctx = talloc(id_ctx->server_mode, struct ipa_ad_server_ctx);
    if (trust_ctx == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    trust_ctx->dom = subdom;
    trust_ctx->ad_id_ctx = ad_id_ctx;

    DLIST_ADD(id_ctx->server_mode->trusts, trust_ctx);

    /* In this particular patch, we just want to fake the async interface
     * for an otherwise synchronous operation of creating two-way trusts,
     * so currently the request is just marked as done and terminated. We
     * will convert the request to fully async in a subsequent patch that
     * adds support for one-way trusts.
     */
    ret = EOK;
    goto immediate;

    return req;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ipa_server_trust_add_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ipa_server_create_trusts_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *id_ctx;
    struct sss_domain_info *domiter;
};

static errno_t ipa_server_create_trusts_step(struct tevent_req *req);
static void ipa_server_create_trusts_done(struct tevent_req *subreq);

struct tevent_req *
ipa_server_create_trusts_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct be_ctx *be_ctx,
                              struct ipa_id_ctx *id_ctx,
                              struct sss_domain_info *parent)
{
    struct tevent_req *req = NULL;
    struct ipa_server_create_trusts_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_server_create_trusts_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->id_ctx = id_ctx;
    state->domiter = parent;

    ret = ipa_server_create_trusts_step(req);
    if (ret != EAGAIN) {
        goto immediate;
    }

    return req;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ipa_server_create_trusts_step(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct ipa_ad_server_ctx *trust_iter;
    struct ipa_server_create_trusts_state *state = NULL;

    state = tevent_req_data(req, struct ipa_server_create_trusts_state);

    for (state->domiter = get_next_domain(state->domiter, true);
         state->domiter && IS_SUBDOMAIN(state->domiter);
         state->domiter = get_next_domain(state->domiter, false)) {

        /* Check if we already have an ID context for this subdomain */
        DLIST_FOR_EACH(trust_iter, state->id_ctx->server_mode->trusts) {
            if (trust_iter->dom == state->domiter) {
                break;
            }
        }

        /* Newly detected trust */
        if (trust_iter == NULL) {
            subreq = ipa_server_trust_add_send(state, state->ev, state->be_ctx,
                                               state->id_ctx, state->domiter);
            if (subreq == NULL) {
                return ENOMEM;
            }
            tevent_req_set_callback(subreq, ipa_server_create_trusts_done, req);
            return EAGAIN;
        }
    }

    return EOK;
}

static void ipa_server_create_trusts_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    ret = ipa_server_trust_add_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = ipa_server_create_trusts_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
        return;
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }

    /* Will cycle back */
}

errno_t ipa_server_create_trusts_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

void ipa_ad_subdom_remove(struct be_ctx *be_ctx,
                          struct ipa_id_ctx *id_ctx,
                          struct sss_domain_info *subdom)
{
    struct ipa_ad_server_ctx *iter;
    struct sdap_domain *sdom;

    if (dp_opt_get_bool(id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        return;
    }

    DLIST_FOR_EACH(iter, id_ctx->server_mode->trusts) {
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
    DLIST_REMOVE(id_ctx->server_mode->trusts, iter);

    /* terminate all requests for this subdomain so we can free it */
    be_terminate_domain_requests(be_ctx, subdom->name);
    talloc_zfree(sdom);
}

struct ipa_ad_subdom_reinit_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *id_ctx;
    struct sss_domain_info *parent;
};

static void create_trusts_at_startup_done(struct tevent_req *req)
{
    errno_t ret;

    ret = ipa_server_create_trusts_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ipa_server_create_trusts_send request failed [%d]: %s\n",
              ret, sss_strerror(ret));
    }
}

static void create_trusts_at_startup(struct tevent_context *ev,
                                     struct tevent_immediate *imm,
                                     void *pvt)
{
    struct tevent_req *req;
    struct ipa_ad_subdom_reinit_state *state;

    state = talloc_get_type(pvt, struct ipa_ad_subdom_reinit_state);

    req = ipa_server_create_trusts_send(state, state->ev, state->be_ctx,
                                        state->id_ctx, state->parent);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_server_create_trusts_send failed.\n");
        talloc_free(state);
        return;
    }

    tevent_req_set_callback(req, create_trusts_at_startup_done, state);
    return;
}

static errno_t ipa_ad_subdom_reinit(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct be_ctx *be_ctx,
                                    struct ipa_id_ctx *id_ctx,
                                    struct sss_domain_info *parent)
{
    struct tevent_immediate *imm;
    struct ipa_ad_subdom_reinit_state *state;

    state = talloc(mem_ctx, struct ipa_ad_subdom_reinit_state);
    if (state == NULL) {
        return ENOMEM;
    }
    state->ev = ev;
    state->be_ctx = be_ctx;
    state->id_ctx = id_ctx;
    state->parent = parent;

    if (dp_opt_get_bool(id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        return EOK;
    }

    imm = tevent_create_immediate(mem_ctx);
    if (imm == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_create_immediate failed.\n");
        talloc_free(state);
        return ENOMEM;
    }

    tevent_schedule_immediate(imm, ev, create_trusts_at_startup, state);
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

    ret = ipa_ad_subdom_reinit(be_ctx, be_ctx->ev,
                               be_ctx, id_ctx, be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_ad_subdom_refresh failed.\n");
        return ret;
    }

    return EOK;
}
