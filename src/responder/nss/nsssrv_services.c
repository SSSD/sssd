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


#include <collection.h>
#include <arpa/inet.h>
#include "util/util.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_private.h"
#include "responder/nss/nsssrv_services.h"
#include "responder/common/negcache.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "db/sysdb_services.h"

struct getserv_ctx {
    struct tevent_context *ev;
    uint16_t port;
    struct nss_dom_ctx *dctx;

    struct sss_domain_info **domains;
    size_t dom_idx;

    char *name;
    char *cased_name;

    char *proto;
    char *cased_proto;
    struct ldb_result *res;
};

static errno_t lookup_service_step(struct tevent_req *req);
static void lookup_service_done(struct tevent_req *req);

#define SVC_NAME_CASED (dom->case_sensitive ? state->cased_name \
                                           : state->name)
#define SVC_PROTO_CASED (dom->case_sensitive ? state->cased_proto \
                                            : state->proto)

/* Provider Lookup Logic:
 * Iterate through the available caches. If the cached entry is
 * present and not expired, return it immediately(*). If it is
 * present and expired, add it to a list of domains eligible to
 * be checked. If it is in the negative cache, skip over it and
 * do not add it to the eligible domain list.
 *
 * Once we have searched all of the caches, if the entry has not
 * been determined to be available, search all domains in order
 * to see if any of them contain the requested entry.
 *
 * (*) Optionally perform a midpoint cache refresh if appropriate.
 */

static struct tevent_req *
getserv_send(TALLOC_CTX *mem_ctx,
             struct tevent_context *ev,
             uint16_t port,
             const char *service_name,
             const char *service_protocol,
             struct nss_dom_ctx *dctx)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct getserv_ctx *state;
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sss_domain_info *dom;
    size_t num_domains = 0;
    size_t dom_idx = 0;
    struct nss_ctx *nctx =
            talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    struct sysdb_ctx *sysdb;
    time_t now = time(NULL);
    uint64_t lastUpdate;
    uint64_t cacheExpire;
    uint64_t midpoint_refresh;

    req = tevent_req_create(mem_ctx, &state, struct getserv_ctx);
    if (!req) return NULL;
    state->dctx = dctx;

    for (dom = cctx->rctx->domains; dom; dom = dom->next) num_domains++;

    /* Create an array of domains to check. To save resizes, we'll
     * assume that all will be checked
     */
    state->domains = talloc_zero_array(state,
                                       struct sss_domain_info *,
                                       num_domains + 1);
    if (!state->domains) {
        ret = ENOMEM;
        goto immediate;
    }

    state->port = port;

    /* Store both the case-sensitive and lowercased names
     * in the state object, to avoid recalculating the
     * lowercase in multiple domains.
     */
    if (service_protocol) {
        state->proto = talloc_strdup(state, service_protocol);
        if (!state->proto) {
            ret = ENOMEM;
            goto immediate;
        }
        state->cased_proto = sss_get_cased_name(state, service_protocol,
                                                true);
        if (!state->cased_proto) {
            ret = ENOMEM;
            goto immediate;
        }
    } else {
        state->proto = NULL;
        state->cased_proto = NULL;
    }

    /* If we're looking up by name */
    if (service_name) {
        /* Store both the case-sensitive and lowercased names
         * in the state object, to avoid recalculating the
         * lowercase in multiple domains.
         */
        state->name = talloc_strdup(state, service_name);
        if (!state->name) {
            ret = ENOMEM;
            goto immediate;
        }

        state->cased_name = sss_get_cased_name(state, service_name,
                                               true);
        if (!state->cased_name) {
            ret = ENOMEM;
            goto immediate;
        }
    }

    dom = cctx->rctx->domains;
    while(dom) {
        /* if it is a domainless search, skip domains that require fully
          * qualified names instead */
         while (dom && cmdctx->check_next && dom->fqnames) {
             dom = dom->next;
         }
         if (!dom) break;

         ret = sysdb_get_ctx_from_list(cctx->rctx->db_list, dom, &sysdb);
         if (ret != EOK) {
             DEBUG(SSSDBG_CRIT_FAILURE,
                   ("Critical: Sysdb CTX not found for [%s]!\n", dom->name));
             ret = EINVAL;
             goto immediate;
         }

         /* If we're looking up by name */
         if (service_name) {
             /* Check the negative cache */
             ret = sss_ncache_check_service(nctx->ncache,
                                            nctx->neg_timeout,
                                            dom,
                                            SVC_NAME_CASED,
                                            SVC_PROTO_CASED);
             /* If negatively cached, return we didn't find it */
             if (ret == EEXIST) {
                 DEBUG(SSSDBG_TRACE_FUNC,
                       ("Service [%s:%s] does not exist in [%s]! "
                        "(negative cache)\n",
                        SVC_NAME_CASED,
                        SVC_PROTO_CASED ? SVC_PROTO_CASED : "<ANY>",
                        dom->name));

                 /* If this is a multi-domain search, try the next one */
                 if (cmdctx->check_next) {
                     dom = dom->next;
                 } else {
                     /* This was a single-domain search.
                      * exit the loop. Since it was negatively-
                      * cached, don't add it to the eligible
                      * domains list.
                      */
                     dom = NULL;
                 }

                 continue;
             }

             /* Check the cache */
             DEBUG(SSSDBG_TRACE_FUNC,
                   ("Checking cache for [%s:%s@%s]\n",
                    SVC_NAME_CASED,
                    SVC_PROTO_CASED ? SVC_PROTO_CASED : "<ANY>",
                    dom->name));

             ret = sysdb_getservbyname(state, sysdb,
                                       SVC_NAME_CASED,
                                       SVC_PROTO_CASED,
                                       &state->res);
         } else { /* Looking up by port */
             /* Check the negative cache */
             ret = sss_ncache_check_service_port(nctx->ncache,
                                            nctx->neg_timeout,
                                            dom, port,
                                            SVC_PROTO_CASED);
             /* If negatively cached, return we didn't find it */
             if (ret == EEXIST) {
                 DEBUG(SSSDBG_TRACE_FUNC,
                       ("Service [%lu:%s] does not exist in [%s]! "
                        "(negative cache)\n",
                        port,
                        SVC_PROTO_CASED ? SVC_PROTO_CASED : "<ANY>",
                        dom->name));

                 /* If this is a multi-domain search, try the next one */
                 if (cmdctx->check_next) {
                     dom = dom->next;
                 } else {
                     /* This was a single-domain search.
                      * exit the loop. Since it was negatively-
                      * cached, don't add it to the eligible
                      * domains list.
                      */
                     dom = NULL;
                 }

                 continue;
             }

             /* Check the cache */
             DEBUG(SSSDBG_TRACE_FUNC,
                   ("Checking cache for [%lu:%s@%s]\n",
                    port,
                    SVC_PROTO_CASED ? SVC_PROTO_CASED : "<ANY>",
                    dom->name));

             ret = sysdb_getservbyport(state, sysdb, port,
                                       SVC_PROTO_CASED,
                                       &state->res);
         }
         if (ret != EOK && ret != ENOENT) goto immediate;

         if (ret == ENOENT) {
             /* Not found in the cache. Add this domain to the
              * list of eligible domains to check the provider.
              */
             if (NEED_CHECK_PROVIDER(dom->provider)) {
                 state->domains[dom_idx] = dom;
                 dom_idx++;
             } else {
                 /* No provider to check. Set the negative cache here */
                 if (state->name) {
                     ret = sss_ncache_set_service_name(nctx->ncache, false,
                                                       dom,
                                                       SVC_NAME_CASED,
                                                       SVC_PROTO_CASED);
                     if (ret != EOK) {
                         /* Failure to set the negative cache is non-fatal.
                          * We'll log an error and continue.
                          */
                         DEBUG(SSSDBG_MINOR_FAILURE,
                               ("Could not set negative cache for [%s][%s]\n",
                                SVC_NAME_CASED, SVC_PROTO_CASED));
                     }
                 } else {
                     ret = sss_ncache_set_service_port(nctx->ncache, false,
                                                       dom,
                                                       state->port,
                                                       SVC_PROTO_CASED);
                     if (ret != EOK) {
                         /* Failure to set the negative cache is non-fatal.
                          * We'll log an error and continue.
                          */
                         DEBUG(SSSDBG_MINOR_FAILURE,
                               ("Could not set negative cache for [%lu][%s]\n",
                                state->port, SVC_PROTO_CASED));
                     }
                 }
             }

             /* If this is a multi-domain search, try the next one */
             if (cmdctx->check_next) {
                 dom = dom->next;
             } else {
                 /* This was a single-domain search.
                  * exit the loop.
                  */
                 dom = NULL;
             }
             continue;
         }

         /* Found a result. Check its validity */
         if (state->res->count > 1) {
             DEBUG(SSSDBG_OP_FAILURE,
                   ("getservby* returned more than one result!\n"));
             ret = ENOENT;
             goto immediate;
         }

         lastUpdate = ldb_msg_find_attr_as_uint64(state->res->msgs[0],
                                                  SYSDB_LAST_UPDATE, 0);

         cacheExpire = ldb_msg_find_attr_as_uint64(state->res->msgs[0],
                                                   SYSDB_CACHE_EXPIRE, 0);

         midpoint_refresh = 0;
         if(nctx->cache_refresh_percent) {
             midpoint_refresh = lastUpdate +
               (cacheExpire - lastUpdate)*nctx->cache_refresh_percent/100;
             if (midpoint_refresh - lastUpdate < 10) {
                 /* If the percentage results in an expiration
                  * less than ten seconds after the lastUpdate time,
                  * that's too often we will simply set it to 10s
                  */
                 midpoint_refresh = lastUpdate+10;
             }
         }

         if (cacheExpire > now) {
             /* cache still valid */

             if (NEED_CHECK_PROVIDER(dom->provider)
                     && midpoint_refresh
                     && midpoint_refresh < now) {
                 /* We're past the the cache refresh timeout
                  * We'll return the value from the cache, but we'll also
                  * queue the cache entry for update out-of-band.
                  */
                 DEBUG(SSSDBG_TRACE_FUNC,
                       ("Performing midpoint cache update\n"));

                 /* Update the cache */
                 subreq = sss_dp_get_account_send(cctx, cctx->rctx,
                                                  dom, true,
                                                  SSS_DP_SERVICES,
                                                  SVC_NAME_CASED,
                                                  port, NULL);
                 if (!subreq) {
                     DEBUG(SSSDBG_CRIT_FAILURE,
                           ("Out of memory sending out-of-band data provider "
                            "request\n"));
                     /* This is non-fatal, so we'll continue here */
                 }
                 /* We don't need to listen for a reply, so we will free the
                  * request here.
                  */
                 talloc_zfree(subreq);
             }

             /* The cache is valid. Return it */
             ret = EOK;
             goto immediate;
         } else {
             /* Cache is expired. Add this domain to the
              * list of eligible domains to check the provider.
              */
             if (NEED_CHECK_PROVIDER(dom->provider)) {
                 state->domains[dom_idx] = dom;
                 dom_idx++;
             }

             /* If this is a multi-domain search, try the next one */
             if (cmdctx->check_next) {
                 dom = dom->next;
             } else {
                 /* This was a single-domain search.
                  * exit the loop.
                  */
                 dom = NULL;
             }
         }
    }

    /* No valid cached entries found and
     * not found in negative caches.
     * Iterate through the domains and try
     * to look the data up.
     */

    state->dom_idx = 0;
    if (!state->domains[state->dom_idx]) {
        /* No domains to search. Return ENOENT */
        ret = ENOENT;
        goto immediate;
    }

    ret = lookup_service_step(req);
    if (ret != EOK) goto immediate;

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

static errno_t lookup_service_step(struct tevent_req *req)
{
    struct getserv_ctx *state =
            tevent_req_data(req, struct getserv_ctx);
    struct tevent_req *subreq;
    struct cli_ctx *cctx = state->dctx->cmdctx->cctx;
    struct sss_domain_info *dom =
            state->domains[state->dom_idx];

    /* Update the cache */
    subreq = sss_dp_get_account_send(req,
                                     cctx->rctx,
                                     dom,
                                     true,
                                     SSS_DP_SERVICES,
                                     SVC_NAME_CASED,
                                     state->port,
                                     SVC_PROTO_CASED);
    if (!subreq) return ENOMEM;
    tevent_req_set_callback(subreq, lookup_service_done, req);

    return EOK;
}

static void lookup_service_done(struct tevent_req *subreq)
{
    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;
    struct sysdb_ctx *sysdb;

    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct getserv_ctx *state =
            tevent_req_data(req, struct getserv_ctx);
    struct cli_ctx *cctx = state->dctx->cmdctx->cctx;
    struct nss_ctx *nctx =
            talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    struct sss_domain_info *dom = state->domains[state->dom_idx];

    ret = sss_dp_get_account_recv(state, subreq,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get information from Data Provider\n"
               "dp_error: [%u], errno: [%u], error_msg: [%s]\n"
               "Will try to return what we have in cache\n",
               (unsigned int)err_maj, (unsigned int)err_min,
               err_msg ? err_msg : "none"));
    }

    /* Recheck the cache after the lookup.
     * We can ignore the expiration values here, because
     * either we have just updated it or the provider is
     * offline. Either way, whatever is in the cache should
     * be returned, if it exists. Otherwise, move to the
     * next provider.
     */
    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dom, &sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Critical: Sysdb CTX not found for [%s]!\n",
                dom->name));
        ret = EINVAL;
        goto done;
    }

    if (state->cased_name) {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Re-checking cache for [%s:%s@%s]\n",
               state->cased_name,
               state->cased_proto ? state->cased_proto : "<ANY>",
               dom->name));

        ret = sysdb_getservbyname(state, sysdb,
                                  state->cased_name,
                                  state->cased_proto,
                                  &state->res);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Re-checking cache for [%lu:%s@%s]\n",
               state->port,
               state->cased_proto ? state->cased_proto : "<ANY>",
               dom->name));

        ret = sysdb_getservbyport(state, sysdb,
                                  state->port,
                                  state->cased_proto,
                                  &state->res);
    }

    if (ret == ENOENT) {
        /* Nothing in the cache.
         * Set the negative cache
         */
        if (state->name) {
            ret = sss_ncache_set_service_name(nctx->ncache, false,
                                              dom,
                                              SVC_NAME_CASED,
                                              SVC_PROTO_CASED);
            if (ret != EOK) {
                /* Failure to set the negative cache is non-fatal.
                 * We'll log an error and continue.
                 */
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Could not set negative cache for [%s][%s]\n",
                       SVC_NAME_CASED, SVC_PROTO_CASED));
            }
        } else {
            ret = sss_ncache_set_service_port(nctx->ncache, false,
                                              dom,
                                              state->port,
                                              SVC_PROTO_CASED);
            if (ret != EOK) {
                /* Failure to set the negative cache is non-fatal.
                 * We'll log an error and continue.
                 */
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Could not set negative cache for [%lu][%s]\n",
                       state->port, SVC_PROTO_CASED));
            }
        }

        /* Need to check other domains */
        state->dom_idx++;
        if (!state->domains[state->dom_idx]) {
            /* No more domains to search. Return ENOENT */
            ret = ENOENT;
            goto done;
        }
        ret = lookup_service_step(req);
        if (ret != EOK) goto done;

        /* Set EAGAIN so we will re-enter the mainloop */
        ret = EAGAIN;
    }

done:
    if (ret == EOK) {
        /* Cache contained results. Return them */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        /* An error occurred, fail the request */
        tevent_req_error(req, ret);
    }

    /* ret == EAGAIN: Reenter mainloop */
    return;
}

static errno_t
getserv_recv(TALLOC_CTX *mem_ctx,
             struct tevent_req *req,
             struct ldb_result **_res)
{
    struct getserv_ctx *state =
            tevent_req_data(req, struct getserv_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_res = talloc_steal(mem_ctx, state->res);

    return EOK;
}

static errno_t
fill_service(struct sss_packet *packet,
             struct sss_domain_info *dom,
             struct nss_ctx *nctx,
             struct ldb_message **msgs,
             unsigned int *count)
{
    errno_t ret;
    unsigned int msg_count = *count;
    size_t rzero, rsize;
    unsigned int num, i, j;
    uint32_t num_aliases;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *orig_name;
    char *orig_proto;
    struct sized_string cased_name;
    struct sized_string cased_proto;
    uint16_t port;
    char *tmpstr;
    uint8_t *body;
    size_t blen;
    struct sized_string alias;

    /* FIXME: Should we account for fully-qualified
     * service names?
     */

    /* first 2 fields (len and reserved), filled up later */
    ret = sss_packet_grow(packet, 2 * sizeof(uint32_t));
    if (ret != EOK) goto done;

    rzero = 2 * sizeof(uint32_t);
    rsize = 0;

    num = 0;
    for (i = 0; i < msg_count; i++) {
        talloc_zfree(tmp_ctx);
        tmp_ctx = talloc_new(NULL);
        if (!tmp_ctx) return ENOMEM;

        msg = msgs[i];

        /* new service */
        if (!ldb_msg_check_string_attribute(msg, "objectClass",
                                            SYSDB_SVC_CLASS)) {
            DEBUG(1, ("Wrong object (%s) found on stack!\n",
                      ldb_dn_get_linearized(msg->dn)));
            continue;
        }

        /* new result starts at end of previous result */
        rzero += rsize;
        rsize = 0;

        /* Get the service name */
        orig_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        tmpstr = sss_get_cased_name(tmp_ctx, orig_name, dom->case_sensitive);
        if (tmpstr == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not identify service name, skipping\n"));
            continue;
        }
        to_sized_string(&cased_name, tmpstr);

        /* Get the port */
        port = (uint16_t) ldb_msg_find_attr_as_uint(msg, SYSDB_SVC_PORT, 0);
        if (!port) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("No port for service [%s]. Skipping\n"));

        }

        /* Get the service protocol.
         * If more than one is available, select the
         * first in the message.
         */
        el = ldb_msg_find_element(msg, SYSDB_SVC_PROTO);
        if (el->num_values == 0) {
            ret = EINVAL;
            num = 0;
            goto done;
        }
        orig_proto = (char *)el->values[0].data;

        tmpstr = sss_get_cased_name(tmp_ctx, orig_proto, dom->case_sensitive);
        if (tmpstr == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("sss_get_cased_name failed, skipping\n"));
            continue;
        }
        to_sized_string(&cased_proto, tmpstr);

        sss_packet_grow(packet, 2 * sizeof(uint16_t)
                            + sizeof(uint32_t)
                            + cased_name.len
                            + cased_proto.len);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        /* Store the port number */
        SAFEALIGN_SET_UINT32(&body[rzero + rsize], (uint32_t)htons(port), &rsize);

        /* Get the aliases */
        el = ldb_msg_find_element(msg, SYSDB_NAME_ALIAS);
        if (!el) {
            /* No aliases for this user */
            num_aliases = 0;
        } else {
            num_aliases = el->num_values;
        }

        /* Store the alias count */
        SAFEALIGN_SET_UINT32(&body[rzero + rsize], num_aliases, &rsize);

        /* Store the primary name */
        safealign_memcpy(&body[rzero + rsize],
                         cased_name.str,
                         cased_name.len,
                         &rsize);

        /* Store the protocol */
        safealign_memcpy(&body[rzero + rsize],
                         cased_proto.str,
                         cased_proto.len,
                         &rsize);

        for (j = 0; j < num_aliases; j++) {
            tmpstr = sss_get_cased_name(tmp_ctx,
                                        (const char *)el->values[j].data,
                                        dom->case_sensitive);
            to_sized_string(&alias, tmpstr);

            ret = sss_packet_grow(packet, alias.len);
            if (ret != EOK) {
                num = 0;
                goto done;
            }
            sss_packet_get_body(packet, &body, &blen);

            /* Store the alias */
            safealign_memcpy(&body[rzero + rsize],
                             alias.str,
                             alias.len,
                             &rsize);

            talloc_zfree(tmpstr);
        }

        num++;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK ||num == 0) {
        /* if num is 0 most probably something went wrong,
         * reset packet and return ENOENT */
        sss_packet_set_size(packet, 0);
        return ENOENT;
    }

    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return ret;
}
/*****************
 * getservbyname *
 *****************/

errno_t parse_getservbyname(TALLOC_CTX *mem_ctx,
                            uint8_t *body, size_t blen,
                            struct sss_names_ctx *names,
                            char **domain_name,
                            char **service_name,
                            char **service_protocol);

static void
nss_cmd_getserv_done(struct tevent_req *req);

int nss_cmd_getservbyname(struct cli_ctx *cctx)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    char *domname;
    char *service_name;
    char *service_protocol;
    uint8_t *body;
    size_t blen;
    struct tevent_req *req;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) return ENOMEM;

    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* get service name and protocol */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        ret = EINVAL;
        goto done;
    }

    ret = parse_getservbyname(cmdctx, body, blen,
                              cctx->rctx->names,
                              &domname,
                              &service_name,
                              &service_protocol);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not parse request\n"));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requesting info for service [%s:%s] from [%s]\n",
           service_name,
           service_protocol ? service_protocol : "<ANY>",
           domname ? domname : "<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(cctx->rctx->domains, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->domain = cctx->rctx->domains;
        cmdctx->check_next = true;
    }

    /* Identify if this backend requires a provider check */
    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* Ok, find it! */
    req = getserv_send(cmdctx, cctx->ev, 0,
                       service_name,
                       service_protocol,
                       dctx);
    if (!req) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(req, nss_cmd_getserv_done, dctx);

done:
    return nss_cmd_done(cmdctx, ret);
}

errno_t parse_getservbyname(TALLOC_CTX *mem_ctx,
                            uint8_t *body, size_t blen,
                            struct sss_names_ctx *names,
                            char **domain_name,
                            char **service_name,
                            char **service_protocol)
{
    errno_t ret;
    size_t i, j, namelen;
    char *rawname;
    char *domname;
    char *svc_name;
    char *protocol;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* The raw name is at most one character shorter
     * than the body length (if the protocol wasn't
     * specified). Since this is a common case, we'll
     * just assume the maximum memory size for the
     * rawname.
     */
    rawname = talloc_array(tmp_ctx, char, blen - 1);
    if (!rawname) {
        ret = ENOMEM;
        goto done;
    }

    i = j = 0;

    /* Copy in the service name */
    while (body[i] && i < (blen - 1)) {
        rawname[j] = body[i];
        i++;
        j++;
    }
    if (body[i] != '\0') {
        /* blen - 1 was reached without hitting
         * a NULL-terminator. No protocol field
         * is possible.
         */
        ret = EINVAL;
        goto done;
    }
    rawname[j] = '\0';

    i++;
    namelen = i;
    j = 0;

    /* Copy in the protocol */
    if (body[i] == '\0') {
        /* Zero-length protocol
         * Just set the protocol to NULL
         */
        protocol = NULL;
    } else {
        /* The protocol must be no longer than the remaining
         * body space, after the name was copied.
         */
        protocol = talloc_array(tmp_ctx, char, blen - i - 1);
        if (!protocol) {
            ret = ENOMEM;
            goto done;
        }

        while (body[i] && i < blen) {
            protocol[j] = body[i];
            i++;
            j++;
        }
        if (body[i] != '\0') {
            /* blen was reached without hitting
             * a NULL-terminator.
             */
            ret = EINVAL;
            goto done;
        }

        protocol[j] = '\0';

        if (j != blen - namelen - 1) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Body longer than the name and protocol\n"));
            ret = EINVAL;
            goto done;
        }
    }

    ret = sss_parse_name(tmp_ctx, names, rawname,
                         &domname, &svc_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not split name and domain of [%s]\n",
               rawname));
        goto done;
    }

    *domain_name = talloc_steal(mem_ctx, domname);
    *service_name = talloc_steal(mem_ctx, svc_name);
    *service_protocol = talloc_steal(mem_ctx, protocol);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void
nss_cmd_getserv_done(struct tevent_req *req)
{
    errno_t ret, reqret;
    unsigned int i;

    struct nss_dom_ctx *dctx =
            tevent_req_callback_data(req, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;

    struct nss_ctx *nctx =
            talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    reqret = getserv_recv(dctx, req, &dctx->res);
    talloc_zfree(req);
    if (reqret != EOK && reqret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("getservbyname failed\n"));
        nss_cmd_done(cmdctx, reqret);
        return;
    }

    /* Either we succeeded or no domains were eligible */
    ret = sss_packet_new(cmdctx->cctx->creq, 0,
                         sss_packet_get_cmd(cmdctx->cctx->creq->in),
                         &cmdctx->cctx->creq->out);
    if (ret == EOK) {
        if (reqret == ENOENT) {
            /* Notify the caller that this entry wasn't found */
            ret = fill_empty(cmdctx->cctx->creq->out);
        } else {
            i = dctx->res->count;
            ret = fill_service(cmdctx->cctx->creq->out,
                               dctx->domain,
                               nctx, dctx->res->msgs,
                               &i);
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Could not create response packet: [%s]\n",
                   strerror(ret)));
        }

        sss_cmd_done(cmdctx->cctx, cmdctx);
        return;
    }

    DEBUG(SSSDBG_OP_FAILURE, ("Error creating packet\n"));
}

errno_t parse_getservbyport(TALLOC_CTX *mem_ctx,
                            uint8_t *body, size_t blen,
                            struct sss_names_ctx *names,
                            uint16_t *service_port,
                            char **service_protocol)
{
    errno_t ret;
    size_t i, j;
    size_t port_and_padding_len;
    uint16_t c, port;
    char *protocol;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Copy in the port */
    SAFEALIGN_COPY_UINT16(&c, body, NULL);
    port = ntohs(c);

    port_and_padding_len = 2 * sizeof(uint16_t) + sizeof(uint32_t);
    i = port_and_padding_len;
    j = 0;

    /* Copy in the protocol */
    if (body[i] == '\0') {
        /* Zero-length protocol
         * Just set the protocol to NULL
         */
        protocol = NULL;
    } else {
        /* The protocol must be no longer than the remaining
         * body space.
         */
        protocol = talloc_array(tmp_ctx, char, blen - i);
        if (!protocol) {
            ret = ENOMEM;
            goto done;
        }

        while (body[i] && i < blen) {
            protocol[j] = body[i];
            i++;
            j++;
        }
        if (body[i] != '\0') {
            /* blen was reached without hitting
             * a NULL-terminator.
             */
            ret = EINVAL;
            goto done;
        }

        protocol[j] = '\0';

        if (j != blen - port_and_padding_len - 1) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Body longer than the name and protocol\n"));
            ret = EINVAL;
            goto done;
        }
    }

    *service_port = port;
    *service_protocol = talloc_steal(mem_ctx, protocol);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/*****************
 * getservbyport *
 *****************/
int nss_cmd_getservbyport(struct cli_ctx *cctx)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    uint16_t port;
    char *service_protocol;
    uint8_t *body;
    size_t blen;
    struct tevent_req *req;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) return ENOMEM;

    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* get service port and protocol */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        ret = EINVAL;
        goto done;
    }

    ret = parse_getservbyport(cmdctx, body, blen,
                              cctx->rctx->names,
                              &port,
                              &service_protocol);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not parse request\n"));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requesting info for service on port [%lu/%s]\n",
           port, service_protocol ? service_protocol : "<ANY>"));

    /* All port lookups are multidomain searches */
    dctx->domain = cctx->rctx->domains;
    cmdctx->check_next = true;

    /* Identify if this backend requires a provider check */
    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* Ok, find it! */
    req = getserv_send(cmdctx, cctx->ev, port,
                       NULL, service_protocol, dctx);
    if (!req) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(req, nss_cmd_getserv_done, dctx);

done:
    return nss_cmd_done(cmdctx, ret);
}


int nss_cmd_setservent(struct cli_ctx *cctx)
{
    return EOK;
}

int nss_cmd_getservent(struct cli_ctx *cctx)
{
    return EOK;
}

int nss_cmd_endservent(struct cli_ctx *cctx)
{
    return EOK;
}
