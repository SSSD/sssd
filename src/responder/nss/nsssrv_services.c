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
    uint16_t port;
    struct tevent_context *ev;
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

#define SVC_NAME_CASED (dom->case_sensitive ? state->name \
                                           : state->cased_name)
#define SVC_PROTO_CASED (dom->case_sensitive ? state->proto \
                                            : state->cased_proto)

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
                                                false);
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
                                               false);
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

         sysdb = dom->sysdb;
         if (sysdb == NULL) {
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
                 /* We're past the cache refresh timeout
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
    sysdb = dom->sysdb;
    if (sysdb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Critical: Sysdb CTX not found for [%s]!\n",
                dom->name));
        ret = EINVAL;
        goto done;
    }

    if (state->name) {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Re-checking cache for [%s:%s@%s]\n",
               SVC_NAME_CASED,
               SVC_PROTO_CASED ? SVC_PROTO_CASED : "<ANY>",
               dom->name));

        ret = sysdb_getservbyname(state, sysdb,
                                  SVC_NAME_CASED,
                                  SVC_PROTO_CASED,
                                  &state->res);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Re-checking cache for [%lu:%s@%s]\n",
               state->port,
               SVC_PROTO_CASED ? SVC_PROTO_CASED : "<ANY>",
               dom->name));

        ret = sysdb_getservbyport(state, sysdb,
                                  state->port,
                                  SVC_PROTO_CASED,
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
             const char *protocol,
             struct ldb_message **msgs,
             unsigned int *count)
{
    errno_t ret;
    unsigned int msg_count = *count;
    size_t rzero, rsize, aptr;
    unsigned int num = 0;
    unsigned int i, j;
    uint32_t num_aliases, written_aliases;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *orig_name;
    const char *orig_proto;
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
         * Use the requested protocol if present,
         * otherwise take the first protocol returned
         * by the sysdb.
         * If more than one is available, select the
         * first in the message.
         */
        if (protocol) {
            orig_proto = protocol;
        } else {
            el = ldb_msg_find_element(msg, SYSDB_SVC_PROTO);
            if (el->num_values == 0) {
                ret = EINVAL;
                num = 0;
                goto done;
            }
            orig_proto = (const char *)el->values[0].data;
        }

        tmpstr = sss_get_cased_name(tmp_ctx, orig_proto, dom->case_sensitive);
        if (tmpstr == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("sss_get_cased_name failed, skipping\n"));
            continue;
        }
        to_sized_string(&cased_proto, tmpstr);

        ret = sss_packet_grow(packet, 2 * sizeof(uint16_t)
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

        /* We'll store the alias count here */
        aptr = rzero+rsize;
        rsize += sizeof(uint32_t);

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

        written_aliases = 0;
        for (j = 0; j < num_aliases; j++) {
            if (sss_string_equal(dom->case_sensitive,
                             (const char *)el->values[j].data,
                             cased_name.str)) {
                continue;
            }
            to_sized_string(&alias, (const char *)el->values[j].data);

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

            written_aliases++;
            talloc_zfree(tmpstr);
        }
        SAFEALIGN_SET_UINT32(&body[aptr], written_aliases, &rsize);

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
                            struct sss_domain_info *domains,
                            char *default_domain,
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
                              cctx->rctx->domains,
                              cctx->rctx->default_domain,
                              &domname,
                              &service_name,
                              &service_protocol);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not parse request\n"));
        goto done;
    }

    dctx->protocol = service_protocol;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requesting info for service [%s:%s] from [%s]\n",
           service_name,
           service_protocol ? service_protocol : "<ANY>",
           domname ? domname : "<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(dctx, cctx->rctx, domname);
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
                            struct sss_domain_info *domains,
                            char *default_domain,
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

        if (j != blen - namelen - 1) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Body longer than the name and protocol\n"));
            ret = EINVAL;
            goto done;
        }
    }

    ret = sss_parse_name_for_domains(tmp_ctx, domains, default_domain, rawname,
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
            ret = sss_cmd_empty_packet(cmdctx->cctx->creq->out);
        } else {
            i = dctx->res->count;
            ret = fill_service(cmdctx->cctx->creq->out,
                               dctx->domain,
                               nctx,
                               dctx->protocol,
                               dctx->res->msgs,
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
                              &port,
                              &service_protocol);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not parse request\n"));
        goto done;
    }

    dctx->protocol = service_protocol;

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

struct setservent_ctx {
    struct cli_ctx *cctx;
    struct nss_ctx *nctx;
    struct nss_dom_ctx *dctx;
    struct getent_ctx *getent_ctx;
};

static errno_t
setservent_step(struct setent_step_ctx *step_ctx);
static void
setservent_step_done(struct tevent_req *req);

static struct tevent_req *
lookup_servent_send(TALLOC_CTX *mem_ctx,
                    struct resp_ctx *rctx,
                    struct sss_domain_info *dom);

static struct tevent_req *
setservent_send(TALLOC_CTX *mem_ctx, struct cli_ctx *cctx)
{
    errno_t ret;
    unsigned int num_domains;
    struct tevent_req *req;
    struct setservent_ctx *state;
    struct sss_domain_info *dom;
    struct setent_step_ctx *step_ctx;
    struct nss_ctx *nctx =
            talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    DEBUG(SSSDBG_TRACE_FUNC, ("Received setservent request\n"));

    /* Reset the read pointers */
    cctx->svc_dom_idx = 0;
    cctx->svcent_cur = 0;

    req = tevent_req_create(mem_ctx, &state, struct setservent_ctx);
    if (!req) return NULL;

    state->nctx = nctx;
    state->cctx = cctx;
    state->dctx = talloc_zero(state, struct nss_dom_ctx);
    if (!state->dctx) {
        ret = ENOMEM;
        goto immediate;
    }
    state->dctx->domain = cctx->rctx->domains;

    /* Is the result context already available */
    if (state->nctx->svcctx) {
        if (state->nctx->svcctx->ready) {
            /* All of the necessary data is in place
             * We can return now, getservent requests will work at this point
             */
            ret = EOK;
            goto immediate;
        }
        else {
            /* Object is still being constructed
             * Register for notification when it's
             * ready.
             */
            ret = nss_setent_add_ref(state, state->nctx->svcctx, req);
            if (ret != EOK) goto immediate;
        }
        return req;
    }

    /* Create a new result context
     * We are creating it on the nss_ctx so that it doesn't
     * go away if the original request does. We will delete
     * it when the refcount goes to zero;
     */
    state->nctx->svcctx = talloc_zero(nctx, struct getent_ctx);
    if (!state->nctx->svcctx) {
        ret = ENOMEM;
        goto immediate;
    }
    state->getent_ctx = nctx->svcctx;

    /* Assume that all domains will have results (to avoid having
     * to reallocate later
     */
    num_domains = 0;
    dom = state->cctx->rctx->domains;
    while (dom) {
        num_domains++;
        dom = dom->next;
    }

    state->nctx->svcctx->doms = talloc_zero_array(state->nctx->svcctx,
                                                  struct dom_ctx,
                                                  num_domains);
    if (!state->nctx->svcctx->doms) {
        ret = ENOMEM;
        goto immediate;
    }

    /* Add a callback reference for ourselves */
    ret = nss_setent_add_ref(state, state->nctx->svcctx, req);
    if (ret != EOK) {
        goto immediate;
    }

    /* ok, start the searches */
    step_ctx = talloc_zero(state->getent_ctx, struct setent_step_ctx);
    if (!step_ctx) {
        ret = ENOMEM;
        goto immediate;
    }

    /* Steal the dom_ctx onto the step_ctx so it doesn't go out of scope if
     * this request is canceled while other requests are in-progress.
     */
    step_ctx->dctx = talloc_steal(step_ctx, state->dctx);
    step_ctx->nctx = state->nctx;
    step_ctx->getent_ctx = state->getent_ctx;
    step_ctx->rctx = cctx->rctx;
    step_ctx->cctx = cctx;
    step_ctx->returned_to_mainloop = false;

    while (step_ctx->dctx->domain) {
        /* There are more domains to check */
        ret = setservent_step(step_ctx);
        if (ret == EOK) {
            /* Re-enter the mainloop */
            return req;
        }

        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error [%s] requesting info from domain [%s]. Skipping.\n",
               strerror(ret), step_ctx->dctx->domain->name));

        step_ctx->dctx->domain = step_ctx->dctx->domain->next;
    }

    /* All domains failed */
    ret = EIO;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, cctx->rctx->ev);
    return req;
}

static errno_t
setservent_step(struct setent_step_ctx *step_ctx)
{
    struct tevent_req *req;

    req = lookup_servent_send(step_ctx,
                              step_ctx->rctx,
                              step_ctx->dctx->domain);
    if (!req) {
        return ENOMEM;
    }
    tevent_req_set_callback(req, setservent_step_done, step_ctx);

    return EOK;
}

struct lookup_servent_ctx {
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    struct ldb_result *res;
};

static void
lookup_servent_done(struct tevent_req *subreq);

static void
setservent_finalize(struct setent_step_ctx *step_ctx);

static struct tevent_req *
lookup_servent_send(TALLOC_CTX *mem_ctx,
                    struct resp_ctx *rctx,
                    struct sss_domain_info *dom)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct lookup_servent_ctx *state;
    struct sysdb_ctx *sysdb;

    req = tevent_req_create(mem_ctx, &state, struct lookup_servent_ctx);
    if (!req) return NULL;

    state->rctx = rctx;
    state->dom = dom;

    if (!dom->enumerate) {
        ret = ENOENT;
        goto immediate;
    }

    if (!(NEED_CHECK_PROVIDER(dom->name))) {
        /* No provider check required. Just ask the
         * sysdb.
         */
        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("Sysdb CTX not found for [%s]!\n", dom->name));
            ret = EINVAL;
            goto immediate;
        }

        ret = sysdb_enumservent(state, sysdb, &state->res);
        /* Whatever the result, we're done, so report it */
        goto immediate;
    }

    /* We need to ask the provider for an enumeration */
    /* Update the cache */
    subreq = sss_dp_get_account_send(req,  rctx, state->dom,
                                     true, SSS_DP_SERVICES,
                                     NULL, 0, NULL);
    if (!subreq) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, lookup_servent_done, req);

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ENOENT);
    }
    tevent_req_post(req, rctx->ev);
    return req;
}

static void
lookup_servent_done(struct tevent_req *subreq)
{
    errno_t ret;
    dbus_uint16_t dp_err;
    dbus_uint32_t dp_ret;
    char *err_msg;
    struct sysdb_ctx *sysdb;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct lookup_servent_ctx *state =
            tevent_req_data(req, struct lookup_servent_ctx);

    ret = sss_dp_get_account_recv(state, subreq,
                                  &dp_err, &dp_ret, &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get information from Data Provider\n"
               "dp_error: [%u], errno: [%u], error_msg: [%s]\n"
               "Will try to return what we have in cache\n",
               (unsigned int)dp_err, (unsigned int)dp_ret,
               err_msg ? err_msg : "none"));
    }

    /* Check the cache now */
    sysdb = state->dom->sysdb;
    if (sysdb == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Sysdb CTX not found for [%s]!\n", state->dom->name));
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_enumservent(state, sysdb, &state->res);
    /* Whatever the result, we're done, so report it */

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static errno_t
lookup_servent_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    struct ldb_result **res)
{
    struct lookup_servent_ctx *state =
            tevent_req_data(req, struct lookup_servent_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *res = talloc_steal(mem_ctx, state->res);
    return EOK;
}

static void
setservent_step_done(struct tevent_req *req)
{
    errno_t ret;
    struct ldb_result *res = NULL;
    struct setent_step_ctx *step_ctx =
            tevent_req_callback_data(req, struct setent_step_ctx);
    struct nss_dom_ctx *dctx = step_ctx->dctx;
    struct getent_ctx *svcctx = step_ctx->getent_ctx;


    ret = lookup_servent_recv(step_ctx, req, &res);
    talloc_zfree(req);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Domain [%s] returned no results\n", dctx->domain->name));
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error [%s] while retrieving info from domain [%s]. "
               "Skipping.\n", strerror(ret), dctx->domain->name));
        /* Continue on */
    } else {
        /* Got some results
         * Add the retrieved results to the list
         */
        svcctx->doms[svcctx->num].domain = dctx->domain;
        svcctx->doms[svcctx->num].res = talloc_steal(svcctx->doms, res);
        svcctx->num++;
    }

    step_ctx->dctx->domain = step_ctx->dctx->domain->next;

    while (step_ctx->dctx->domain) {
        /* There are more domains to check */
        ret = setservent_step(step_ctx);
        if (ret == EOK) {
            /* Re-enter the mainloop */
            return;
        }

        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error [%s] requesting info from domain [%s]. Skipping.\n",
               strerror(ret), step_ctx->dctx->domain->name));

        step_ctx->dctx->domain = step_ctx->dctx->domain->next;
    }

    /* All domains have been checked */
    setservent_finalize(step_ctx);
}

static void
setservent_result_timeout(struct tevent_context *ev,
                          struct tevent_timer *te,
                          struct timeval current_time,
                          void *pvt);

static void
setservent_finalize(struct setent_step_ctx *step_ctx)
{
    struct nss_ctx *nctx = step_ctx->nctx;
    struct resp_ctx *rctx = step_ctx->rctx;
    struct timeval tv;
    struct tevent_timer *te;

    /* We've finished all our lookups
     * The result object is now safe to read.
     */
    nctx->svcctx->ready = true;

    /* Set up a lifetime timer for this result object
     * We don't want this result object to outlive the
     * enum cache refresh timeout
     */
    tv = tevent_timeval_current_ofs(nctx->enum_cache_timeout, 0);
    te = tevent_add_timer(rctx->ev, nctx->svcctx, tv,
                          setservent_result_timeout, nctx);
    if (!te) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not set up life timer for setservent result object. "
               "Entries may become stale.\n"));
    }

    nss_setent_notify_done(nctx->svcctx);
}

static void
setservent_result_timeout(struct tevent_context *ev,
                          struct tevent_timer *te,
                          struct timeval current_time,
                          void *pvt)
{
    struct nss_ctx *nctx = talloc_get_type(pvt, struct nss_ctx);

    DEBUG(SSSDBG_TRACE_FUNC,
          ("setservent result object has expired. Cleaning up.\n"));

    /* Free the service enumeration context.
     * If additional getservent requests come in, they will invoke
     * an implicit setservent and refresh the result object.
     */
    talloc_zfree(nctx->svcctx);
}

static errno_t
setservent_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static void
nss_cmd_setservent_done(struct tevent_req *req);

int
nss_cmd_setservent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;
    errno_t ret = EOK;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    req = setservent_send(cmdctx, cctx);
    if (!req) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Fatal error calling nss_cmd_setservent_send\n"));
        ret = EIO;
        goto done;
    }
    tevent_req_set_callback(req, nss_cmd_setservent_done, cmdctx);

done:
    return nss_cmd_done(cmdctx, ret);
}

static void
nss_cmd_setservent_done(struct tevent_req *req)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);

    ret = setservent_recv(req);
    talloc_zfree(req);
    if (ret == EOK || ret == ENOENT) {
        /* Either we succeeded or no domains
         * were eligible.
         * Return an acknowledgment
         */
        ret = sss_packet_new(cmdctx->cctx->creq, 0,
                             sss_packet_get_cmd(cmdctx->cctx->creq->in),
                             &cmdctx->cctx->creq->out);
        if (ret == EOK) {
            sss_cmd_done(cmdctx->cctx, cmdctx);
            return;
        }
    }

    /* Something bad happened.
     * Return an error
     */
    nss_cmd_done(cmdctx, ret);
}

static void
nss_cmd_implicit_setservent_done(struct tevent_req *req);

static errno_t
nss_cmd_getservent_immediate(struct nss_cmd_ctx *cmdctx);

static errno_t
retservent(struct cli_ctx *cctx, int num);

int nss_cmd_getservent(struct cli_ctx *cctx)
{
    struct nss_ctx *nctx;
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requesting info for all services\n"));

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* Save the current index and cursor locations
     * If we end up calling setservent implicitly, because the response object
     * expired and has to be recreated, we want to resume from the same
     * location.
     */
    cmdctx->saved_dom_idx = cctx->svc_dom_idx;
    cmdctx->saved_cur = cctx->svcent_cur;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    if(!nctx->svcctx || !nctx->svcctx->ready) {
        /* Make sure we invoke setservent if it hasn't been run or is still
         * processing from another client
         */
        req = setservent_send(cmdctx, cctx);
        if (!req) {
            return EIO;
        }
        tevent_req_set_callback(req,
                                nss_cmd_implicit_setservent_done,
                                cmdctx);
        return EOK;
    }

    return nss_cmd_getservent_immediate(cmdctx);
}

static void
nss_cmd_implicit_setservent_done(struct tevent_req *req)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);

    ret = setservent_recv(req);
    talloc_zfree(req);

    /* ENOENT is acceptable, as it just means that there were no entries
     * to be returned. This will be handled gracefully in retservent
     * later.
     */
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Implicit setservent failed with unexpected error [%d][%s]\n",
               ret, strerror(ret)));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }

    /* Restore the saved index and cursor locations */
    cmdctx->cctx->svc_dom_idx = cmdctx->saved_dom_idx;
    cmdctx->cctx->svcent_cur = cmdctx->saved_cur;

    ret = nss_cmd_getservent_immediate(cmdctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Immediate retrieval failed with unexpected error "
               "[%d][%s]\n", ret, strerror(ret)));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }
}

static errno_t
nss_cmd_getservent_immediate(struct nss_cmd_ctx *cmdctx)
{
    struct cli_ctx *cctx = cmdctx->cctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    /* get max num of entries to return in one call */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    num = *((uint32_t *)body);

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    ret = retservent(cctx, num);

    sss_packet_set_error(cctx->creq->out, ret);
    sss_cmd_done(cctx, cmdctx);

    return EOK;
}

static errno_t
retservent(struct cli_ctx *cctx, int num)
{
    struct nss_ctx *nctx;
    struct getent_ctx *svcctx;
    struct ldb_message **msgs = NULL;
    struct dom_ctx *pdom = NULL;
    unsigned int n = 0;
    int ret = ENOENT;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    if (!nctx->svcctx) goto none;

    svcctx = nctx->svcctx;

    while (ret == ENOENT) {
        if (cctx->svc_dom_idx >= svcctx->num) break;

        pdom = &svcctx->doms[cctx->svc_dom_idx];

        n = pdom->res->count - cctx->svcent_cur;
        if (n <= 0 && (cctx->svc_dom_idx+1 < svcctx->num)) {
            cctx->svc_dom_idx++;
            pdom = &svcctx->doms[cctx->svc_dom_idx];
            n = pdom->res->count;
            cctx->svcent_cur = 0;
        }

        if (!n) break;

        if (n > num) n = num;

        msgs = &(pdom->res->msgs[cctx->svcent_cur]);

        ret = fill_service(cctx->creq->out,
                           pdom->domain,
                           nctx, NULL, msgs,
                           &n);

        cctx->svcent_cur += n;
    }

none:
    if (ret == ENOENT) {
        ret = sss_cmd_empty_packet(cctx->creq->out);
    }
    return ret;
}

int nss_cmd_endservent(struct cli_ctx *cctx)
{
    struct nss_ctx *nctx;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Terminating request info for all accounts\n"));

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);

    if (ret != EOK) {
        return ret;
    }
    if (nctx->svcctx == NULL) goto done;

    /* Reset the indices so that subsequent requests start at zero */
    cctx->svc_dom_idx = 0;
    cctx->svcent_cur = 0;

done:
    sss_cmd_done(cctx, NULL);
    return EOK;
}
