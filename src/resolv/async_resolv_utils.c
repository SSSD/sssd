/*
    Authors:
        Pavel B??ezina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include <string.h>
#include <talloc.h>
#include <tevent.h>
#include <unistd.h>

#include "util/util.h"
#include "resolv/async_resolv.h"

struct resolv_get_domain_state {
    char *fqdn;
    char *hostname;
};

static void resolv_get_domain_done(struct tevent_req *subreq);

struct tevent_req *
resolv_get_domain_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct resolv_ctx *resolv_ctx,
                        const char *hostname,
                        enum host_database *host_dbs,
                        enum restrict_family family_order)
{
    struct resolv_get_domain_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    char system_hostname[HOST_NAME_MAX];
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct resolv_get_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    if (hostname == NULL) {
        /* use system hostname */
        ret = gethostname(system_hostname, HOST_NAME_MAX);
        if (ret) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, ("gethostname() failed: [%d]: %s\n",
                                        ret, strerror(ret)));
            goto immediately;
        }
        system_hostname[HOST_NAME_MAX-1] = '\0';
        hostname = system_hostname;
    }

    state->fqdn = NULL;
    state->hostname = talloc_strdup(state, hostname);
    if (state->hostname == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_LIBS, ("Host name is: %s\n", state->hostname));

    subreq = resolv_gethostbyname_send(state, ev, resolv_ctx, state->hostname,
                                       family_order, host_dbs);
    if (subreq == NULL) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, resolv_get_domain_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void resolv_get_domain_done(struct tevent_req *subreq)
{
    struct resolv_get_domain_state *state = NULL;
    struct tevent_req *req = NULL;
    struct resolv_hostent *rhostent;
    int resolv_status;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct resolv_get_domain_state);

    ret = resolv_gethostbyname_recv(subreq, req, &resolv_status,
                                    NULL, &rhostent);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not get fully qualified name for host name %s "
               "error [%d]: %s, resolver returned: [%d]: %s\n",
               state->hostname, ret, strerror(ret), resolv_status,
               resolv_strerror(resolv_status)));
        state->fqdn = state->hostname;
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, ("The FQDN is: %s\n", rhostent->name));
        state->fqdn = talloc_steal(state, rhostent->name);
        talloc_zfree(rhostent);
    }

    tevent_req_done(req);
}

errno_t resolv_get_domain_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               char **_dns_domain)
{
    struct resolv_get_domain_state *state = NULL;
    char *dns_domain = NULL;
    char *domptr = NULL;

    state = tevent_req_data(req, struct resolv_get_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    domptr = strchr(state->fqdn, '.');
    if (domptr == NULL || (*(domptr+1) == '\0')) {
        /* If the FQDN did not contain a dot or the dot was the last character
         * (broken DNS server perhaps) */
        dns_domain = state->fqdn;
    } else {
        dns_domain = domptr + 1;
    }

    *_dns_domain = talloc_strdup(mem_ctx, dns_domain);
    if (*_dns_domain == NULL) {
        return ENOMEM;
    }

    return EOK;
}
