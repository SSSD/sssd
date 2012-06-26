/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <errno.h>
#include <tevent.h>
#include <talloc.h>

#include "util/util.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_id_op.h"
#include "providers/ldap/sdap_sudo.h"

struct sdap_sudo_get_hostinfo_state {
    char **hostnames;
    char **ip_addr;
};

struct tevent_req * sdap_sudo_get_hostinfo_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_options *opts,
                                                struct be_ctx *be_ctx)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_get_hostinfo_state *state = NULL;
    char *conf_hostnames = NULL;
    char *conf_ip_addr = NULL;
    int ret;

    /* create request */
    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_get_hostinfo_state);
    if (req == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->hostnames = NULL;
    state->ip_addr = NULL;

    /* load info from configuration */
    conf_hostnames = dp_opt_get_string(opts->basic, SDAP_SUDO_HOSTNAMES);
    conf_ip_addr = dp_opt_get_string(opts->basic, SDAP_SUDO_IP);

    if (conf_hostnames != NULL) {
        ret = split_on_separator(state, conf_hostnames, ' ', true,
                                 &state->hostnames, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Unable to parse hostnames [%d]: %s\n", ret, strerror(ret)));
            goto done;
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS, ("Hostnames set to: %s\n", conf_hostnames));
        }
    }

    if (conf_ip_addr != NULL) {
        ret = split_on_separator(state, conf_ip_addr, ' ', true,
                                 &state->ip_addr, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Unable to parse IP addresses [%d]: %s\n", ret, strerror(ret)));
            goto done;
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS, ("IP addresses set to: %s\n", conf_ip_addr));
        }
    }

    /* auto configuration will be supported later */

done:
    if (ret != EAGAIN) {
        if (ret == EOK) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
        tevent_req_post(req, be_ctx->ev);
    }

    return req;
}

int sdap_sudo_get_hostinfo_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                char ***hostnames, char ***ip_addr)
{
    struct sdap_sudo_get_hostinfo_state *state = NULL;
    state = tevent_req_data(req, struct sdap_sudo_get_hostinfo_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *hostnames = talloc_steal(mem_ctx, state->hostnames);
    *ip_addr = talloc_steal(mem_ctx, state->ip_addr);

    return EOK;
}
