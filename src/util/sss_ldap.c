/*
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

#include "config.h"

#include <fcntl.h>

#include "util/util.h"
#include "util/sss_sockets.h"
#include "util/sss_ldap.h"

#include "providers/ldap/sdap.h"

const char* sss_ldap_err2string(int err)
{
    if (IS_SSSD_ERROR(err)) {
        return sss_strerror(err);
    } else {
        return ldap_err2string(err);
    }
}

void sss_ldap_error_debug(int level, const char *msg, LDAP *ld, int error_code)
{
    char *diagnostics = NULL;
    int ret;

    ret = ldap_get_option(ld, SDAP_DIAGNOSTIC_MESSAGE, (void*)&diagnostics);

    DEBUG(level, "%s: '%s' ('%s')\n", msg,
          sss_ldap_err2string(error_code),
          ((ret == LDAP_SUCCESS) ? diagnostics : "-no diagnostics-"));

    if (ret == LDAP_SUCCESS) {
        ldap_memfree(diagnostics);
    }
}

int sss_ldap_control_create(const char *oid, int iscritical,
                            struct berval *value, int dupval,
                            LDAPControl **ctrlp)
{
#ifdef HAVE_LDAP_CONTROL_CREATE
    return ldap_control_create(oid, iscritical, value, dupval, ctrlp);
#else
    LDAPControl *lc = NULL;

    if (oid == NULL || ctrlp == NULL) {
        return LDAP_PARAM_ERROR;
    }

    lc = calloc(sizeof(LDAPControl), 1);
    if (lc == NULL) {
        return LDAP_NO_MEMORY;
    }

    lc->ldctl_oid = strdup(oid);
    if (lc->ldctl_oid == NULL) {
        free(lc);
        return LDAP_NO_MEMORY;
    }

    if (value != NULL && value->bv_val != NULL) {
        if (dupval == 0) {
            lc->ldctl_value = *value;
        } else {
            ber_dupbv(&lc->ldctl_value, value);
            if (lc->ldctl_value.bv_val == NULL) {
                free(lc->ldctl_oid);
                free(lc);
                return LDAP_NO_MEMORY;
            }
        }
    }

    lc->ldctl_iscritical = iscritical;

    *ctrlp = lc;

    return LDAP_SUCCESS;
#endif
}

#ifdef HAVE_LDAP_INIT_FD

#define LDAP_PROTO_TCP 1 /* ldap://  */
#define LDAP_PROTO_UDP 2 /* reserved */
#define LDAP_PROTO_IPC 3 /* ldapi:// */
#define LDAP_PROTO_EXT 4 /* user-defined socket/sockbuf */

extern int ldap_init_fd(ber_socket_t fd, int proto, const char *url, LDAP **ld);

static void sss_ldap_init_sys_connect_done(struct tevent_req *subreq);
#endif

struct sss_ldap_init_state {
    LDAP *ldap;
    int sd;
    const char *uri;
    bool use_udp;
};

static int sss_ldap_init_state_destructor(void *data)
{
    struct sss_ldap_init_state *state = (struct sss_ldap_init_state *)data;

    if (state->ldap) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "calling ldap_unbind_ext for ldap:[%p] sd:[%d]\n",
              state->ldap, state->sd);
        ldap_unbind_ext(state->ldap, NULL, NULL);
    }
    if (state->sd != -1) {
        DEBUG(SSSDBG_TRACE_FUNC, "closing socket [%d]\n", state->sd);
        close(state->sd);
        state->sd = -1;
    }

    return 0;
}


struct tevent_req *sss_ldap_init_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      const char *uri,
                                      struct sockaddr *addr,
                                      int addr_len, int timeout)
{
    int ret = EOK;
    struct tevent_req *req;
    struct sss_ldap_init_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sss_ldap_init_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    talloc_set_destructor((TALLOC_CTX *)state, sss_ldap_init_state_destructor);

    state->ldap = NULL;
    state->sd = -1;
    state->uri = uri;
    state->use_udp = strncmp(uri, "cldap", 5) == 0 ? true : false;

#ifdef HAVE_LDAP_INIT_FD
    struct tevent_req *subreq;

    subreq = sssd_async_socket_init_send(state, ev, state->use_udp, addr,
                                         addr_len, timeout);
    if (subreq == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "sssd_async_socket_init_send failed.\n");
        goto fail;
    }

    tevent_req_set_callback(subreq, sss_ldap_init_sys_connect_done, req);
    return req;

fail:
    tevent_req_error(req, ret);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "ldap_init_fd not available, "
              "will use ldap_initialize with uri [%s].\n", uri);
    ret = ldap_initialize(&state->ldap, uri);
    if (ret == LDAP_SUCCESS) {
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ldap_initialize failed [%s].\n", sss_ldap_err2string(ret));
        if (ret == LDAP_SERVER_DOWN) {
            tevent_req_error(req, ETIMEDOUT);
        } else {
            tevent_req_error(req, EIO);
        }
    }
#endif

    tevent_req_post(req, ev);
    return req;
}

#ifdef HAVE_LDAP_INIT_FD
static errno_t unset_fcntl_flags(int fd, int fl_flags)
{
    errno_t ret;
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fcntl F_GETFL failed [%s].\n", strerror(ret));
        return ret;
    }

    /* unset flags */
    flags &= ~fl_flags;

    ret = fcntl(fd, F_SETFL, flags);
    if (ret != EOK) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fcntl F_SETFL failed [%s].\n", strerror(ret));
        return ret;
    }

    return EOK;
}

static void sss_ldap_init_sys_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sss_ldap_init_state *state = tevent_req_data(req,
                                                    struct sss_ldap_init_state);
    int ret;
    int lret;
    int ticks_before_install;
    int ticks_after_install;

    ret = sssd_async_socket_init_recv(subreq, &state->sd);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sssd_async_socket_init request failed: [%d]: %s.\n",
              ret, sss_strerror(ret));
        goto fail;
    }

    /* openldap < 2.5 does not correctly handle O_NONBLOCK during starttls for
     * ldaps, so we need to remove the flag here. This is fine since I/O events
     * are handled via tevent so we only read when there is data available.
     *
     * We need to keep O_NONBLOCK due to a bug in openldap to correctly perform
     * a parallel CLDAP pings without timeout. See:
     * https://bugs.openldap.org/show_bug.cgi?id=9328
     *
     * @todo remove this when the bug is fixed and we can put a hard requirement
     * on newer openldap.
     */
    if (!state->use_udp) {
        ret = unset_fcntl_flags(state->sd, O_NONBLOCK);
        if (ret != EOK) {
            goto fail;
        }
    }

    /* Initialize LDAP handler */

    lret = ldap_init_fd(state->sd,
                        state->use_udp ? LDAP_PROTO_UDP : LDAP_PROTO_TCP,
                        state->uri, &state->ldap);
    if (lret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ldap_init_fd failed: %s. [%d][%s]\n",
               sss_ldap_err2string(lret), state->sd, state->uri);
        ret = lret == LDAP_SERVER_DOWN ? ETIMEDOUT : EIO;
        goto fail;
    }

    if (ldap_is_ldaps_url(state->uri)) {
        ticks_before_install = get_watchdog_ticks();
        lret = ldap_install_tls(state->ldap);
        ticks_after_install = get_watchdog_ticks();
        if (lret != LDAP_SUCCESS) {
            if (lret == LDAP_LOCAL_ERROR) {
                DEBUG(SSSDBG_FUNC_DATA, "TLS/SSL already in place.\n");
            } else {
                sss_ldap_error_debug(SSSDBG_CRIT_FAILURE, "ldap_install_tls failed",
                                     state->ldap, lret);
                sss_log(SSS_LOG_ERR, "Could not start TLS encryption.");

                if (ticks_after_install > ticks_before_install) {
                    ret = ERR_TLS_HANDSHAKE_INTERRUPTED;
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Assuming %s\n",
                          sss_ldap_err2string(ret));
                    goto fail;
                }

                ret = EIO;
                goto fail;
            }
        }
    }

    tevent_req_done(req);
    return;

fail:
    tevent_req_error(req, ret);
}
#endif

int sss_ldap_init_recv(struct tevent_req *req, LDAP **ldap, int *sd)
{
    struct sss_ldap_init_state *state = tevent_req_data(req,
                                                    struct sss_ldap_init_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    /* Everything went well therefore we do not want to release resources */
    talloc_set_destructor(state, NULL);

    *ldap = state->ldap;
    *sd = state->sd;

    return EOK;
}

/*
 * _filter will contain combined filters from all possible search bases
 * or NULL if it should be empty
 */


bool sss_ldap_dn_in_search_bases_len(TALLOC_CTX *mem_ctx,
                                     const char *dn,
                                     struct sdap_search_base **search_bases,
                                     char **_filter,
                                     int *_match_len)
{
    struct sdap_search_base *base;
    int basedn_len, dn_len;
    int len_diff;
    int i, j;
    bool base_confirmed = false;
    bool comma_found = false;
    bool backslash_found = false;
    char *filter = NULL;
    bool ret = false;
    int match_len;

    if (dn == NULL) {
        DEBUG(SSSDBG_FUNC_DATA, "dn is NULL\n");
        ret = false;
        goto done;
    }

    if (search_bases == NULL) {
        DEBUG(SSSDBG_FUNC_DATA, "search_bases is NULL\n");
        ret = false;
        goto done;
    }

    dn_len = strlen(dn);
    for (i = 0; search_bases[i] != NULL; i++) {
        base = search_bases[i];
        basedn_len = strlen(base->basedn);

        if (basedn_len > dn_len) {
            continue;
        }

        len_diff = dn_len - basedn_len;
        base_confirmed = (strncasecmp(&dn[len_diff], base->basedn, basedn_len) == 0);
        if (!base_confirmed) {
            continue;
        }
        match_len = basedn_len;

        switch (base->scope) {
        case LDAP_SCOPE_BASE:
            /* dn > base? */
            if (len_diff != 0) {
                continue;
            }
            break;
        case LDAP_SCOPE_ONELEVEL:
            if (len_diff == 0) {
                /* Base object doesn't belong to scope=one
                 * search */
                continue;
            }

            comma_found = false;
            for (j = 0; j < len_diff - 1; j++) { /* ignore comma before base */
                if (dn[j] == '\\') {
                    backslash_found = true;
                } else if (dn[j] == ',' && !backslash_found) {
                    comma_found = true;
                    break;
                } else {
                    backslash_found = false;
                }
            }

            /* it has at least one more level */
            if (comma_found) {
                continue;
            }

            break;
        case LDAP_SCOPE_SUBTREE:
            /* dn length >= base dn length && base_confirmed == true */
            break;
        default:
            DEBUG(SSSDBG_FUNC_DATA, "Unsupported scope: %d\n", base->scope);
            continue;
        }

        /*
         *  If we get here, the dn is valid.
         *  If no filter is set, than return true immediately.
         *  Append filter otherwise.
         */
        ret = true;
        if (_match_len) {
            *_match_len = match_len;
        }

        if (base->filter == NULL || _filter == NULL) {
            goto done;
        } else {
            filter = talloc_strdup_append(filter, base->filter);
            if (filter == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup_append() failed\n");
                ret = false;
                goto done;
            }
        }
    }

    if (_filter != NULL) {
        if (filter != NULL) {
            *_filter = talloc_asprintf(mem_ctx, "(|%s)", filter);
            if (*_filter == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "talloc_asprintf_append() failed\n");
                ret = false;
                goto done;
            }
        } else {
            *_filter = NULL;
        }
    }

done:
    talloc_free(filter);
    return ret;
}

bool sss_ldap_dn_in_search_bases(TALLOC_CTX *mem_ctx,
                                 const char *dn,
                                 struct sdap_search_base **search_bases,
                                 char **_filter)
{
    return sss_ldap_dn_in_search_bases_len(mem_ctx, dn, search_bases, _filter,
                                           NULL);
}

char *sss_ldap_encode_ndr_uint32(TALLOC_CTX *mem_ctx, uint32_t flags)
{
    char hex[9]; /* 4 bytes in hex + terminating zero */
    errno_t ret;

    ret = snprintf(hex, 9, "%08x", flags);
    if (ret != 8) {
        return NULL;
    }

    return talloc_asprintf(mem_ctx, "\\%c%c\\%c%c\\%c%c\\%c%c",
                           hex[6], hex[7], hex[4], hex[5],
                           hex[2], hex[3], hex[0], hex[1]);
}
