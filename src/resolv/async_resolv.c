/*
   SSSD

   Async resolver

   Authors:
        Martin Nagy <mnagy@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2009

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

#include <sys/select.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <ares.h>
#include <talloc.h>
#include <tevent.h>

#include <errno.h>
#include <netdb.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "resolv/async_resolv.h"
#include "util/dlinklist.h"
#include "util/util.h"

#ifndef HAVE_ARES_DATA
#define ares_parse_srv_reply(abuf, alen, srv_out) \
    _ares_parse_srv_reply(abuf, alen, srv_out)
#define ares_parse_txt_reply(abuf, alen, txt_out) \
    _ares_parse_txt_reply(abuf, alen, txt_out)
#define ares_free_data(dataptr) \
    _ares_free_data(dataptr)
#define ares_malloc_data(data) \
    _ares_malloc_data(data)
#endif /* HAVE_ARES_DATA */

#ifndef HAVE_STRUCT_ARES_ADDRTTL
#define ares_addrttl addrttl
#endif

#ifndef HAVE_STRUCT_ARES_ADDR6TTL
#define ares_addr6ttl addr6ttl
#endif

#define DNS__16BIT(p)                   (((p)[0] << 8) | (p)[1])
#define DNS_HEADER_ANCOUNT(h)           DNS__16BIT((h) + 6)

#define RESOLV_TIMEOUTMS  5000

enum host_database default_host_dbs[] = { DB_FILES, DB_DNS, DB_SENTINEL };

struct fd_watch {
    struct fd_watch *prev;
    struct fd_watch *next;

    int fd;
    struct resolv_ctx *ctx;
    struct tevent_fd *fde;
};

struct resolv_ctx {
    /* Contexts are linked so we can keep track of them and re-create
     * the ares channels in all of them at once if we need to. */
    struct resolv_ctx *prev;
    struct resolv_ctx *next;

    struct tevent_context *ev_ctx;
    ares_channel channel;

    /* List of file descriptors that are watched by tevent. */
    struct fd_watch *fds;

    /* Time in milliseconds before canceling a DNS request */
    int timeout;

    /* The timeout watcher periodically calls ares_process_fd() to check
     * if our pending requests didn't timeout. */
    int pending_requests;
    struct tevent_timer *timeout_watcher;
};

struct request_watch {
    struct tevent_req *req;
    struct resolv_request *rr;
};

struct resolv_request {
    struct resolv_ctx *ctx;
    struct request_watch *rwatch;
    struct tevent_timer *request_timeout;
};

struct resolv_ctx *context_list;

errno_t
resolv_get_family_order(struct confdb_ctx *cdb, const char *conf_path,
                        enum restrict_family *family_order)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *str_opt;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = confdb_get_string(cdb, tmp_ctx, conf_path,
                            CONFDB_DOMAIN_FAMILY_ORDER,
                            "ipv4_first", &str_opt);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(7, ("Lookup order: %s\n", str_opt));

    if (strcasecmp(str_opt, "ipv4_first") == 0) {
        *family_order = IPV4_FIRST;
    } else if (strcasecmp(str_opt, "ipv4_only") == 0) {
        *family_order = IPV4_ONLY;
    } else if (strcasecmp(str_opt, "ipv6_first") == 0) {
        *family_order = IPV6_FIRST;
    } else if (strcasecmp(str_opt, "ipv6_only") == 0) {
        *family_order = IPV6_ONLY;
    } else {
        DEBUG(1, ("Unknown value for option %s: %s\n",
                  CONFDB_DOMAIN_FAMILY_ORDER, str_opt));
        ret = EINVAL;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int
return_code(int ares_code)
{
    switch (ares_code) {
    case ARES_SUCCESS:
        return EOK;
    case ARES_ENOMEM:
        return ENOMEM;
    case ARES_EFILE:
    default:
        return EIO;
    }
}

const char *
resolv_strerror(int ares_code)
{
    return ares_strerror(ares_code);
}

static int
fd_watch_destructor(struct fd_watch *f)
{
    DLIST_REMOVE(f->ctx->fds, f);
    f->fd = -1;

    return 0;
}

static void
fd_input_available(struct tevent_context *ev, struct tevent_fd *fde,
                   uint16_t flags, void *data)
{
    struct fd_watch *watch = talloc_get_type(data, struct fd_watch);

    if (watch->ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        return;
    }

    if (flags & TEVENT_FD_READ) {
        ares_process_fd(watch->ctx->channel, watch->fd, ARES_SOCKET_BAD);
    }
    if (flags & TEVENT_FD_WRITE) {
        ares_process_fd(watch->ctx->channel, ARES_SOCKET_BAD, watch->fd);
    }
}

static void
check_fd_timeouts(struct tevent_context *ev, struct tevent_timer *te,
                  struct timeval current_time, void *private_data);

static void
add_timeout_timer(struct tevent_context *ev, struct resolv_ctx *ctx)
{
    struct timeval tv = { 0, 0 };
    struct timeval *tvp;

    if (ctx->timeout_watcher) {
        return;
    }

    tvp = ares_timeout(ctx->channel, NULL, &tv);

    if (tvp == NULL) {
        tvp = &tv;
    }

    /* Enforce a minimum of 1 second. */
    if (tvp->tv_sec < 1) {
        tv = tevent_timeval_current_ofs(1, 0);
    } else {
        tv = tevent_timeval_current_ofs(tvp->tv_sec, tvp->tv_usec);
    }

    ctx->timeout_watcher = tevent_add_timer(ev, ctx, tv, check_fd_timeouts,
                                            ctx);
    if (ctx->timeout_watcher == NULL) {
        DEBUG(1, ("Out of memory\n"));
    }
}

static void
check_fd_timeouts(struct tevent_context *ev, struct tevent_timer *te,
                  struct timeval current_time, void *private_data)
{
    struct resolv_ctx *ctx = talloc_get_type(private_data, struct resolv_ctx);

    DEBUG(9, ("Checking for DNS timeouts\n"));

    /* NULLify the timeout_watcher so we don't
     * free it in the _done() function if it
     * gets called. Now that we're already in
     * the handler, tevent will take care of
     * freeing it when it returns.
     */
    ctx->timeout_watcher = NULL;

    ares_process_fd(ctx->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

    if (ctx->pending_requests > 0) {
        add_timeout_timer(ev, ctx);
    }
}

static void
resolv_request_timeout(struct tevent_context *ev,
                       struct tevent_timer *te,
                       struct timeval tv, void *pvt)
{
    struct resolv_request *rreq;

    DEBUG(SSSDBG_MINOR_FAILURE, ("The resolve request timed out\n"));

    rreq = talloc_get_type(pvt, struct resolv_request);
    if (rreq->rwatch == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("The request already completed\n"));
        return;
    }

    tevent_req_error(rreq->rwatch->req, ETIMEDOUT);
    rreq->rwatch = NULL;
}

static int
request_watch_destructor(struct request_watch *rwatch)
{
    DEBUG(SSSDBG_TRACE_FUNC, ("Deleting request watch\n"));
    if (rwatch->rr) rwatch->rr->rwatch = NULL;
    return 0;
}

static struct resolv_request *
schedule_request_timeout(struct tevent_context *ev, struct resolv_ctx *ctx,
                         struct tevent_req *req)
{
    struct resolv_request *rreq;
    struct timeval tv;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Scheduling a timeout of %d seconds\n",
                                  ctx->timeout));
    tv = tevent_timeval_current_ofs(ctx->timeout, 0);

    /* Intentionally allocating on ctx, because the request might go away
     * before c-ares returns */
    rreq = talloc(ctx, struct resolv_request);
    if (!rreq) {
        talloc_zfree(req);
        return NULL;
    }
    rreq->ctx = ctx;
    rreq->request_timeout = tevent_add_timer(ev, rreq, tv,
                                             resolv_request_timeout,
                                             rreq);
    if (rreq->request_timeout == NULL) {
        talloc_free(rreq);
        return NULL;
    }

    /* The watch will go away when the request finishes */
    rreq->rwatch = talloc(req, struct request_watch);
    if (!rreq->rwatch) {
        talloc_zfree(req);
        return NULL;
    }

    rreq->rwatch->req = req;
    rreq->rwatch->rr = rreq;
    talloc_set_destructor(rreq->rwatch, request_watch_destructor);

    return rreq;
}

static struct resolv_request *
schedule_timeout_watcher(struct tevent_context *ev, struct resolv_ctx *ctx,
                         struct tevent_req *req)
{
    struct resolv_request *rreq;

    rreq = schedule_request_timeout(ev, ctx, req);
    if (!rreq) return NULL;

    ctx->pending_requests++;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Scheduling DNS timeout watcher\n"));
    add_timeout_timer(ev, ctx);
    return rreq;
}

static void
unschedule_timeout_watcher(struct resolv_ctx *ctx, struct resolv_request *rreq)
{
    /* Unlink the watch if the request is still active */
    if (rreq->rwatch) {
        rreq->rwatch->rr = NULL;
    }
    talloc_free(rreq); /* Cancels the tevent timeout as well */

    if (ctx->pending_requests <= 0) {
        DEBUG(1, ("Pending DNS requests mismatch\n"));
        return;
    }

    ctx->pending_requests--;
    if (ctx->pending_requests == 0) {
        DEBUG(9, ("Unscheduling DNS timeout watcher\n"));
        talloc_zfree(ctx->timeout_watcher);
    }
}

static void fd_event_add(struct resolv_ctx *ctx, int s, int flags);
static void fd_event_close(struct resolv_ctx *ctx, int s);

/*
 * When ares is ready to read or write to a file descriptor, it will
 * call this callback. If both read and write are 0, it means that ares
 * will soon close the socket. We are mainly using this function to register
 * new file descriptors with tevent.
 */
static void
fd_event(void *data, int s, int fd_read, int fd_write)
{
    struct resolv_ctx *ctx = talloc_get_type(data, struct resolv_ctx);
    struct fd_watch *watch;
    int flags;

    /* The socket is about to get closed. */
    if (fd_read == 0 && fd_write == 0) {
        fd_event_close(ctx, s);
        return;
    }

    flags = fd_read ? TEVENT_FD_READ : 0;
    flags |= fd_write ? TEVENT_FD_WRITE : 0;

    /* Are we already watching this file descriptor? */
    watch = ctx->fds;
    while (watch) {
        if (watch->fd == s) {
            tevent_fd_set_flags(watch->fde, flags);
            return;
        }
        watch = watch->next;
    }

    fd_event_add(ctx, s, flags);
}

static void
fd_event_add(struct resolv_ctx *ctx, int s, int flags)
{
    struct fd_watch *watch;

    /* The file descriptor is new, register it with tevent. */
    watch = talloc(ctx, struct fd_watch);
    if (watch == NULL) {
        DEBUG(1, ("Out of memory allocating fd_watch structure\n"));
        return;
    }
    talloc_set_destructor(watch, fd_watch_destructor);

    watch->fd = s;
    watch->ctx = ctx;

    watch->fde = tevent_add_fd(ctx->ev_ctx, watch, s, flags,
                               fd_input_available, watch);
    if (watch->fde == NULL) {
        DEBUG(1, ("tevent_add_fd() failed\n"));
        talloc_free(watch);
        return;
    }
    DLIST_ADD(ctx->fds, watch);
}

static void
fd_event_close(struct resolv_ctx *ctx, int s)
{
    struct fd_watch *watch;

    /* Remove the socket from list */
    watch = ctx->fds;
    while (watch) {
        if (watch->fd == s) {
            talloc_free(watch);
            return;
        }
        watch = watch->next;
    }
}

static int
resolv_ctx_destructor(struct resolv_ctx *ctx)
{
    ares_channel channel;

    DLIST_REMOVE(context_list, ctx);

    if (ctx->channel == NULL) {
        DEBUG(1, ("Ares channel already destroyed?\n"));
        return -1;
    }

    /* Set ctx->channel to NULL first, so that callbacks that get
     * ARES_EDESTRUCTION won't retry. */
    channel = ctx->channel;
    ctx->channel = NULL;
    ares_destroy(channel);

    return 0;
}

static int
recreate_ares_channel(struct resolv_ctx *ctx)
{
    int ret;
    ares_channel new_channel;
    ares_channel old_channel;
    struct ares_options options;

    DEBUG(4, ("Initializing new c-ares channel\n"));
    /* FIXME: the options would contain
     * the nameservers to contact, the domains
     * to search... => get from confdb
     */
    options.sock_state_cb = fd_event;
    options.sock_state_cb_data = ctx;
    options.timeout = RESOLV_TIMEOUTMS;
    /* Only affects ares_gethostbyname */
    options.lookups = discard_const("f");
    options.tries = 1;
    ret = ares_init_options(&new_channel, &options,
                            ARES_OPT_SOCK_STATE_CB |
                            ARES_OPT_TIMEOUTMS |
                            ARES_OPT_LOOKUPS |
                            ARES_OPT_TRIES);
    if (ret != ARES_SUCCESS) {
        DEBUG(1, ("Failed to initialize ares channel: %s\n",
                  resolv_strerror(ret)));
        return return_code(ret);
    }

    old_channel = ctx->channel;
    ctx->channel = new_channel;
    if (old_channel != NULL) {
        DEBUG(4, ("Destroying the old c-ares channel\n"));
        ares_destroy(old_channel);
    }

    return EOK;
}

int
resolv_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev_ctx,
            int timeout, struct resolv_ctx **ctxp)
{
    int ret;
    struct resolv_ctx *ctx;

    if (timeout < 1) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("The timeout is too short, DNS operations are going to fail. "
               "This is a bug outside unit tests\n"));
    }

    ctx = talloc_zero(mem_ctx, struct resolv_ctx);
    if (ctx == NULL)
        return ENOMEM;

    ctx->ev_ctx = ev_ctx;
    ctx->timeout = timeout;

    ret = recreate_ares_channel(ctx);
    if (ret != EOK) {
        goto done;
    }

    DLIST_ADD(context_list, ctx);
    talloc_set_destructor(ctx, resolv_ctx_destructor);

    *ctxp = ctx;
    return EOK;

done:
    talloc_free(ctx);
    return ret;
}

void
resolv_reread_configuration(void)
{
    struct resolv_ctx *ctx;

    DEBUG(4, ("Recreating all c-ares channels\n"));
    DLIST_FOR_EACH(ctx, context_list) {
        recreate_ares_channel(ctx);
    }
}

static errno_t
resolv_copy_in_addr(TALLOC_CTX *mem_ctx, struct resolv_addr *ret,
                    struct ares_addrttl *attl)
{
    ret->ipaddr = talloc_array(mem_ctx, uint8_t, sizeof(struct in_addr));
    if (!ret->ipaddr) return ENOMEM;

    memcpy(ret->ipaddr, &attl->ipaddr, sizeof(struct in_addr));
    ret->ttl = attl->ttl;

    return EOK;
}

static errno_t
resolv_copy_in6_addr(TALLOC_CTX *mem_ctx, struct resolv_addr *ret,
                     struct ares_addr6ttl *a6ttl)
{
    ret->ipaddr = talloc_array(mem_ctx, uint8_t, sizeof(struct in6_addr));
    if (!ret->ipaddr) return ENOMEM;

    memcpy(ret->ipaddr, &a6ttl->ip6addr, sizeof(struct in6_addr));
    ret->ttl = a6ttl->ttl;

    return EOK;
}

static struct resolv_hostent *
resolv_copy_hostent_common(TALLOC_CTX *mem_ctx, struct hostent *src)
{
    struct resolv_hostent *ret;
    int len;
    int i;

    ret = talloc_zero(mem_ctx, struct resolv_hostent);
    if (ret == NULL) {
        return NULL;
    }

    if (src->h_name != NULL) {
        ret->name = talloc_strdup(ret, src->h_name);
        if (ret->name == NULL) {
            goto fail;
        }
    }
    if (src->h_aliases != NULL) {
        for (len = 0; src->h_aliases[len] != NULL; len++);

        ret->aliases = talloc_array(ret, char *, len + 1);
        if (ret->aliases == NULL) {
            goto fail;
        }

        for (i = 0; i < len; i++) {
            ret->aliases[i] = talloc_strdup(ret->aliases, src->h_aliases[i]);
            if (ret->aliases[i] == NULL) {
                goto fail;
            }
        }
        ret->aliases[len] = NULL;
    }

    ret->family = src->h_addrtype;
    return ret;

fail:
    talloc_free(ret);
    return NULL;
}

struct resolv_hostent *
resolv_copy_hostent(TALLOC_CTX *mem_ctx, struct hostent *src)
{
    struct resolv_hostent *ret;
    int len;
    int i;

    ret = resolv_copy_hostent_common(mem_ctx, src);
    if (ret == NULL) {
        return NULL;
    }

    if (src->h_addr_list != NULL) {
        for (len = 0; src->h_addr_list[len] != NULL; len++);

        ret->addr_list = talloc_array(ret, struct resolv_addr *, len + 1);
        if (ret->addr_list == NULL) {
            goto fail;
        }

        for (i = 0; i < len; i++) {
            ret->addr_list[i] = talloc_zero(ret->addr_list,
                                            struct resolv_addr);
            if (ret->addr_list[i] == NULL) {
                goto fail;
            }

            ret->addr_list[i]->ipaddr = talloc_memdup(ret->addr_list[i],
                                                      src->h_addr_list[i],
                                                      src->h_length);
            if (ret->addr_list[i]->ipaddr == NULL) {
                goto fail;
            }
            ret->addr_list[i]->ttl = RESOLV_DEFAULT_TTL;
        }
        ret->addr_list[len] = NULL;
    }
    return ret;

fail:
    talloc_free(ret);
    return NULL;
}

struct resolv_hostent *
resolv_copy_hostent_ares(TALLOC_CTX *mem_ctx, struct hostent *src,
                         int family, void *ares_ttl_data,
                         int num_ares_ttl_data)
{
    struct resolv_hostent *ret;
    errno_t cret;
    int i;

    ret = resolv_copy_hostent_common(mem_ctx, src);
    if (ret == NULL) {
        return NULL;
    }

    if (num_ares_ttl_data > 0) {
        ret->addr_list = talloc_array(ret, struct resolv_addr *,
                                      num_ares_ttl_data + 1);
        if (ret->addr_list == NULL) {
            goto fail;
        }

        for (i = 0; i < num_ares_ttl_data; i++) {
            ret->addr_list[i] = talloc_zero(ret->addr_list,
                                            struct resolv_addr);
            if (ret->addr_list[i] == NULL) {
                goto fail;
            }

            switch (family) {
            case AF_INET:
                cret = resolv_copy_in_addr(ret->addr_list, ret->addr_list[i],
                                &((struct ares_addrttl *) ares_ttl_data)[i]);
                break;
            case AF_INET6:
                cret = resolv_copy_in6_addr(ret->addr_list, ret->addr_list[i],
                                &((struct ares_addr6ttl *) ares_ttl_data)[i]);
                break;
            default:
                DEBUG(1, ("Unknown address family %d\n"));
                goto fail;
            }

            if (cret != EOK) {
                DEBUG(1, ("Could not copy address\n"));
                goto fail;
            }
        }
        ret->addr_list[num_ares_ttl_data] = NULL;
    }

    ret->family = family;
    return ret;

fail:
    talloc_free(ret);
    return NULL;
}

/* =================== Resolve host name in files =========================*/
struct gethostbyname_files_state {
    struct resolv_ctx *resolv_ctx;

    /* Part of the query. */
    const char *name;
    int family;

    /* query result */
    struct resolv_hostent *rhostent;

    /* returned by ares. */
    int status;
};

/* Fake up an async interface even though files would
 * always be blocking */
static struct tevent_req *
resolv_gethostbyname_files_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct resolv_ctx *ctx,
                                const char *name,
                                int family)
{
    struct tevent_req *req;
    struct gethostbyname_files_state *state;
    struct hostent *hostent = NULL;

    req = tevent_req_create(mem_ctx, &state,
                            struct gethostbyname_files_state);
    if (req == NULL) {
        tevent_req_error(req, ENOMEM);
        goto done;
    }

    state->resolv_ctx = ctx;
    state->name = name;
    state->rhostent = NULL;
    state->family = family;

    DEBUG(4, ("Trying to resolve %s record of '%s' in files\n",
              state->family == AF_INET ? "A" : "AAAA", state->name));

    state->status = ares_gethostbyname_file(state->resolv_ctx->channel,
                                            state->name, state->family,
                                            &hostent);

    if (state->status == ARES_SUCCESS) {
        state->rhostent = resolv_copy_hostent(state, hostent);
        if (state->rhostent == NULL) {
            tevent_req_error(req, ENOMEM);
            goto done;
        }
    } else if (state->status == ARES_ENOTFOUND ||
               state->status == ARES_ENODATA) {
        /* Just say we didn't find anything and let the caller decide
         * about retrying */
        tevent_req_error(req, ENOENT);
        goto done;
    } else {
        tevent_req_error(req, return_code(state->status));
        goto done;
    }

    tevent_req_done(req);
done:
    if (hostent) ares_free_hostent(hostent);
    tevent_req_post(req, ev);
    return req;
}

static errno_t
resolv_gethostbyname_files_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                                int *status, struct resolv_hostent **rhostent)
{
    struct gethostbyname_files_state *state = tevent_req_data(req,
                                        struct gethostbyname_files_state);

    /* Fill in even in case of error as status contains the
     * c-ares return code */
    if (status) {
        *status = state->status;
    }
    if (rhostent) {
        *rhostent = talloc_steal(mem_ctx, state->rhostent);
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==================== Resolve host name in DNS =========================*/
struct gethostbyname_dns_state {
    struct resolv_ctx *resolv_ctx;
    struct tevent_context *ev;

    /* Part of the query. */
    const char *name;
    int family;

    /* query result */
    struct resolv_hostent *rhostent;

    /* These are returned by ares. */
    int status;
    int timeouts;
    int retrying;
};

static void
resolv_gethostbyname_dns_wakeup(struct tevent_req *subreq);
static void
resolv_gethostbyname_dns_query(struct tevent_req *req,
                               struct gethostbyname_dns_state *state);
static void
resolv_gethostbyname_dns_query_done(void *arg, int status, int timeouts,
                                    unsigned char *abuf, int alen);
static int
resolv_gethostbyname_dns_parse(struct gethostbyname_dns_state *state, int status,
                               int timeouts, unsigned char *abuf, int alen);

static struct tevent_req *
resolv_gethostbyname_dns_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                              struct resolv_ctx *ctx, const char *name,
                              int family)
{
    struct tevent_req *req, *subreq;
    struct gethostbyname_dns_state *state;
    struct timeval tv = { 0, 0 };

    if (ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct gethostbyname_dns_state);
    if (req == NULL) {
        return NULL;
    }

    state->resolv_ctx = ctx;
    state->ev = ev;
    state->name = name;
    state->rhostent = NULL;
    state->status = 0;
    state->timeouts = 0;
    state->retrying = 0;
    state->family = family;

    /* We need to have a wrapper around ares async calls, because
     * they can in some cases call it's callback immediately.
     * This would not let our caller to set a callback for req. */
    subreq = tevent_wakeup_send(req, ev, tv);
    if (subreq == NULL) {
        DEBUG(1, ("Failed to add critical timer to run next operation!\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, resolv_gethostbyname_dns_wakeup, req);

    return req;
}

static void
resolv_gethostbyname_dns_wakeup(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct gethostbyname_dns_state *state = tevent_req_data(req,
                                        struct gethostbyname_dns_state);

    if (!tevent_wakeup_recv(subreq)) {
        tevent_req_error(req, EIO);
        return;
    }
    talloc_zfree(subreq);

    if (state->resolv_ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        tevent_req_error(req, EIO);
        return;
    }

    resolv_gethostbyname_dns_query(req, state);
}

static void
resolv_gethostbyname_dns_query(struct tevent_req *req,
                               struct gethostbyname_dns_state *state)
{
    struct resolv_request *rreq;

    DEBUG(4, ("Trying to resolve %s record of '%s' in DNS\n",
              state->family == AF_INET ? "A" : "AAAA", state->name));

    rreq = schedule_timeout_watcher(state->ev, state->resolv_ctx, req);
    if (!rreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ares_search(state->resolv_ctx->channel,
                state->name, ns_c_in,
                (state->family == AF_INET) ? ns_t_a : ns_t_aaaa,
                resolv_gethostbyname_dns_query_done, rreq);
}

static void
resolv_gethostbyname_dns_query_done(void *arg, int status, int timeouts,
                                    unsigned char *abuf, int alen)
{
    errno_t ret;
    struct gethostbyname_dns_state *state;
    struct resolv_request *rreq = talloc_get_type(arg, struct resolv_request);
    struct tevent_req *req;


    if (rreq->rwatch == NULL) {
        /* The tevent request was cancelled while the ares call was still in
         * progress so nobody cares about the result now. Quit. */
        unschedule_timeout_watcher(rreq->ctx, rreq);
        return;
    }

    req = rreq->rwatch->req;
    unschedule_timeout_watcher(rreq->ctx, rreq);

    state = tevent_req_data(req, struct gethostbyname_dns_state);

    state->status = status;
    state->timeouts = timeouts;

    /* If resolv.conf changed during processing of a request we might
     * destroy the old channel before the request has a chance to finish.
     * We must resend the request in this case */
    if (state->retrying == 0 && status == ARES_EDESTRUCTION
        && state->resolv_ctx->channel != NULL) {
        state->retrying = 1;
        resolv_gethostbyname_dns_query(req, state);
        return;
    }

    if (status == ARES_ENOTFOUND || status == ARES_ENODATA) {
        /* Just say we didn't find anything and let the caller decide
         * about retrying */
        tevent_req_error(req, ENOENT);
        return;
    }

    if (status != ARES_SUCCESS) {
        /* Any other error indicates a server error,
         * so don't bother trying again
         */
        tevent_req_error(req, return_code(status));
        return;
    }

    ret = resolv_gethostbyname_dns_parse(state, status, timeouts, abuf, alen);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int
resolv_gethostbyname_dns_parse(struct gethostbyname_dns_state *state,
                               int status, int timeouts,
                               unsigned char *abuf, int alen)
{
    TALLOC_CTX *tmp_ctx;
    struct hostent *hostent;
    int naddrttls;
    errno_t ret;
    void *addr;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    naddrttls = DNS_HEADER_ANCOUNT(abuf);

    switch (state->family) {
        case AF_INET:
            DEBUG(7, ("Parsing an A reply\n"));

            addr = talloc_array(state, struct ares_addrttl, naddrttls);
            if (!addr) {
                ret = ENOMEM;
                goto fail;
            }

            status = ares_parse_a_reply(abuf, alen, &hostent,
                                        (struct ares_addrttl *) addr,
                                        &naddrttls);
            break;
        case AF_INET6:
            DEBUG(7, ("Parsing an AAAA reply\n"));

            addr = talloc_array(state, struct ares_addr6ttl, naddrttls);
            if (!addr) {
                ret = ENOMEM;
                goto fail;
            }

            status = ares_parse_aaaa_reply(abuf, alen, &hostent,
                                           (struct ares_addr6ttl *) addr,
                                           &naddrttls);
            break;
        default:
            DEBUG(1, ("Unknown family %d\n", state->family));
            ret = EAFNOSUPPORT;
            goto fail;
    }

    if (hostent != NULL) {
        state->rhostent = resolv_copy_hostent_ares(state, hostent,
                                                   state->family,
                                                   addr, naddrttls);
        ares_free_hostent(hostent);
        if (state->rhostent == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    talloc_free(tmp_ctx);
    return return_code(status);

fail:
    talloc_free(tmp_ctx);
    return ret;
}

static int
resolv_gethostbyname_dns_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                              int *status, int *timeouts,
                              struct resolv_hostent **rhostent)
{
    struct gethostbyname_dns_state *state = tevent_req_data(req,
                                        struct gethostbyname_dns_state);

    /* Fill in even in case of error as status contains the
     * c-ares return code */
    if (status) {
        *status = state->status;
    }
    if (timeouts) {
        *timeouts = state->timeouts;
    }
    if (rhostent) {
        *rhostent = talloc_steal(mem_ctx, state->rhostent);
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/*******************************************************************
 * Get host by name.                                               *
 *******************************************************************/

struct gethostbyname_state {
    struct resolv_ctx *resolv_ctx;
    struct tevent_context *ev;

    /* Part of the query. */
    const char *name;
    int family;

    /* In which order to use IPv4, or v6 */
    enum restrict_family family_order;

    /* Known hosts databases and index to the current one */
    enum host_database *db;
    int dbi;

    /* These are returned by ares. The hostent struct will be freed
     * when the user callback returns. */
    struct resolv_hostent *rhostent;
    int status;
    int timeouts;
    int retrying;
};

static errno_t
resolv_gethostbyname_address(TALLOC_CTX *mem_ctx, const char *address,
                             struct resolv_hostent **_rhostent);
static inline int
resolv_gethostbyname_family_init(enum restrict_family family_order);
static bool
resolv_is_address(const char *name);
static errno_t
resolv_gethostbyname_step(struct tevent_req *req);

struct tevent_req *
resolv_gethostbyname_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                          struct resolv_ctx *ctx, const char *name,
                          enum restrict_family family_order,
                          enum host_database *db)
{
    struct tevent_req *req;
    struct gethostbyname_state *state;
    errno_t ret;

    if (ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct gethostbyname_state);
    if (req == NULL) {
        return NULL;
    }

    state->resolv_ctx = ctx;
    state->ev = ev;
    state->name = name;
    state->rhostent = NULL;
    state->status = 0;
    state->timeouts = 0;
    state->retrying = 0;
    state->family_order = family_order;
    state->family = resolv_gethostbyname_family_init(state->family_order);
    state->db = db;
    state->dbi = 0;

    /* Do not attempt to resolve IP addresses */
    if (resolv_is_address(state->name)) {
        ret = resolv_gethostbyname_address(state, state->name,
                                           &state->rhostent);
        if (ret != EOK) {
            DEBUG(1, ("Canot create a fake hostent structure\n"));
            talloc_zfree(req);
            return NULL;
        }

        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    ret = resolv_gethostbyname_step(req);
    if (ret != EOK) {
        DEBUG(1, ("Cannot start the resolving\n"));
        talloc_zfree(req);
        return NULL;
    }

    return req;
}

static bool
resolv_is_address(const char *name)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int ret;

    memset((void *) &hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST; /* No network lookups */

    ret = getaddrinfo(name, NULL, &hints, &res);
    freeaddrinfo(res);
    if (ret != 0) {
        if (ret == -2) {
            DEBUG(9, ("[%s] does not look like an IP address\n", name));
        } else {
            DEBUG(2, ("getaddrinfo failed [%d]: %s\n",
                      ret, gai_strerror(ret)));
        }
    }

    return ret == 0;
}

static errno_t
resolv_gethostbyname_address(TALLOC_CTX *mem_ctx, const char *address,
                             struct resolv_hostent **_rhostent)
{
    struct resolv_hostent *rhostent;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    int family;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    rhostent = talloc_zero(tmp_ctx, struct resolv_hostent);
    if (!rhostent) {
        ret = ENOMEM;
        goto done;
    }

    rhostent->name = talloc_strdup(rhostent, address);
    rhostent->addr_list = talloc_array(rhostent, struct resolv_addr *, 2);

    if (!rhostent->name ||
        !rhostent->addr_list) {
        ret = ENOMEM;
        goto done;
    }

    rhostent->addr_list[0] = talloc_zero(rhostent->addr_list,
                                         struct resolv_addr);
    if (!rhostent->addr_list[0]) {
        ret = ENOMEM;
        goto done;
    }
    rhostent->addr_list[0]->ipaddr = talloc_array(rhostent->addr_list[0],
                                                  uint8_t,
                                                  sizeof(struct in6_addr));
    if (!rhostent->addr_list[0]->ipaddr) {
        ret = ENOMEM;
        goto done;
    }

    family = AF_INET;
    ret = inet_pton(family, address,
                    rhostent->addr_list[0]->ipaddr);
    if (ret != 1) {
        family = AF_INET6;
        ret = inet_pton(family, address,
                        rhostent->addr_list[0]->ipaddr);
        if (ret != 1) {
            DEBUG(1, ("Could not parse address as neither v4 nor v6\n"));
            ret = EINVAL;
            goto done;
        }
    }

    rhostent->addr_list[0]->ttl = RESOLV_DEFAULT_TTL;
    rhostent->addr_list[1] = NULL;
    rhostent->family = family;
    rhostent->aliases = NULL;

    *_rhostent = talloc_move(mem_ctx, &rhostent);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static inline int
resolv_gethostbyname_family_init(enum restrict_family family_order)
{
    switch(family_order) {
        case IPV4_ONLY:
        case IPV4_FIRST:
            return AF_INET;
        case IPV6_ONLY:
        case IPV6_FIRST:
            return AF_INET6;
    }

    DEBUG(1, ("Unknown address family order %d\n", family_order));
    return -1;
}

static int
resolv_gethostbyname_next(struct gethostbyname_state *state)
{
    if (state->family_order == IPV4_FIRST &&
        state->family == AF_INET) {
        state->family = AF_INET6;
        return EOK;
    } else if (state->family_order == IPV6_FIRST &&
               state->family == AF_INET6) {
        state->family = AF_INET;
        return EOK;
    } else {
        /* No more address families for this DB, check if
         * there is another DB to try */
        DEBUG(5, ("No more address families to retry\n"));
        state->dbi++;
        if (state->db[state->dbi] != DB_SENTINEL) {
            state->family = resolv_gethostbyname_family_init(
                                                state->family_order);
            return EOK;
        }
    }

    DEBUG(4, ("No more hosts databases to retry\n"));
    return ENOENT;
}

static void
resolv_gethostbyname_done(struct tevent_req *subreq);

static errno_t
resolv_gethostbyname_step(struct tevent_req *req)
{
    struct gethostbyname_state *state = tevent_req_data(req,
                                                struct gethostbyname_state);
    struct tevent_req *subreq;

    switch(state->db[state->dbi]) {
        case DB_FILES:
            DEBUG(8, ("Querying files\n"));
            subreq = resolv_gethostbyname_files_send(state, state->ev,
                                                     state->resolv_ctx,
                                                     state->name,
                                                     state->family);
            break;
        case DB_DNS:
            DEBUG(8, ("Querying DNS\n"));
            subreq = resolv_gethostbyname_dns_send(state, state->ev,
                                                   state->resolv_ctx,
                                                   state->name,
                                                   state->family);
            break;
        default:
            DEBUG(1, ("Invalid hosts database\n"));
            return EINVAL;
    }

    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, resolv_gethostbyname_done, req);
    return EOK;
}

static void
resolv_gethostbyname_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct gethostbyname_state *state = tevent_req_data(req,
                                                struct gethostbyname_state);
    errno_t ret;

    switch(state->db[state->dbi]) {
        case DB_FILES:
            ret = resolv_gethostbyname_files_recv(subreq, state,
                                                  &state->status,
                                                  &state->rhostent);
            /* files is synchronous, there can be no timeouts */
            state->timeouts = 0;
            break;
        case DB_DNS:
            ret = resolv_gethostbyname_dns_recv(subreq, state,
                                                &state->status, &state->timeouts,
                                                &state->rhostent);
            break;
        default:
            DEBUG(1, ("Invalid hosts database\n"));
            tevent_req_error(req, EINVAL);
            return;
    }

    talloc_zfree(subreq);

    if (ret == ENOENT) {
        ret = resolv_gethostbyname_next(state);
        if (ret == EOK) {
            ret = resolv_gethostbyname_step(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }

        /* No more databases and/or address families */
        tevent_req_error(req, ENOENT);
        return;
    } else if (ret == ETIMEDOUT) {
        /* In case we killed the request before c-ares answered */
        state->status = ARES_ETIMEOUT;
    }

    if (ret != EOK) {
        DEBUG(2, ("querying hosts database failed [%d]: %s\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int
resolv_gethostbyname_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                          int *status, int *timeouts,
                          struct resolv_hostent **rhostent)
{
    struct gethostbyname_state *state = tevent_req_data(req, struct gethostbyname_state);

    /* Fill in even in case of error as status contains the
     * c-ares return code */
    if (status) {
        *status = state->status;
    }
    if (timeouts) {
        *timeouts = state->timeouts;
    }
    if (rhostent) {
        *rhostent = talloc_steal(mem_ctx, state->rhostent);
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

char *
resolv_get_string_address_index(TALLOC_CTX *mem_ctx,
                                struct resolv_hostent *hostent,
                                unsigned int addrindex)
{
    char *address;

    if (!hostent) return NULL;

    address = talloc_zero_size(mem_ctx, 128);
    if (address == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return NULL;
    }

    errno = 0;
    if (inet_ntop(hostent->family, hostent->addr_list[addrindex]->ipaddr,
                  address, 128) == NULL) {
        DEBUG(1, ("inet_ntop failed [%d][%s].\n", errno, strerror(errno)));
        talloc_free(address);
        return NULL;
    }

    return address;
}

struct sockaddr_storage *
resolv_get_sockaddr_address(TALLOC_CTX *mem_ctx, struct resolv_hostent *hostent,
                            int port)
{
    struct sockaddr_storage *sockaddr;

    if (!hostent) return NULL;

    sockaddr = talloc_zero(mem_ctx, struct sockaddr_storage);
    if (sockaddr == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return NULL;
    }

    switch(hostent->family) {
        case AF_INET:
            sockaddr->ss_family = AF_INET;
            memcpy(&((struct sockaddr_in *) sockaddr)->sin_addr,
                   hostent->addr_list[0]->ipaddr, sizeof(struct in_addr));
            ((struct sockaddr_in *) sockaddr)->sin_port = (in_port_t) htons(port);

            break;
        case AF_INET6:
            sockaddr->ss_family = AF_INET6;
            memcpy(&((struct sockaddr_in6 *) sockaddr)->sin6_addr,
                   hostent->addr_list[0]->ipaddr, sizeof(struct in6_addr));
            ((struct sockaddr_in6 *) sockaddr)->sin6_port = (in_port_t) htons(port);
            break;
        default:
            DEBUG(1, ("Unknown address family %d\n"));
            return NULL;
    }

    return sockaddr;
}

/*
 * A simple helper function that will take an array of struct ares_srv_reply that
 * was allocated by malloc() in c-ares and copies it using talloc. The old one
 * is freed and the talloc one is put into 'reply_list' instead.
 */
static int
rewrite_talloc_srv_reply(TALLOC_CTX *mem_ctx, struct ares_srv_reply **reply_list)
{
    struct ares_srv_reply *ptr = NULL;
    struct ares_srv_reply *new_list = NULL;
    struct ares_srv_reply *old_list = *reply_list;

    /* Nothing to do, but not an error */
    if (!old_list) {
        return EOK;
    }

    /* Copy the linked list */
    while (old_list) {
        /* Special case for the first node */
        if (!new_list) {
            new_list = talloc_zero(mem_ctx, struct ares_srv_reply);
            if (new_list == NULL) {
                ares_free_data(*reply_list);
                return ENOMEM;
            }
            ptr = new_list;
        } else {
            ptr->next = talloc_zero(new_list, struct ares_srv_reply);
            if (ptr->next == NULL) {
                ares_free_data(*reply_list);
                talloc_free(new_list);
                return ENOMEM;
            }
            ptr = ptr->next;
        }

        ptr->weight = old_list->weight;
        ptr->priority = old_list->priority;
        ptr->port = old_list->port;
        ptr->host = talloc_strdup(ptr, old_list->host);
        if (ptr->host == NULL) {
            ares_free_data(*reply_list);
            talloc_free(new_list);
            return ENOMEM;
        }

        old_list = old_list->next;
    }

    /* Free the old one (uses malloc). */
    ares_free_data(*reply_list);

    /* And now put our own new_list in place. */
    *reply_list = new_list;

    return EOK;
}

/*******************************************************************
 * Get SRV record                                                  *
 *******************************************************************/

struct getsrv_state {
    struct tevent_context *ev;
    struct resolv_ctx *resolv_ctx;
    /* the SRV query - for example _ldap._tcp.example.com */
    const char *query;

    /* parsed data returned by ares */
    struct ares_srv_reply *reply_list;
    int status;
    int timeouts;
    int retrying;
};

static void
ares_getsrv_wakeup(struct tevent_req *subreq);
static void
resolv_getsrv_query(struct tevent_req *req,
                    struct getsrv_state *state);

struct tevent_req *
resolv_getsrv_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                   struct resolv_ctx *ctx, const char *query)
{
    struct tevent_req *req, *subreq;
    struct getsrv_state *state;
    struct timeval tv = { 0, 0 };

    DEBUG(4, ("Trying to resolve SRV record of '%s'\n", query));

    if (ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct getsrv_state);
    if (req == NULL)
        return NULL;

    state->resolv_ctx = ctx;
    state->query = query;
    state->reply_list = NULL;
    state->status = 0;
    state->timeouts = 0;
    state->retrying = 0;
    state->ev = ev;

    subreq = tevent_wakeup_send(req, ev, tv);
    if (subreq == NULL) {
        DEBUG(1, ("Failed to add critical timer to run next operation!\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, ares_getsrv_wakeup, req);

    return req;
}

static void
resolv_getsrv_done(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{
    struct resolv_request *rreq = talloc_get_type(arg, struct resolv_request);
    struct tevent_req *req;
    struct getsrv_state *state;
    int ret;
    struct ares_srv_reply *reply_list;

    if (rreq->rwatch == NULL) {
        /* The tevent request was cancelled while the ares call was still in
         * progress so nobody cares about the result now. Quit. */
        unschedule_timeout_watcher(rreq->ctx, rreq);
        return;
    }

    req = rreq->rwatch->req;
    unschedule_timeout_watcher(rreq->ctx, rreq);
    state = tevent_req_data(req, struct getsrv_state);

    if (state->retrying == 0 && status == ARES_EDESTRUCTION
        && state->resolv_ctx->channel != NULL) {
        state->retrying = 1;
        resolv_getsrv_query(req, state);
        return;
    }

    state->status = status;
    state->timeouts = timeouts;

    if (status != ARES_SUCCESS) {
        ret = return_code(status);
        goto fail;
    }

    ret = ares_parse_srv_reply(abuf, alen, &reply_list);
    if (status != ARES_SUCCESS) {
        DEBUG(2, ("SRV record parsing failed: %d: %s\n", ret, ares_strerror(ret)));
        ret = return_code(ret);
        goto fail;
    }
    ret = rewrite_talloc_srv_reply(req, &reply_list);
    if (ret != EOK) {
        goto fail;
    }
    state->reply_list = reply_list;

    tevent_req_done(req);
    return;

fail:
    state->reply_list = NULL;
    tevent_req_error(req, ret);
}

int
resolv_getsrv_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req, int *status,
                   int *timeouts, struct ares_srv_reply **reply_list)
{
    struct getsrv_state *state = tevent_req_data(req, struct getsrv_state);

    if (status)
        *status = state->status;
    if (timeouts)
        *timeouts = state->timeouts;
    if (reply_list)
        *reply_list = talloc_steal(mem_ctx, state->reply_list);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void
ares_getsrv_wakeup(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct getsrv_state *state = tevent_req_data(req,
                                                struct getsrv_state);

    if (!tevent_wakeup_recv(subreq)) {
        return;
    }
    talloc_zfree(subreq);

    if (state->resolv_ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        tevent_req_error(req, EIO);
        return;
    }

    return resolv_getsrv_query(req, state);
}

static void
resolv_getsrv_query(struct tevent_req *req,
                    struct getsrv_state *state)
{
    struct resolv_request *rreq;

    rreq = schedule_timeout_watcher(state->ev, state->resolv_ctx, req);
    if (!rreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ares_query(state->resolv_ctx->channel, state->query,
               ns_c_in, ns_t_srv, resolv_getsrv_done, rreq);
}

/* TXT parsing is not used anywhere in the code yet, so we disable it
 * for now
 */
#ifdef BUILD_TXT

/*
 * A simple helper function that will take an array of struct txt_reply that
 * was allocated by malloc() in c-ares and copies it using talloc. The old one
 * is freed and the talloc one is put into 'reply_list' instead.
 */
static int
rewrite_talloc_txt_reply(TALLOC_CTX *mem_ctx, struct ares_txt_reply **reply_list)
{
    struct ares_txt_reply *ptr = NULL;
    struct ares_txt_reply *new_list = NULL;
    struct ares_txt_reply *old_list = *reply_list;

    /* Nothing to do, but not an error */
    if (!old_list) {
        return EOK;
    }

    /* Copy the linked list */
    while (old_list) {

        /* Special case for the first node */
        if (!new_list) {
            new_list = talloc_zero(mem_ctx, struct ares_txt_reply);
            if (new_list == NULL) {
                ares_free_data(*reply_list);
                talloc_free(new_list);
                return ENOMEM;
            }
            ptr = new_list;
        } else {
            ptr->next = talloc_zero(new_list, struct ares_txt_reply);
            if (ptr->next == NULL) {
                ares_free_data(*reply_list);
                talloc_free(new_list);
                return ENOMEM;
            }
            ptr = ptr->next;
        }

        ptr->length = old_list->length;
        ptr->txt = talloc_memdup(ptr, old_list->txt,
                                 old_list->length);
        if (ptr->txt == NULL) {
            ares_free_data(*reply_list);
            talloc_free(new_list);
            return ENOMEM;
        }

        old_list = old_list->next;
    }

    ares_free_data(*reply_list);

    /* And now put our own new_list in place. */
    *reply_list = new_list;

    return EOK;
}

/*******************************************************************
 * Get TXT record                                                  *
 *******************************************************************/

struct gettxt_state {
    struct tevent_context *ev;
    struct resolv_ctx *resolv_ctx;
    /* the TXT query */
    const char *query;

    /* parsed data returned by ares */
    struct ares_txt_reply *reply_list;
    int status;
    int timeouts;
    int retrying;
};

static void
ares_gettxt_wakeup(struct tevent_req *subreq);
static void
resolv_gettxt_query(struct tevent_req *req,
                    struct gettxt_state *state);

struct tevent_req *
resolv_gettxt_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                          struct resolv_ctx *ctx, const char *query)
{
    struct tevent_req *req, *subreq;
    struct gettxt_state *state;
    struct timeval tv = { 0, 0 };

    DEBUG(4, ("Trying to resolve TXT record of '%s'\n", query));

    if (ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct gettxt_state);
    if (req == NULL)
        return NULL;

    state->resolv_ctx = ctx;
    state->query = query;
    state->reply_list = NULL;
    state->status = 0;
    state->timeouts = 0;
    state->retrying = 0;
    state->ev = ev;

    subreq = tevent_wakeup_send(req, ev, tv);
    if (subreq == NULL) {
        DEBUG(1, ("Failed to add critical timer to run next operation!\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, ares_gettxt_wakeup, req);

    return req;
}

static void
resolv_gettxt_done(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{
    struct resolv_request *rreq = talloc_get_type(arg, struct resolv_request);
    struct tevent_req *req;
    struct gettxt_state *state;
    int ret;
    struct ares_txt_reply *reply_list;

    if (rreq->rwatch == NULL) {
        /* The tevent request was cancelled while the ares call was still in
         * progress so nobody cares about the result now. Quit. */
        unschedule_timeout_watcher(rreq->ctx, rreq);
        return;
    }

    req = rreq->rwatch->req;
    unschedule_timeout_watcher(rreq->ctx, rreq);
    state = tevent_req_data(req, struct gettxt_state);

    if (state->retrying == 0 && status == ARES_EDESTRUCTION
            && state->resolv_ctx->channel != NULL) {
        state->retrying = 1;
        ares_query(state->resolv_ctx->channel, state->query,
                   ns_c_in, ns_t_txt, resolv_gettxt_done, req);
        return;
    }

    state->status = status;
    state->timeouts = timeouts;

    if (status != ARES_SUCCESS) {
        ret = return_code(status);
        goto fail;
    }

    ret = ares_parse_txt_reply(abuf, alen, &reply_list);
    if (status != ARES_SUCCESS) {
        DEBUG(2, ("TXT record parsing failed: %d: %s\n", ret, ares_strerror(ret)));
        ret = return_code(ret);
        goto fail;
    }
    ret = rewrite_talloc_txt_reply(req, &reply_list);
    if (ret != EOK) {
        goto fail;
    }
    state->reply_list = reply_list;

    tevent_req_done(req);
    return;

fail:
    state->reply_list = NULL;
    tevent_req_error(req, ret);
}

int
resolv_gettxt_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req, int *status,
                   int *timeouts, struct ares_txt_reply **reply_list)
{
    struct gettxt_state *state = tevent_req_data(req, struct gettxt_state);

    if (status)
        *status = state->status;
    if (timeouts)
        *timeouts = state->timeouts;
    if (reply_list)
        *reply_list = talloc_steal(mem_ctx, state->reply_list);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void
ares_gettxt_wakeup(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                            struct tevent_req);
    struct gettxt_state *state = tevent_req_data(req,
                                            struct gettxt_state);

    if (!tevent_wakeup_recv(subreq)) {
        return;
    }
    talloc_zfree(subreq);

    if (state->resolv_ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        tevent_req_error(req, EIO);
        return;
    }

    return resolv_gettxt_query(req, state);
}

static void
resolv_gettxt_query(struct tevent_req *req,
                    struct gettxt_state *state)
{
    struct resolv_request *rreq;

    rreq = schedule_timeout_watcher(state->ev, state->resolv_ctx, req);
    if (!rreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ares_query(state->resolv_ctx->channel, state->query,
               ns_c_in, ns_t_txt, resolv_gettxt_done, rreq);
}

#endif

static struct ares_srv_reply *split_reply_list(struct ares_srv_reply *list)
{
    struct ares_srv_reply *single_step, *double_step, *prev;

    if (!list) {
        return NULL;
    }

    prev        = list;
    single_step = list->next;
    double_step = single_step->next;

    while (double_step && double_step->next) {
        prev = single_step;
        single_step = single_step->next;
        double_step = double_step->next->next;
    }

    prev->next = NULL;
    return single_step;
}

static struct ares_srv_reply *merge_reply_list(struct ares_srv_reply *left,
                                               struct ares_srv_reply *right)
{
    struct ares_srv_reply *l, *r;
    struct ares_srv_reply *res, *res_start;

    if (!left)
        return right;
    if (!right)
        return left;

    if (left->priority < right->priority) {
        res_start = left;
        l = left->next;
        r = right;
    } else {
        res_start = right;
        l = left;
        r = right->next;
    }

    res = res_start;

    while(l && r) {
        if (l->priority < r->priority) {
            res->next = l;
            res = l;
            l = l->next;
        } else {
            res->next = r;
            res = r;
            r = r->next;
        }
    }

    res->next = l ? l : r;

    return res_start;
}

/**
 * sort linked list of struct ares_srv_reply by priority using merge sort.
 *
 * Merge sort is ideal for sorting linked lists as there is no problem
 * with absence of random access into the list. The complexity is O(n log n)
 *
 * For reference, see Robert Sedgewick's "Algorithms in C", Addison-Wesley,
 * ISBN 0-201-51425
 */
static struct ares_srv_reply *reply_priority_sort(struct ares_srv_reply *list)
{
    struct ares_srv_reply *half;

    if (!list || !list->next)
        return list;

    half = split_reply_list(list);
    list = merge_reply_list(reply_priority_sort(list),
                            reply_priority_sort(half));

    return list;
}

static int reply_weight_rearrange(TALLOC_CTX *mem_ctx,
                                  int len,
                                  struct ares_srv_reply **start,
                                  struct ares_srv_reply **end)
{
    int i;
    int total, selected;
    int *totals;
    struct ares_srv_reply *r, *prev, *tmp;
    struct ares_srv_reply *new_start = NULL;
    struct ares_srv_reply *new_end = NULL;

    if (len <= 1) {
        return EOK;
    }

    totals = talloc_array(mem_ctx, int, len);
    if (!totals) {
        return ENOMEM;
    }

    srand(time(NULL) * getpid());

    /* promote all servers with weight==0 to the top */
    r = *(start);
    prev = NULL;
    while (r != NULL) {
        if (r->weight == 0) {
            /* remove from the old list */
            if (prev) {
                prev->next = r->next;
            } else {
                *start = r->next;
            }

            /* add to the head of the new list */
            tmp = r;
            r = r->next;

            tmp->next = *start;
            *start = tmp;
        } else {
            prev = r;
            r = r->next;
        }
    }
    *end = prev ? prev : *start;

    while (*start != NULL) {
        /* Commpute the sum of the weights of those RRs, and with each RR
         * associate the running sum in the selected order.
         */
        total = 0;
        memset(totals, -1, sizeof(int) * len);
        for (i = 0, r = *start; r != NULL; r=r->next, ++i) {
            totals[i] = r->weight + total;
            total = totals[i];
        }

        /* choose a  uniform random number between 0 and the sum computed
         * (inclusive), and select the RR whose running sum value is the
         * first in the selected order which is greater than or equal to
         * the random number selected.
         */
        selected = (int)((total + 1) * (rand()/(RAND_MAX + 1.0)));
        for (i = 0, r = *start, prev = NULL; r != NULL; r=r->next, ++i) {
            if (totals[i] >= selected)
                break;

            prev = r;
        }

        if (r == NULL || totals[i] == -1) {
            DEBUG(1, ("Bug: did not select any server!\n"));
            return EIO;
        }

        /* remove r from the old list */
        if (prev) {
            prev->next = r->next;
        } else {
            *start = r->next;
        }

        /* add r to the end of the new list */
        if (!new_start) {
            new_start = r;
            new_end = r;
        } else {
            new_end->next = r;
            new_end = r;
        }
    }
    new_end->next = NULL;

    /* return the rearranged list */
    *start = new_start;
    *end = new_end;
    talloc_free(totals);
    return EOK;
}

int
resolv_sort_srv_reply(TALLOC_CTX *mem_ctx, struct ares_srv_reply **reply)
{
    int ret;
    struct ares_srv_reply *pri_start, *pri_end, *next, *prev_end;
    int len;

    /* RFC 2782 says: If there is precisely one SRV RR, and its Target is "."
     * (the root domain), abort.
     */
    if (*reply && !(*reply)->next && strcmp((*reply)->host, ".") == 0) {
        DEBUG(1, ("DNS returned only the root domain, aborting\n"));
        return EIO;
    }

    /* sort the list by priority */
    *reply = reply_priority_sort(*reply);

    pri_start = *reply;
    prev_end  = NULL;

    while (pri_start) {
        pri_end = pri_start;

        /* Find nodes with the same priority */
        len = 1;
        while (pri_end->next && pri_end->priority == pri_end->next->priority) {
            pri_end = pri_end->next;
            len++;
        }

        /* rearrange each priority level according to the weight field */
        next = pri_end->next;
        pri_end->next = NULL;
        ret = reply_weight_rearrange(mem_ctx, len, &pri_start, &pri_end);
        if (ret) {
            DEBUG(1, ("Error rearranging priority level [%d]: %s\n",
                      ret, strerror(ret)));
            return ret;
        }

        /* Hook the level back into the list */
        if (prev_end) {
            prev_end->next = pri_start;
        } else {
            *reply = pri_start;
        }
        pri_end->next = next;

        /* Move on to the next level */
        prev_end  = pri_end;
        pri_start = next;
    }

    return EOK;
}
