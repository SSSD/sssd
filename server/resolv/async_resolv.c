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

#ifndef HAVE_ARES_PARSE_SRV
#define ares_parse_srv_reply(abuf, alen, srv_out, nsrvreply) \
    _ares_parse_srv_reply(abuf, alen, srv_out, nsrvreply)
#endif /* HAVE_ARES_PARSE_SRV */

#ifndef HAVE_ARES_PARSE_TXT
#define ares_parse_txt_reply(abuf, alen, txt_out, ntxtreply) \
    _ares_parse_txt_reply(abuf, alen, txt_out, ntxtreply)
#endif /* HAVE_ARES_PARSE_TXT */

struct fd_watch {
    struct fd_watch *prev;
    struct fd_watch *next;

    int fd;
    struct resolv_ctx *ctx;
};

struct resolv_ctx {
    struct tevent_context *ev_ctx;

    ares_channel channel;
    /* List of file descriptors that are watched by tevent. */
    struct fd_watch *fds;
};

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
    ares_process_fd(watch->ctx->channel, watch->fd, watch->fd);
}


static void fd_event_add(struct resolv_ctx *ctx, int s);
static void fd_event_write(struct resolv_ctx *ctx, int s);
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

    /* The socket is about to get closed. */
    if (fd_read == 0 && fd_write == 0) {
        fd_event_close(ctx, s);
        return;
    }

    /* If ares needs to write to a descriptor */
    if (fd_write == 1) {
        fd_event_write(ctx, s);
    }

    /* Are we already watching this file descriptor? */
    watch = ctx->fds;
    while (watch) {
        if (watch->fd == s) {
            return;
        }
        watch = watch->next;
    }

    fd_event_add(ctx, s);
}

static void
fd_event_add(struct resolv_ctx *ctx, int s)
{
    struct fd_watch *watch;
    struct tevent_fd *fde;

    /* The file descriptor is new, register it with tevent. */
    watch = talloc(ctx, struct fd_watch);
    if (watch == NULL) {
        DEBUG(1, ("Out of memory allocating fd_watch structure"));
        return;
    }
    talloc_set_destructor(watch, fd_watch_destructor);

    watch->fd = s;
    watch->ctx = ctx;

    fde = tevent_add_fd(ctx->ev_ctx, watch, s, TEVENT_FD_READ, fd_input_available, watch);
    if (fde == NULL) {
        DEBUG(1, ("tevent_add_fd() failed"));
        talloc_free(watch);
        return;
    }
    DLIST_ADD(ctx->fds, watch);
}

static void
fd_event_write(struct resolv_ctx *ctx, int s)
{
    if (ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        return;
    }
    /* do not allow any read. */
    ares_process_fd(ctx->channel, ARES_SOCKET_BAD, s);
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
    if (ctx->channel == NULL) {
        DEBUG(1, ("Ares channel already destroyed?\n"));
        return -1;
    }

    ares_destroy(ctx->channel);
    ctx->channel = NULL;

    return 0;
}

int
resolv_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev_ctx,
            struct resolv_ctx **ctxp)
{
    int ret;
    struct resolv_ctx *ctx;
    struct ares_options options;

    ctx = talloc_zero(mem_ctx, struct resolv_ctx);
    if (ctx == NULL)
        return ENOMEM;

    ctx->ev_ctx = ev_ctx;

    /* FIXME: the options would contain
     * the nameservers to contact, the domains
     * to search, timeout... => get from confdb
     */
    options.sock_state_cb = fd_event;
    options.sock_state_cb_data = ctx;
    ret = ares_init_options(&ctx->channel, &options, ARES_OPT_SOCK_STATE_CB);
    if (ret != ARES_SUCCESS) {
        DEBUG(1, ("Failed to initialize ares channel: %s",
                  resolv_strerror(ret)));
        ret = return_code(ret);
        goto done;
    }

    talloc_set_destructor(ctx, resolv_ctx_destructor);

    *ctxp = ctx;
    return EOK;

done:
    talloc_free(ctx);
    return ret;
}

struct hostent *
resolv_copy_hostent(TALLOC_CTX *mem_ctx, struct hostent *src)
{
    struct hostent *ret;
    int len;
    int i;

    ret = talloc_zero(mem_ctx, struct hostent);
    if (ret == NULL) {
        return NULL;
    }

    if (src->h_name != NULL) {
        ret->h_name = talloc_strdup(ret, src->h_name);
        if (ret->h_name == NULL) {
            goto fail;
        }
    }
    if (src->h_aliases != NULL) {
        for (len = 0; src->h_aliases[len] != NULL; len++);
        ret->h_aliases = talloc_size(ret, sizeof(char *) * (len + 1));
        if (ret->h_aliases == NULL) {
            goto fail;
        }
        for (i = 0; i < len; i++) {
            ret->h_aliases[i] = talloc_strdup(ret->h_aliases, src->h_aliases[i]);
            if (ret->h_aliases[i] == NULL) {
                goto fail;
            }
        }
        ret->h_aliases[len] = NULL;
    }
    ret->h_addrtype = src->h_addrtype;
    ret->h_length = src->h_length;
    if (src->h_addr_list != NULL) {
        for (len = 0; src->h_addr_list[len] != NULL; len++);
        ret->h_addr_list = talloc_size(ret, sizeof(char *) * (len + 1));
        if (ret->h_addr_list == NULL) {
            goto fail;
        }
        for (i = 0; i < len; i++) {
            ret->h_addr_list[i] = talloc_memdup(ret->h_addr_list,
                                                src->h_addr_list[i],
                                                ret->h_length);
            if (ret->h_addr_list[i] == NULL) {
                goto fail;
            }
        }
        ret->h_addr_list[len] = NULL;
    }

    return ret;

fail:
    talloc_free(ret);
    return NULL;
}

/*******************************************************************
 * Get host by name.                                               *
 *******************************************************************/

struct gethostbyname_state {
    struct resolv_ctx *resolv_ctx;
    /* Part of the query. */
    const char *name;
    int family;
    /* These are returned by ares. The hostent struct will be freed
     * when the user callback returns. */
    struct hostent *hostent;
    int status;
    int timeouts;
};

static void
ares_gethostbyname_wakeup(struct tevent_req *req);

struct tevent_req *
resolv_gethostbyname_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                          struct resolv_ctx *ctx, const char *name, int family)
{
    struct tevent_req *req, *subreq;
    struct gethostbyname_state *state;
    struct timeval tv = { 0, 0 };

    if (ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct gethostbyname_state);
    if (req == NULL)
        return NULL;

    state->resolv_ctx = ctx;
    state->name = name;
    state->family = family;
    state->hostent = NULL;
    state->status = 0;
    state->timeouts = 0;

    /* We need to have a wrapper around ares_gethostbyname(), because
     * ares_gethostbyname() can in some cases call it's callback immediately.
     * This would not let our caller to set a callback for req. */
    subreq = tevent_wakeup_send(req, ev, tv);
    if (subreq == NULL) {
        DEBUG(1, ("Failed to add critical timer to run next operation!\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, ares_gethostbyname_wakeup, req);

    return req;
}

static void
resolv_gethostbyname_done(void *arg, int status, int timeouts, struct hostent *hostent)
{
    struct tevent_req *req = talloc_get_type(arg, struct tevent_req);
    struct gethostbyname_state *state = tevent_req_data(req, struct gethostbyname_state);

    if (hostent != NULL) {
        state->hostent = resolv_copy_hostent(req, hostent);
        if (state->hostent == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
    } else {
        state->hostent = NULL;
    }
    state->status = status;
    state->timeouts = timeouts;

    if (status != ARES_SUCCESS)
        tevent_req_error(req, return_code(status));
    else
        tevent_req_done(req);
}

int
resolv_gethostbyname_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                          int *status, int *timeouts,
                          struct hostent **hostent)
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
    if (hostent) {
        *hostent = talloc_steal(mem_ctx, state->hostent);
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void
ares_gethostbyname_wakeup(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct gethostbyname_state *state = tevent_req_data(req,
                                                struct gethostbyname_state);

    if (!tevent_wakeup_recv(subreq)) {
        return;
    }
    talloc_zfree(subreq);

    if (state->resolv_ctx->channel == NULL) {
        DEBUG(1, ("Invalid ares channel - this is likely a bug\n"));
        tevent_req_error(req, EIO);
        return;
    }

    ares_gethostbyname(state->resolv_ctx->channel, state->name,
                       state->family, resolv_gethostbyname_done, req);
}

/*
 * A simple helper function that will take an array of struct srv_reply that
 * was allocated by malloc() in c-ares and copies it using talloc. The old one
 * is freed and the talloc one is put into 'reply_list' instead.
 */
static int
rewrite_talloc_srv_reply(TALLOC_CTX *mem_ctx, struct srv_reply **reply_list,
                         int num_replies)
{
    int i;
    struct srv_reply *new_list;
    struct srv_reply *old_list = *reply_list;

    new_list = talloc_array(mem_ctx, struct srv_reply, num_replies);
    if (new_list == NULL) {
        return ENOMEM;
    }

    /* Copy the new_list array. */
    for (i = 0; i < num_replies; i++) {
        new_list[i].weight = old_list[i].weight;
        new_list[i].priority = old_list[i].priority;
        new_list[i].port = old_list[i].port;
        new_list[i].host = talloc_strdup(new_list, old_list[i].host);
        if (new_list[i].host == NULL) {
            talloc_free(new_list);
            return ENOMEM;
        }
    }

    /* Free the old one (uses malloc). */
    for (i = 0; i < num_replies; i++) {
        free(old_list[i].host);
    }
    free(old_list);

    /* And now put our own new_list in place. */
    *reply_list = new_list;

    return EOK;
}

/*******************************************************************
 * Get SRV record                                                  *
 *******************************************************************/

struct getsrv_state {
    struct resolv_ctx *resolv_ctx;
    /* the SRV query - for example _ldap._tcp.example.com */
    const char *query;

    /* parsed data returned by ares */
    struct srv_reply *reply_list;
    int num_replies;
    int status;
    int timeouts;
};

static void
ares_getsrv_wakeup(struct tevent_req *subreq);

struct tevent_req *
resolv_getsrv_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                   struct resolv_ctx *ctx, const char *query)
{
    struct tevent_req *req, *subreq;
    struct getsrv_state *state;
    struct timeval tv = { 0, 0 };

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
    state->num_replies = 0;
    state->status = 0;
    state->timeouts = 0;

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
    struct tevent_req *req = talloc_get_type(arg, struct tevent_req);
    struct getsrv_state *state = tevent_req_data(req, struct getsrv_state);
    int ret;
    int num_replies;
    struct srv_reply *reply_list;

    state->status = status;
    state->timeouts = timeouts;

    if (status != ARES_SUCCESS) {
        tevent_req_error(req, return_code(status));
        ret = return_code(status);
        goto fail;
    }

    ret = ares_parse_srv_reply(abuf, alen, &reply_list, &num_replies);
    if (status != ARES_SUCCESS) {
        DEBUG(2, ("SRV record parsing failed: %d: %s\n", ret, ares_strerror(ret)));
        ret = return_code(ret);
        goto fail;
    }
    ret = rewrite_talloc_srv_reply(req, &reply_list, num_replies);
    if (ret != EOK) {
        goto fail;
    }
    state->reply_list = reply_list;
    state->num_replies = num_replies;

    tevent_req_done(req);
    return;

fail:
    state->reply_list = NULL;
    state->num_replies = 0;
    tevent_req_error(req, ret);
}

int
resolv_getsrv_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req, int *status,
                   int *timeouts, struct srv_reply **reply_list,
                   int *num_replies)
{
    struct getsrv_state *state = tevent_req_data(req, struct getsrv_state);

    if (status)
        *status = state->status;
    if (timeouts)
        *timeouts = state->timeouts;
    if (reply_list)
        *reply_list = talloc_steal(mem_ctx, state->reply_list);
    if (num_replies)
        *num_replies = state->num_replies;

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

    ares_query(state->resolv_ctx->channel, state->query,
               ns_c_in, ns_t_srv, resolv_getsrv_done, req);
}

/*
 * A simple helper function that will take an array of struct txt_reply that
 * was allocated by malloc() in c-ares and copies it using talloc. The old one
 * is freed and the talloc one is put into 'reply_list' instead.
 */
static int
rewrite_talloc_txt_reply(TALLOC_CTX *mem_ctx, struct txt_reply **reply_list,
                         int num_replies)
{
    int i;
    struct txt_reply *new_list;
    struct txt_reply *old_list = *reply_list;

    new_list = talloc_array(mem_ctx, struct txt_reply, num_replies);
    if (new_list == NULL) {
        return ENOMEM;
    }

    /* Copy the new_list array. */
    for (i = 0; i < num_replies; i++) {
        new_list[i].length = old_list[i].length;
        new_list[i].txt = talloc_memdup(new_list, old_list[i].txt,
                                        old_list[i].length);
        if (new_list[i].txt == NULL) {
            talloc_free(new_list);
            return ENOMEM;
        }
    }

    /* Free the old one (uses malloc). */
    for (i = 0; i < num_replies; i++) {
        free(old_list[i].txt);
    }
    free(old_list);

    /* And now put our own new_list in place. */
    *reply_list = new_list;

    return EOK;
}

/*******************************************************************
 * Get TXT record                                                  *
 *******************************************************************/

struct gettxt_state {
    struct resolv_ctx *resolv_ctx;
    /* the TXT query */
    const char *query;

    /* parsed data returned by ares */
    struct txt_reply *reply_list;
    int num_replies;
    int status;
    int timeouts;
};

static void
ares_gettxt_wakeup(struct tevent_req *subreq);

struct tevent_req *
resolv_gettxt_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                          struct resolv_ctx *ctx, const char *query)
{
    struct tevent_req *req, *subreq;
    struct gettxt_state *state;
    struct timeval tv = { 0, 0 };

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
    state->num_replies = 0;
    state->status = 0;
    state->timeouts = 0;


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
    struct tevent_req *req = talloc_get_type(arg, struct tevent_req);
    struct gettxt_state *state = tevent_req_data(req, struct gettxt_state);
    int ret;
    int num_replies;
    struct txt_reply *reply_list;

    state->status = status;
    state->timeouts = timeouts;

    if (status != ARES_SUCCESS) {
        ret = return_code(status);
        goto fail;
    }

    ret = ares_parse_txt_reply(abuf, alen, &reply_list, &num_replies);
    if (status != ARES_SUCCESS) {
        DEBUG(2, ("TXT record parsing failed: %d: %s\n", ret, ares_strerror(ret)));
        ret = return_code(ret);
        goto fail;
    }
    ret = rewrite_talloc_txt_reply(req, &reply_list, num_replies);
    if (ret != EOK) {
        goto fail;
    }
    state->reply_list = reply_list;
    state->num_replies = num_replies;

    tevent_req_done(req);
    return;

fail:
    state->reply_list = NULL;
    state->num_replies = 0;
    tevent_req_error(req, ret);
}

int
resolv_gettxt_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req, int *status,
                   int *timeouts, struct txt_reply **reply_list,
                   int *num_replies)
{
    struct gettxt_state *state = tevent_req_data(req, struct gettxt_state);

    if (status)
        *status = state->status;
    if (timeouts)
        *timeouts = state->timeouts;
    if (reply_list)
        *reply_list = talloc_steal(mem_ctx, state->reply_list);
    if (num_replies)
        *num_replies = state->num_replies;

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

    ares_query(state->resolv_ctx->channel, state->query,
               ns_c_in, ns_t_txt, resolv_gettxt_done, req);
}

