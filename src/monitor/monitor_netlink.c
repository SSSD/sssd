/*
   SSSD - Service monitor - netlink support

   Authors:
       Jakub Hrozek <jhrozek@redhat.com>
       Parts of this code were borrowed from NetworkManager

   Copyright (C) 2010 Red Hat

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

#include <talloc.h>
#include <tevent.h>
#include <sys/types.h>
#define __USE_GNU /* needed for struct ucred */
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include "monitor/monitor.h"
#include "util/util.h"

#ifdef HAVE_LIBNL
#include <linux/if.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/rtnl.h>
#include <netlink/handlers.h>
#endif

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifdef HAVE_LIBNL_OLDER_THAN_1_1
#define nlw_get_fd nl_handle_get_fd
#define nlw_recvmsgs_default nl_recvmsgs_def
#define nlw_get_pid nl_handle_get_pid
#define nlw_object_match nl_object_match
#define NLW_OK NL_PROCEED
#define OBJ_CAST(ptr)           ((struct nl_object *) (ptr))
#else
#define nlw_get_fd nl_socket_get_fd
#define nlw_recvmsgs_default nl_recvmsgs_default
#define nlw_get_pid nl_socket_get_local_port
#define nlw_object_match nl_object_match_filter
#define NLW_OK NL_OK
#endif

struct netlink_ctx {
#ifdef HAVE_LIBNL
    struct nl_handle *nlh;
#endif
    struct tevent_fd *tefd;

    network_change_cb change_cb;
    void *cb_data;
};

#ifdef HAVE_LIBNL
static int netlink_ctx_destructor(void *ptr)
{
    struct netlink_ctx *nlctx;
    nlctx = talloc_get_type(ptr, struct netlink_ctx);

    nl_handle_destroy(nlctx->nlh);
    return 0;
}

/*******************************************************************
 * Wrappers for different capabilities of different libnl versions
 *******************************************************************/

static bool nlw_accept_message(struct nl_handle *nlh,
                               const struct sockaddr_nl *snl,
                               struct nlmsghdr *hdr)
{
    bool accept_msg = false;
    uint32_t local_port;

    if (snl == NULL) {
        DEBUG(3, ("Malformed message, skipping\n"));
        return false;
    }

    /* Accept any messages from the kernel */
    if (hdr->nlmsg_pid == 0 || snl->nl_pid == 0) {
        accept_msg = true;
    }

    /* And any multicast message directed to our netlink PID, since multicast
     * currently requires CAP_ADMIN to use.
     */
    local_port = nlw_get_pid(nlh);
    if ((hdr->nlmsg_pid == local_port) && snl->nl_groups) {
        accept_msg = true;
    }

    if (accept_msg == false) {
        DEBUG(9, ("ignoring netlink message from PID %d",
                  hdr->nlmsg_pid));
    }

    return accept_msg;
}

static bool nlw_is_link_object(struct nl_object *obj)
{
    bool is_link_object = true;
    struct rtnl_link *filter;

    filter = rtnl_link_alloc();
    if (!filter) {
        DEBUG(0, ("Allocation error!\n"));
        is_link_object = false;
    }

    /* Ensure it's a link object */
    if (!nlw_object_match(obj, OBJ_CAST(filter))) {
        DEBUG(2, ("Not a link object\n"));
        is_link_object = false;
    }

    rtnl_link_put(filter);
    return is_link_object;
}

static int nlw_enable_passcred(struct nl_handle *nlh)
{
#ifndef HAVE_NL_SET_PASSCRED
    return EOK;                      /* not available in this version */
#else
    return nl_set_passcred(nlh, 1);  /* 1 = enabled */
#endif
}

static int nlw_group_subscribe(struct nl_handle *nlh)
{
    int ret;

#ifdef HAVE_NL_SOCKET_ADD_MEMBERSHIP
    ret = nl_socket_add_membership(nlh, RTNLGRP_LINK);
    if (ret != 0) {
        DEBUG(1, ("Unable to add membership: %s\n", nl_geterror()));
        return ret;
    }
#else
     int nlfd = nlw_get_fd(nlh);
     int group = RTNLGRP_LINK;

     errno = 0;
     ret = setsockopt(nlfd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                      &group, sizeof(group));
     if (ret < 0) {
         ret = errno;
         DEBUG(1, ("setsockopt failed (%d): %s\n", ret, strerror(ret)));
         return ret;
     }
#endif

     return 0;
}

/*******************************************************************
 * Callbacks for validating and receiving messages
 *******************************************************************/

#ifdef HAVE_LIBNL_OLDER_THAN_1_1
static int event_msg_recv(struct sockaddr_nl *nla, struct nlmsghdr *hdr,
                          void *arg)
{
    struct netlink_ctx *ctx = (struct netlink_ctx *) arg;

    if (!nlw_accept_message(ctx->nlh, nla, hdr)) {
        return NL_SKIP;
    }

    return NLW_OK;
}
#else
static int event_msg_recv(struct nl_msg *msg, void *arg)
{
    struct netlink_ctx *ctx = (struct netlink_ctx *) arg;
    struct nlmsghdr *hdr;
    const struct sockaddr_nl *snl;
    struct ucred *creds;

    creds = nlmsg_get_creds(msg);
    if (!creds || creds->uid != 0) {
        DEBUG(9, ("Ignoring netlink message from UID %d",
                  creds ? creds->uid : -1));
        return NL_SKIP;
    }

    hdr = nlmsg_hdr(msg);
    snl = nlmsg_get_src(msg);

    if (!nlw_accept_message(ctx->nlh, snl, hdr)) {
        return NL_SKIP;
    }

    return NLW_OK;
}
#endif

static void link_msg_handler(struct nl_object *obj, void *arg);

#ifdef HAVE_LIBNL_OLDER_THAN_1_1
static int event_msg_ready(struct sockaddr_nl *nla, struct nlmsghdr *hdr,
                           void *arg)
{
    nl_msg_parse(hdr, &link_msg_handler, arg);
    return NLW_OK;
}
#else
static int event_msg_ready(struct nl_msg *msg, void *arg)
{
    nl_msg_parse(msg, &link_msg_handler, arg);
    return NLW_OK;
}
#endif

static int nlw_set_callbacks(struct nl_handle *nlh, void *data)
{
    int ret = EIO;

#ifndef HAVE_NL_SOCKET_MODIFY_CB
    struct nl_cb *cb = nl_handle_get_cb(nlh);
    ret = nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM, event_msg_recv, data);
#else
    ret = nl_socket_modify_cb(nlh, NL_CB_MSG_IN, NL_CB_CUSTOM, event_msg_recv, data);
#endif
    if (ret != 0) {
        DEBUG(1, ("Unable to set validation callback\n"));
        return ret;
    }

#ifndef HAVE_NL_SOCKET_MODIFY_CB
    ret = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, event_msg_ready, data);
#else
    ret = nl_socket_modify_cb(nlh, NL_CB_VALID, NL_CB_CUSTOM, event_msg_ready, data);
#endif
    if (ret != 0) {
        DEBUG(1, ("Unable to set receive callback\n"));
        return ret;
    }

    return ret;
}

static void link_msg_handler(struct nl_object *obj, void *arg)
{
    struct netlink_ctx *ctx = (struct netlink_ctx *) arg;
    struct rtnl_link *link_obj;
    int flags;
    int ifidx;

    if (!nlw_is_link_object(obj)) return;

    link_obj = (struct rtnl_link *) obj;
    flags = rtnl_link_get_flags(link_obj);
    ifidx = rtnl_link_get_ifindex(link_obj);

    DEBUG(8, ("netlink link message: iface idx %d flags 0x%X\n", ifidx, flags));

    /* IFF_LOWER_UP is the indicator of carrier status */
    if (flags & IFF_LOWER_UP) {
        ctx->change_cb(NL_ROUTE_UP, ctx->cb_data);
    } else {
        ctx->change_cb(NL_ROUTE_DOWN, ctx->cb_data);
    }
}

static void netlink_fd_handler(struct tevent_context *ev, struct tevent_fd *fde,
                               uint16_t flags, void *data)
{
    struct netlink_ctx *nlctx = talloc_get_type(data, struct netlink_ctx);
    int ret;

    if (!nlctx || !nlctx->nlh) {
        DEBUG(1, ("Invalid netlink handle, this is most likely a bug!\n"));
        return;
    }

    ret = nlw_recvmsgs_default(nlctx->nlh);
    if (ret != EOK) {
        DEBUG(1, ("Error while reading from netlink fd\n"));
        return;
    }
}

/*******************************************************************
 * Set up the netlink library
 *******************************************************************/

int setup_netlink(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                  network_change_cb change_cb, void *cb_data,
                  struct netlink_ctx **_nlctx)
{
    struct netlink_ctx *nlctx;
    int ret;
    int nlfd;
    unsigned flags;

    nlctx = talloc_zero(mem_ctx, struct netlink_ctx);
    if (!nlctx) return ENOMEM;
    talloc_set_destructor((TALLOC_CTX *) nlctx, netlink_ctx_destructor);

    nlctx->change_cb = change_cb;
    nlctx->cb_data   = cb_data;

    /* allocate the libnl handle and register the default filter set */
    nlctx->nlh = nl_handle_alloc();
    if (!nlctx->nlh) {
        DEBUG(1, (("unable to allocate netlink handle: %s"),
                   nl_geterror()));
        ret = ENOMEM;
        goto fail;
    }

    /* Register our custom message validation filter */
    ret = nlw_set_callbacks(nlctx->nlh, nlctx);
    if (ret != 0) {
        DEBUG(1, ("Unable to set callbacks\n"));
        ret = EIO;
        goto fail;
    }

    /* Try to start talking to netlink */
    ret = nl_connect(nlctx->nlh, NETLINK_ROUTE);
    if (ret != 0) {
        DEBUG(1, ("Unable to connect to netlink: %s\n", nl_geterror()));
        ret = EIO;
        goto fail;
    }

    ret = nlw_enable_passcred(nlctx->nlh);
    if (ret != 0) {
        DEBUG(1, ("Cannot enable credential passing: %s\n", nl_geterror()));
        ret = EIO;
        goto fail;
    }

    /* Subscribe to the LINK group for internal carrier signals */
    ret = nlw_group_subscribe(nlctx->nlh);
    if (ret != 0) {
        DEBUG(1, ("Unable to subscribe to netlink monitor\n"));
        ret = EIO;
        goto fail;
    }

    nl_disable_sequence_check(nlctx->nlh);

    nlfd = nlw_get_fd(nlctx->nlh);
    flags = fcntl(nlfd, F_GETFL, 0);

    errno = 0;
    ret = fcntl(nlfd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0) {
        ret = errno;
        DEBUG(1, ("Cannot set the netlink fd to nonblocking\n"));
        goto fail;
    }

    nlctx->tefd = tevent_add_fd(ev, nlctx, nlfd, TEVENT_FD_READ,
                                netlink_fd_handler, nlctx);
    if (nlctx->tefd == NULL) {
        DEBUG(1, ("tevent_add_fd() failed\n"));
        ret = EIO;
        goto fail;
    }

    *_nlctx = nlctx;
    return EOK;

fail:
    talloc_free(nlctx);
    return ret;
}

#else       /* HAVE_LIBNL not defined */
int setup_netlink(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                  network_change_cb change_cb, void *cb_data,
                  struct netlink_ctx **_nlctx)
{
    if (nlctx) *nlctx = NULL;
    return EOK;
}
#endif
