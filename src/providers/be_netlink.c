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

#include "config.h"

#include <talloc.h>
#include <tevent.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "providers/be_netlink.h"
#include "util/util.h"

#ifdef HAVE_LIBNL
#include <linux/if.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
#include <linux/wireless.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>
#include <netlink/handlers.h>
#include <netlink/socket.h>
#endif

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define SYSFS_IFACE_TEMPLATE "/sys/class/net/%s"
#define SYSFS_IFACE_PATH_MAX (16+IFNAMSIZ)

#define PHY_80211_SUBDIR   "phy80211"
/* 9 = strlen(PHY_80211_SUBDIR)+1, 1 = path delimiter */
#define SYSFS_SUBDIR_PATH_MAX (SYSFS_IFACE_PATH_MAX+9+1)

#define TYPE_FILE "type"
/* 5 = strlen(TYPE_FILE)+1, 1 = path delimiter */
#define SYSFS_TYPE_PATH_MAX (SYSFS_IFACE_PATH_MAX+5+1)

#define BUFSIZE 8

#ifdef HAVE_LIBNL
/* Wrappers determining use of libnl version 1 or 3 */
#ifdef HAVE_LIBNL3

#define nlw_destroy_handle      nl_socket_free
#define nlw_alloc               nl_socket_alloc
#define nlw_disable_seq_check   nl_socket_disable_seq_check

#define nlw_geterror(error)     nl_geterror(error)

#define nlw_handle              nl_sock

#elif defined(HAVE_LIBNL1)

#define nlw_destroy_handle      nl_handle_destroy
#define nlw_alloc               nl_handle_alloc
#define nlw_disable_seq_check   nl_disable_sequence_check

#define nlw_geterror(error)     nl_geterror()

#define nlw_handle              nl_handle

#endif /* HAVE_LIBNL3 */

#endif /* HAVE_LIBNL */

enum nlw_msg_type {
    NLW_LINK,
    NLW_ROUTE,
    NLW_ADDR,
    NLW_OTHER
};

struct be_netlink_ctx {
#ifdef HAVE_LIBNL
    struct nlw_handle *nlp;
#endif
    struct tevent_fd *tefd;

    network_change_cb change_cb;
    void *cb_data;
};

#ifdef HAVE_LIBNL
static int netlink_ctx_destructor(void *ptr)
{
    struct be_netlink_ctx *nlctx;
    nlctx = talloc_get_type(ptr, struct be_netlink_ctx);

    nlw_destroy_handle(nlctx->nlp);
    return 0;
}

/*******************************************************************
 *                      Utility functions
 *******************************************************************/

/* rtnl_route_get_oif removed from libnl3 */
int
rtnlw_route_get_oif(struct rtnl_route * route)
{
#ifndef HAVE_RTNL_ROUTE_GET_OIF
    struct rtnl_nexthop * nh;
    int hops;

    hops = rtnl_route_get_nnexthops(route);
    if (hops <= 0) {
        return 0;
    }

    nh = rtnl_route_nexthop_n(route, 0);

    return rtnl_route_nh_get_ifindex(nh);
#else
    return rtnl_route_get_oif(route);
#endif
}

static bool has_wireless_extension(const char *ifname)
{
    int s;
    errno_t ret;
    struct iwreq iwr;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not open socket: [%d] %s\n", ret, strerror(ret));
        return false;
    }

    strncpy(iwr.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ-1);
    iwr.ifr_ifrn.ifrn_name[IFNAMSIZ-1] = '\0';
    /* Does the interface support a wireless extension? */
    ret = ioctl(s, SIOCGIWNAME, &iwr);
    close(s);

    return ret == 0;
}

static bool has_ethernet_encapsulation(const char *sysfs_path)
{
    char type_path[SYSFS_TYPE_PATH_MAX];
    errno_t ret;
    int fd = -1;
    char buf[BUFSIZE];

    ret = snprintf(type_path, SYSFS_TYPE_PATH_MAX,
                   "%s/%s", sysfs_path, TYPE_FILE);
    if (ret < 0) {
        DEBUG(SSSDBG_OP_FAILURE, "snprintf failed\n");
        return false;
    } else if (ret >= SYSFS_TYPE_PATH_MAX) {
        DEBUG(SSSDBG_OP_FAILURE, "path too long?!?!\n");
        return false;
    }

    errno = 0;
    fd = open(type_path, O_RDONLY);
    if (fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, "Could not open sysfs file %s: [%d] %s\n",
              type_path, ret, strerror(ret));
        return false;
    }

    memset(buf, 0, BUFSIZE);
    errno = 0;
    ret = sss_atomic_read_s(fd, buf, BUFSIZE);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "read failed [%d][%s].\n", ret, strerror(ret));
        close(fd);
        return false;
    }
    close(fd);
    buf[BUFSIZE-1] = '\0';

    return strncmp(buf, "1\n", BUFSIZE) == 0;
}

static bool has_phy_80211_subdir(const char *sysfs_path)
{
    char phy80211_path[SYSFS_SUBDIR_PATH_MAX];
    struct stat statbuf;
    errno_t ret;

    ret = snprintf(phy80211_path, SYSFS_SUBDIR_PATH_MAX,
                   "%s/%s", sysfs_path, PHY_80211_SUBDIR);
    if (ret < 0) {
        DEBUG(SSSDBG_OP_FAILURE, "snprintf failed\n");
        return false;
    } else if (ret >= SYSFS_SUBDIR_PATH_MAX) {
        DEBUG(SSSDBG_OP_FAILURE, "path too long?!?!\n");
        return false;
    }

    errno = 0;
    ret = stat(phy80211_path, &statbuf);
    if (ret == -1) {
        ret = errno;
        if (ret == ENOENT || ret == ENOTDIR) {
            DEBUG(SSSDBG_TRACE_LIBS, "No %s directory in sysfs, probably "
                  "not a wireless interface\n", PHY_80211_SUBDIR);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "stat failed: [%d] %s\n",
                  ret, strerror(ret));
        }
        return false;
    }

    if (statbuf.st_mode & S_IFDIR) {
        DEBUG(SSSDBG_TRACE_LIBS, "Directory %s found in sysfs, looks like "
              "a wireless iface\n", PHY_80211_SUBDIR);
        return true;
    }

    return false;
}

static bool discard_iff_up(const char *ifname)
{
    char path[SYSFS_IFACE_PATH_MAX];
    errno_t ret;

    /* This catches most of the new 80211 drivers */
    if (has_wireless_extension(ifname)) {
        DEBUG(SSSDBG_TRACE_FUNC, "%s has a wireless extension\n", ifname);
        return true;
    }

    ret = snprintf(path, SYSFS_IFACE_PATH_MAX, SYSFS_IFACE_TEMPLATE, ifname);
    if (ret < 0) {
        DEBUG(SSSDBG_OP_FAILURE, "snprintf failed\n");
        return false;
    } else if (ret >= SYSFS_IFACE_PATH_MAX) {
        DEBUG(SSSDBG_OP_FAILURE, "path too long?!?!\n");
        return false;
    }

    /* This will filter PPP and such. Both wired and wireless
     * interfaces have the encapsulation. */
    if (!has_ethernet_encapsulation(path)) {
        DEBUG(SSSDBG_TRACE_FUNC, "%s does not have ethernet encapsulation, "
              "filtering out\n", ifname);
        return true;
    }

    /* This captures old WEXT drivers, the new mac8011 would
     * be caught by the ioctl check */
    if (has_phy_80211_subdir(path)) {
        DEBUG(SSSDBG_TRACE_FUNC, "%s has a 802_11 subdir, filtering out\n",
              ifname);
        return true;
    }

    return false;
}

static void nladdr_to_string(struct nl_addr *nl, char *buf, size_t bufsize)
{
    int addr_family;
    void *addr;

    addr_family = nl_addr_get_family(nl);
    if (addr_family != AF_INET && addr_family != AF_INET6) {
        strncpy(buf, "unknown", bufsize-1);
        buf[bufsize-1] = '\0';
        return;
    }

    addr = nl_addr_get_binary_addr(nl);
    if (!addr) return;

    if (inet_ntop(addr_family, addr, buf, bufsize) == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "inet_ntop failed\n");
        snprintf(buf, bufsize, "unknown");
    }
}

/*******************************************************************
 * Wrappers for different capabilities of different libnl versions
 *******************************************************************/

static bool nlw_accept_message(struct nlw_handle *nlp,
                               const struct sockaddr_nl *snl,
                               struct nlmsghdr *hdr)
{
    bool accept_msg = false;
    uint32_t local_port;

    if (snl == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Malformed message, skipping\n");
        return false;
    }

    /* Accept any messages from the kernel */
    if (hdr->nlmsg_pid == 0 || snl->nl_pid == 0) {
        accept_msg = true;
    }

    /* And any multicast message directed to our netlink PID, since multicast
     * currently requires CAP_ADMIN to use.
     */
    local_port = nl_socket_get_local_port(nlp);
    if ((hdr->nlmsg_pid == local_port) && snl->nl_groups) {
        accept_msg = true;
    }

    if (accept_msg == false) {
        DEBUG(SSSDBG_TRACE_ALL,
              "ignoring netlink message from PID %d\n", hdr->nlmsg_pid);
    }

    return accept_msg;
}

static bool nlw_is_addr_object(struct nl_object *obj)
{
    bool is_addr_object = true;
    struct rtnl_addr *filter;

    filter = rtnl_addr_alloc();
    if (!filter) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Allocation error!\n");
        is_addr_object = false;
    }

    /* Ensure it's an addr object */
    if (!nl_object_match_filter(obj, OBJ_CAST(filter))) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Not an addr object\n");
        is_addr_object = false;
    }

    rtnl_addr_put(filter);
    return is_addr_object;
}

static bool nlw_is_route_object(struct nl_object *obj)
{
    bool is_route_object = true;
    struct rtnl_route *filter;

    filter = rtnl_route_alloc();
    if (!filter) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Allocation error!\n");
        is_route_object = false;
    }

    /* Ensure it's a route object */
    if (!nl_object_match_filter(obj, OBJ_CAST(filter))) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Not a route object\n");
        is_route_object = false;
    }

    rtnl_route_put(filter);
    return is_route_object;
}

static bool nlw_is_link_object(struct nl_object *obj)
{
    bool is_link_object = true;
    struct rtnl_link *filter;

    filter = rtnl_link_alloc();
    if (!filter) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Allocation error!\n");
        is_link_object = false;
    }

    /* Ensure it's a link object */
    if (!nl_object_match_filter(obj, OBJ_CAST(filter))) {
        DEBUG(SSSDBG_OP_FAILURE, "Not a link object\n");
        is_link_object = false;
    }

    rtnl_link_put(filter);
    return is_link_object;
}

static int nlw_enable_passcred(struct nlw_handle *nlp)
{
#ifdef HAVE_NL_SET_PASSCRED
    return nl_set_passcred(nlp, 1);  /* 1 = enabled */
#elif defined(HAVE_NL_SOCKET_SET_PASSCRED)
    return nl_socket_set_passcred(nlp, 1);
#else
    return EOK;                      /* not available in this version */
#endif
}

static int nlw_group_subscribe(struct nlw_handle *nlp, int group)
{
    int ret;

#ifdef HAVE_NL_SOCKET_ADD_MEMBERSHIP
    ret = nl_socket_add_membership(nlp, group);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to add membership: %s\n", nlw_geterror(ret));
        return ret;
    }
#else
     int nlfd = nl_socket_get_fd(nlp);

     errno = 0;
     ret = setsockopt(nlfd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                      &group, sizeof(group));
     if (ret < 0) {
         ret = errno;
         DEBUG(SSSDBG_CRIT_FAILURE,
               "setsockopt failed (%d): %s\n", ret, strerror(ret));
         return ret;
     }
#endif

     return 0;
}

static int nlw_groups_subscribe(struct nlw_handle *nlp, int *groups)
{
    int ret;
    int i;

    for (i=0; groups[i]; i++) {
        ret = nlw_group_subscribe(nlp, groups[i]);
        if (ret != EOK) return ret;
    }

    return EOK;
}

/*******************************************************************
 * Callbacks for validating and receiving messages
 *******************************************************************/

static int event_msg_recv(struct nl_msg *msg, void *arg)
{
    struct be_netlink_ctx *ctx = (struct be_netlink_ctx *) arg;
    struct nlmsghdr *hdr;
    const struct sockaddr_nl *snl;
    struct ucred *creds;

    creds = nlmsg_get_creds(msg);
    if (!creds || creds->uid != 0) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Ignoring netlink message from UID %"SPRIuid"\n",
              creds ? creds->uid : (uid_t)-1);
        return NL_SKIP;
    }

    hdr = nlmsg_hdr(msg);
    snl = nlmsg_get_src(msg);

    if (!nlw_accept_message(ctx->nlp, snl, hdr)) {
        return NL_SKIP;
    }

    return NL_OK;
}

static void link_msg_handler(struct nl_object *obj, void *arg);
static void route_msg_handler(struct nl_object *obj, void *arg);
static void addr_msg_handler(struct nl_object *obj, void *arg);

static enum nlw_msg_type message_type(struct nlmsghdr *hdr)
{
    DEBUG(SSSDBG_FUNC_DATA, "netlink Message type: %d\n", hdr->nlmsg_type);
    switch (hdr->nlmsg_type) {
        /* network interface added */
        case RTM_NEWLINK:
            return NLW_LINK;
        /* routing table changed */
        case RTM_NEWROUTE:
        case RTM_DELROUTE:
            return NLW_ROUTE;
        /* IP address added or deleted */
        case RTM_NEWADDR:
        case RTM_DELADDR:
            return NLW_ADDR;
        /* Something else happened, but we don't care (typically RTM_GET* ) */
        default:
            return NLW_OTHER;
    }

    return NLW_OTHER;
}

static int event_msg_ready(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);

    switch (message_type(hdr)) {
        case NLW_LINK:
            nl_msg_parse(msg, &link_msg_handler, arg);
            break;
        case NLW_ROUTE:
            nl_msg_parse(msg, &route_msg_handler, arg);
            break;
        case NLW_ADDR:
            nl_msg_parse(msg, &addr_msg_handler, arg);
            break;
        default:
            return EOK; /* Don't care */
    }

    return NL_OK;
}

static int nlw_set_callbacks(struct nlw_handle *nlp, void *data)
{
    int ret = EIO;

#ifdef HAVE_NL_SOCKET_MODIFY_CB
    ret = nl_socket_modify_cb(nlp, NL_CB_MSG_IN, NL_CB_CUSTOM, event_msg_recv,
                              data);
#else
    struct nl_cb *cb = nl_handle_get_cb(nlp);
    ret = nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM, event_msg_recv, data);
#endif
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set validation callback\n");
        return ret;
    }

#ifdef HAVE_NL_SOCKET_MODIFY_CB
    ret = nl_socket_modify_cb(nlp, NL_CB_VALID, NL_CB_CUSTOM, event_msg_ready,
                              data);
#else
    ret = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, event_msg_ready, data);
#endif
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set receive callback\n");
        return ret;
    }

    return ret;
}

static void route_msg_debug_print(struct rtnl_route *route_obj)
{
    int prefixlen;
    char buf[INET6_ADDRSTRLEN];
    struct nl_addr *nl;

    nl = rtnl_route_get_dst(route_obj);
    if (nl) {
        nladdr_to_string(nl, buf, INET6_ADDRSTRLEN);
        prefixlen = nl_addr_get_prefixlen(nl);
    } else {
        strncpy(buf, "unknown", INET6_ADDRSTRLEN);
        prefixlen = 0;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "route idx %d flags %#X family %d addr %s/%d\n",
          rtnlw_route_get_oif(route_obj), rtnl_route_get_flags(route_obj),
          rtnl_route_get_family(route_obj), buf, prefixlen);

}

/*
 * If a bridge interface is configured it sets up a timer to requery for
 * multicast group memberships periodically. We need to discard such
 * messages.
 */
static bool route_is_multicast(struct rtnl_route *route_obj)
{
    struct nl_addr *nl;
    struct in6_addr *addr6 = NULL;
    struct in_addr *addr4 = NULL;

    nl = rtnl_route_get_dst(route_obj);
    if (!nl) {
        DEBUG(SSSDBG_MINOR_FAILURE, "A route with no destination?\n");
        return false;
    }

    if (nl_addr_get_family(nl) == AF_INET) {
        addr4 = nl_addr_get_binary_addr(nl);
        if (!addr4) {
            return false;
        }

        return IN_MULTICAST(ntohl(addr4->s_addr));
    } else if (nl_addr_get_family(nl) == AF_INET6) {
        addr6 = nl_addr_get_binary_addr(nl);
        if (!addr6) {
            return false;
        }

        return IN6_IS_ADDR_MULTICAST(addr6);
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "Unknown route address family\n");
    return false;
}

static void route_msg_handler(struct nl_object *obj, void *arg)
{
    struct rtnl_route *route_obj;
    struct be_netlink_ctx *ctx = (struct be_netlink_ctx *) arg;

    if (!nlw_is_route_object(obj)) return;

    route_obj = (struct rtnl_route *) obj;

    if (route_is_multicast(route_obj)) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Discarding multicast route message\n");
        return;
    }

    if (debug_level & SSSDBG_TRACE_LIBS) {
        route_msg_debug_print(route_obj);
    }

    ctx->change_cb(ctx->cb_data);
}

static void addr_msg_debug_print(struct rtnl_addr *addr_obj)
{
    unsigned int flags;
    char str_flags[512];
    int ifidx;
    struct nl_addr *local_addr;
    char buf[INET6_ADDRSTRLEN];

    flags = rtnl_addr_get_flags(addr_obj);
    ifidx = rtnl_addr_get_ifindex(addr_obj);
    local_addr = rtnl_addr_get_local(addr_obj);

    rtnl_addr_flags2str(flags, str_flags, 512);
    nladdr_to_string(local_addr, buf, INET6_ADDRSTRLEN);

    DEBUG(SSSDBG_TRACE_LIBS, "netlink addr message: iface idx %u "
          "addr %s flags 0x%X (%s)\n", ifidx, buf, flags, str_flags);
}

static void addr_msg_handler(struct nl_object *obj, void *arg)
{
    int err;
    struct be_netlink_ctx *ctx = (struct be_netlink_ctx *) arg;
    struct rtnl_addr *addr_obj;
    struct nl_addr *local_addr;
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    socklen_t salen;

    if (!nlw_is_addr_object(obj)) return;

    addr_obj = (struct rtnl_addr *) obj;
    if (debug_level & SSSDBG_TRACE_LIBS) {
        addr_msg_debug_print(addr_obj);
    }

    local_addr = rtnl_addr_get_local(addr_obj);
    if (local_addr == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Received RTM_NEWADDR with no address\n");
        return;
    }

    switch (nl_addr_get_family(local_addr)) {
    case AF_INET6:
        salen = sizeof(struct sockaddr_in6);
        err = nl_addr_fill_sockaddr(local_addr,
                                    (struct sockaddr *) &sa6,
                                    &salen);
        if (err < 0) {
          DEBUG(SSSDBG_MINOR_FAILURE,
                "Unknown error in nl_addr_fill_sockaddr\n");
          return;
        }

        if (!check_ipv6_addr(&sa6.sin6_addr, SSS_NO_SPECIAL)) {
            DEBUG(SSSDBG_TRACE_LIBS, "Ignoring special address.\n");
            return;
        }
        break;

    case AF_INET:
        salen = sizeof(struct sockaddr_in);
        err = nl_addr_fill_sockaddr(local_addr,
                                    (struct sockaddr *) &sa4,
                                     &salen);
        if (err < 0) {
            DEBUG(SSSDBG_MINOR_FAILURE,
            "Unknown error in nl_addr_fill_sockaddr\n");
            return;
        }
        if (check_ipv4_addr(&sa4.sin_addr, SSS_NO_SPECIAL)) {
            DEBUG(SSSDBG_TRACE_LIBS, "Ignoring special address.\n");
            return;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown address family\n");
        return;
    }

    ctx->change_cb(ctx->cb_data);
}

static void link_msg_handler(struct nl_object *obj, void *arg)
{
    struct be_netlink_ctx *ctx = (struct be_netlink_ctx *) arg;
    struct rtnl_link *link_obj;
    unsigned int flags;
    char str_flags[512];
    int ifidx;
    const char *ifname;

    if (!nlw_is_link_object(obj)) return;

    link_obj = (struct rtnl_link *) obj;
    flags = rtnl_link_get_flags(link_obj);
    ifidx = rtnl_link_get_ifindex(link_obj);

    rtnl_link_flags2str(flags, str_flags, 512);

    ifname = rtnl_link_get_name(link_obj);
    DEBUG(SSSDBG_TRACE_LIBS, "netlink link message: iface idx %u (%s) "
          "flags 0x%X (%s)\n", ifidx, ifname, flags, str_flags);

    /* IFF_LOWER_UP is the indicator of carrier status */
    if ((flags & IFF_RUNNING) && (flags & IFF_LOWER_UP) &&
         !discard_iff_up(ifname)) {
        ctx->change_cb(ctx->cb_data);
    }
}

static void netlink_fd_handler(struct tevent_context *ev, struct tevent_fd *fde,
                               uint16_t flags, void *data)
{
    struct be_netlink_ctx *nlctx = talloc_get_type(data, struct be_netlink_ctx);
    int ret;

    if (!nlctx || !nlctx->nlp) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Invalid netlink handle, this is most likely a bug!\n");
        return;
    }

    ret = nl_recvmsgs_default(nlctx->nlp);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Error while reading from netlink fd: %s\n",
              nlw_geterror(ret));
        return;
    }
}

/*******************************************************************
 * Set up the netlink library
 *******************************************************************/

int netlink_watch(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                  network_change_cb change_cb, void *cb_data,
                  struct be_netlink_ctx **_nlctx)
{
    struct be_netlink_ctx *nlctx;
    int ret;
    int nlfd;
    int groups[] = { RTNLGRP_LINK, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE,
                     RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, 0 };

    nlctx = talloc_zero(mem_ctx, struct be_netlink_ctx);
    if (!nlctx) return ENOMEM;
    talloc_set_destructor((TALLOC_CTX *) nlctx, netlink_ctx_destructor);

    nlctx->change_cb = change_cb;
    nlctx->cb_data   = cb_data;

    /* allocate the libnl handle/socket and register the default filter set */
    nlctx->nlp = nlw_alloc();
    if (!nlctx->nlp) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "unable to allocate netlink handle: %s\n", nlw_geterror(ENOMEM));
        ret = ENOMEM;
        goto fail;
    }

    /* Register our custom message validation filter */
    ret = nlw_set_callbacks(nlctx->nlp, nlctx);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set callbacks\n");
        ret = EIO;
        goto fail;
    }

    /* Try to start talking to netlink */
    ret = nl_connect(nlctx->nlp, NETLINK_ROUTE);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to connect to netlink: %s\n", nlw_geterror(ret));
        ret = EIO;
        goto fail;
    }

    ret = nlw_enable_passcred(nlctx->nlp);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot enable credential passing: %s\n", nlw_geterror(ret));
        ret = EIO;
        goto fail;
    }

    /* Subscribe to the LINK group for internal carrier signals */
    ret = nlw_groups_subscribe(nlctx->nlp, groups);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to subscribe to netlink monitor\n");
        ret = EIO;
        goto fail;
    }

    nlw_disable_seq_check(nlctx->nlp);

    nlfd = nl_socket_get_fd(nlctx->nlp);
    ret = sss_fd_nonblocking(nlfd);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot set the netlink fd to nonblocking\n");
        goto fail;
    }

    nlctx->tefd = tevent_add_fd(ev, nlctx, nlfd, TEVENT_FD_READ,
                                netlink_fd_handler, nlctx);
    if (nlctx->tefd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_fd() failed\n");
        ret = EIO;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Netlink watching is enabled\n");
    *_nlctx = nlctx;
    return EOK;

fail:
    talloc_free(nlctx);
    return ret;
}

#else       /* HAVE_LIBNL not defined */
int netlink_watch(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                  network_change_cb change_cb, void *cb_data,
                  struct be_netlink_ctx **_nlctx)
{
    if (_nlctx) *_nlctx = NULL;
    return EOK;
}
#endif
