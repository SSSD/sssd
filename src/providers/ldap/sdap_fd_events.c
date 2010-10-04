/*
    SSSD

    Helper routines for file descriptor events

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include "util/util.h"
#include "providers/ldap/sdap_async_private.h"

struct sdap_fd_events {
#ifdef HAVE_LDAP_CONNCB
    struct ldap_conncb *conncb;
#else
    struct tevent_fd *fde;
#endif
};

int get_fd_from_ldap(LDAP *ldap, int *fd)
{
    int ret;

    ret = ldap_get_option(ldap, LDAP_OPT_DESC, fd);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to get fd from ldap!!\n"));
        *fd = -1;
        return EIO;
    }

    return EOK;
}

int remove_ldap_connection_callbacks(struct sdap_handle *sh)
{
    /* sdap_fd_events might be NULL here if sdap_mark_offline()
     * was called before a connection was established.
     */
    if (sh->sdap_fd_events) {
#ifdef HAVE_LDAP_CONNCB
        talloc_zfree(sh->sdap_fd_events->conncb);
#else
        talloc_zfree(sh->sdap_fd_events->fde);
#endif
    }
    return EOK;
}

#ifdef HAVE_LDAP_CONNCB

static int remove_connection_callback(TALLOC_CTX *mem_ctx)
{
    int lret;
    struct ldap_conncb *conncb = talloc_get_type(mem_ctx, struct ldap_conncb);

    struct ldap_cb_data *cb_data = talloc_get_type(conncb->lc_arg,
                                                   struct ldap_cb_data);

    lret = ldap_get_option(cb_data->sh->ldap, LDAP_OPT_CONNECT_CB, conncb);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to remove connection callback.\n"));
    } else {
        DEBUG(9, ("Successfully removed connection callback.\n"));
    }
    return EOK;
}

static int sdap_ldap_connect_callback_add(LDAP *ld, Sockbuf *sb,
                                          LDAPURLDesc *srv,
                                          struct sockaddr *addr,
                                          struct ldap_conncb *ctx)
{
    int ret;
    ber_socket_t ber_fd;
    struct fd_event_item *fd_event_item;
    struct ldap_cb_data *cb_data = talloc_get_type(ctx->lc_arg,
                                                   struct ldap_cb_data);

    if (cb_data == NULL) {
        DEBUG(1, ("sdap_ldap_connect_callback_add called without "
                  "callback data.\n"));
        return EINVAL;
    }

    ret = ber_sockbuf_ctrl(sb, LBER_SB_OPT_GET_FD, &ber_fd);
    if (ret == -1) {
        DEBUG(1, ("ber_sockbuf_ctrl failed.\n"));
        return EINVAL;
    }
    DEBUG(9, ("New LDAP connection to [%s] with fd [%d].\n",
              ldap_url_desc2str(srv), ber_fd));

    fd_event_item = talloc_zero(cb_data, struct fd_event_item);
    if (fd_event_item == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }

    fd_event_item->fde = tevent_add_fd(cb_data->ev, fd_event_item, ber_fd,
                                       TEVENT_FD_READ, sdap_ldap_result,
                                       cb_data->sh);
    if (fd_event_item->fde == NULL) {
        DEBUG(1, ("tevent_add_fd failed.\n"));
        talloc_free(fd_event_item);
        return ENOMEM;
    }
    fd_event_item->fd = ber_fd;

    DLIST_ADD(cb_data->fd_list, fd_event_item);

    return LDAP_SUCCESS;
}

static void sdap_ldap_connect_callback_del(LDAP *ld, Sockbuf *sb,
                                           struct ldap_conncb *ctx)
{
    int ret;
    ber_socket_t ber_fd;
    struct fd_event_item *fd_event_item;
    struct ldap_cb_data *cb_data = talloc_get_type(ctx->lc_arg,
                                                   struct ldap_cb_data);

    if (sb == NULL || cb_data == NULL) {
        return;
    }

    ret = ber_sockbuf_ctrl(sb, LBER_SB_OPT_GET_FD, &ber_fd);
    if (ret == -1) {
        DEBUG(1, ("ber_sockbuf_ctrl failed.\n"));
        return;
    }
    DEBUG(9, ("Closing LDAP connection with fd [%d].\n", ber_fd));

    DLIST_FOR_EACH(fd_event_item, cb_data->fd_list) {
        if (fd_event_item->fd == ber_fd) {
            break;
        }
    }
    if (fd_event_item == NULL) {
        DEBUG(1, ("No event for fd [%d] found.\n", ber_fd));
        return;
    }

    DLIST_REMOVE(cb_data->fd_list, fd_event_item);
    talloc_zfree(fd_event_item);

    return;
}

#else

static int sdap_install_ldap_callbacks(struct sdap_handle *sh,
                                       struct tevent_context *ev)
{
    int fd;
    int ret;

    if (sh->sdap_fd_events) {
        DEBUG(1, ("sdap_install_ldap_callbacks is called with already "
                  "initialized sdap_fd_events.\n"));
        return EINVAL;
    }

    sh->sdap_fd_events = talloc_zero(sh, struct sdap_fd_events);
    if (!sh->sdap_fd_events) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ret = get_fd_from_ldap(sh->ldap, &fd);
    if (ret) return ret;

    sh->sdap_fd_events->fde = tevent_add_fd(ev, sh->sdap_fd_events, fd,
                                            TEVENT_FD_READ, sdap_ldap_result,
                                            sh);
    if (!sh->sdap_fd_events->fde) {
        talloc_zfree(sh->sdap_fd_events);
        return ENOMEM;
    }

    DEBUG(8, ("Trace: sh[%p], connected[%d], ops[%p], fde[%p], ldap[%p]\n",
              sh, (int)sh->connected, sh->ops, sh->sdap_fd_events->fde,
              sh->ldap));

    return EOK;
}

#endif


errno_t setup_ldap_connection_callbacks(struct sdap_handle *sh,
                                        struct tevent_context *ev)
{
#ifdef HAVE_LDAP_CONNCB
    int ret;
    struct ldap_cb_data *cb_data;

    sh->sdap_fd_events = talloc_zero(sh, struct sdap_fd_events);
    if (sh->sdap_fd_events == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    sh->sdap_fd_events->conncb = talloc_zero(sh->sdap_fd_events,
                                             struct ldap_conncb);
    if (sh->sdap_fd_events->conncb == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    cb_data = talloc_zero(sh->sdap_fd_events->conncb, struct ldap_cb_data);
    if (cb_data == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    cb_data->sh = sh;
    cb_data->ev = ev;

    sh->sdap_fd_events->conncb->lc_add = sdap_ldap_connect_callback_add;
    sh->sdap_fd_events->conncb->lc_del = sdap_ldap_connect_callback_del;
    sh->sdap_fd_events->conncb->lc_arg = cb_data;

    ret = ldap_set_option(sh->ldap, LDAP_OPT_CONNECT_CB,
                          sh->sdap_fd_events->conncb);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set connection callback\n"));
        ret = EFAULT;
        goto fail;
    }

    talloc_set_destructor((TALLOC_CTX *) sh->sdap_fd_events->conncb,
                          remove_connection_callback);

    return EOK;

fail:
    talloc_zfree(sh->sdap_fd_events);
    return ret;
#else
    DEBUG(9, ("LDAP connection callbacks are not supported.\n"));
    return EOK;
#endif
}

errno_t sdap_set_connected(struct sdap_handle *sh, struct tevent_context *ev)
{
    int ret = EOK;

    sh->connected = true;

#ifndef HAVE_LDAP_CONNCB
    ret = sdap_install_ldap_callbacks(sh, ev);
#endif

    return ret;
}
