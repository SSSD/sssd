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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <krb5/locate_plugin.h>

#include "providers/krb5/krb5_auth.h"

struct sssd_ctx {
    char *sssd_realm;
    char *sssd_kdc;
};

krb5_error_code sssd_krb5_locator_init(krb5_context context,
                                       void **private_data)
{
    struct sssd_ctx *ctx;
    char *dummy;

#ifdef KRB5_PLUGIN_DEBUG
    fprintf(stderr,"sssd_krb5_locator_init called\n");
#endif

    ctx = calloc(1,sizeof(struct sssd_ctx));
    if (ctx == NULL) return ENOMEM;

    dummy = getenv(SSSD_KRB5_REALM);
    if (dummy == NULL) goto failed;
    ctx->sssd_realm = strdup(dummy);
    if (ctx->sssd_realm == NULL) goto failed;

    dummy = getenv(SSSD_KRB5_KDC);
    if (dummy == NULL) goto failed;
    ctx->sssd_kdc = strdup(dummy);
    if (ctx->sssd_kdc == NULL) goto failed;

    *private_data = ctx;

    return 0;
failed:
    free(ctx->sssd_realm);
    free(ctx->sssd_kdc);
    free(ctx);

    private_data = NULL;

    return EINVAL;
}

void sssd_krb5_locator_close(void *private_data)
{
    struct sssd_ctx *ctx;

#ifdef KRB5_PLUGIN_DEBUG
    fprintf(stderr,"sssd_krb5_locator_close called\n");
#endif

    if (private_data == NULL) return;

    ctx = (struct sssd_ctx *) private_data;
    free(ctx->sssd_realm);
    free(ctx->sssd_kdc);
    free(ctx);

    return;
}

krb5_error_code sssd_krb5_locator_lookup(void *private_data,
                    enum locate_service_type svc,
                    const char *realm,
                    int socktype,
                    int family,
                    int (*cbfunc)(void *, int, struct sockaddr *),
                    void *cbdata)
{
    int ret;
    struct sockaddr_in addr;
    struct sssd_ctx *ctx;

    memset(&addr, 0, sizeof(struct sockaddr_in));

    if (private_data == NULL) return KRB5_PLUGIN_NO_HANDLE;
    ctx = (struct sssd_ctx *) private_data;

#ifdef KRB5_PLUGIN_DEBUG
    fprintf(stderr,"[%s][%s][%s][%d][%d][%d]\n", realm, ctx->sssd_realm,
                                                 ctx->sssd_kdc, socktype,
                                                 family, svc);
#endif

    switch (svc) {
        case locate_service_kdc:
        case locate_service_master_kdc:
        case locate_service_kadmin:
            break;
        case locate_service_krb524:
        case locate_service_kpasswd:
            return KRB5_PLUGIN_NO_HANDLE;
        default:
            return EINVAL;
    }

    switch (family) {
        case AF_UNSPEC:
        case AF_INET:
            break;
        default:
            return KRB5_PLUGIN_NO_HANDLE;
    }

    switch (socktype) {
        case SOCK_STREAM:
        case SOCK_DGRAM:
            break;
        default:
            return EINVAL;
    }

    if (strcmp(realm, ctx->sssd_realm) != 0)
        return KRB5_PLUGIN_NO_HANDLE;

    addr.sin_family = AF_INET;
    ret = inet_aton(ctx->sssd_kdc, &addr.sin_addr);
    if (ret == 0) return EINVAL;
    addr.sin_port = htons(88);

    ret = cbfunc(cbdata, socktype, (struct sockaddr *) &addr);

    return 0;
}

const krb5plugin_service_locate_ftable service_locator = {
    0, /* version */
    sssd_krb5_locator_init,
    sssd_krb5_locator_close,
    sssd_krb5_locator_lookup,
};
