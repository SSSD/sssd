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
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>


#include <krb5/locate_plugin.h>

#include "providers/krb5/krb5_common.h"

#define SSSD_KRB5_LOCATOR_DEBUG "SSSD_KRB5_LOCATOR_DEBUG"
#define DEBUG_KEY "[sssd_krb5_locator] "
#define DEBUG(body) do { \
    if (ctx->debug) { \
        debug_fn body; \
    } \
} while(0);

struct sssd_ctx {
    char *sssd_realm;
    struct addrinfo *sssd_kdc_addrinfo;
    bool debug;
};

void debug_fn(const char *format, ...)
{
    va_list ap;
    char *s = NULL;
    int ret;

    va_start(ap, format);

    ret = vasprintf(&s, format, ap);
    if (ret < 0) {
        /* ENOMEM */
        return;
    }

    va_end(ap);

    fprintf(stderr, DEBUG_KEY "%s", s);
    free(s);
}

krb5_error_code sssd_krb5_locator_init(krb5_context context,
                                       void **private_data)
{
    struct sssd_ctx *ctx;
    const char *dummy;
    int ret;

    ctx = calloc(1,sizeof(struct sssd_ctx));
    if (ctx == NULL) return ENOMEM;

    dummy = getenv(SSSD_KRB5_LOCATOR_DEBUG);
    if (dummy == NULL) {
        ctx->debug = false;
    } else {
        ctx->debug = true;
        DEBUG(("sssd_krb5_locator_init called\n"));
    }

    dummy = getenv(SSSD_KRB5_REALM);
    if (dummy == NULL) goto failed;
    ctx->sssd_realm = strdup(dummy);
    if (ctx->sssd_realm == NULL) goto failed;

    dummy = getenv(SSSD_KRB5_KDC);
    if (dummy == NULL) goto failed;

    ret = getaddrinfo(dummy, "kerberos", NULL, &ctx->sssd_kdc_addrinfo);
    if (ret != 0) {
        DEBUG(("getaddrinfo failed [%d][%s].\n", ret, gai_strerror(ret)));
        if (ret == EAI_SYSTEM) {
            DEBUG(("getaddrinfo failed [%d][%s].\n", errno, strerror(errno)));
        }
        goto failed;
    }

    *private_data = ctx;

    return 0;
failed:
    freeaddrinfo(ctx->sssd_kdc_addrinfo);
    free(ctx->sssd_realm);
    free(ctx);

    private_data = NULL;

    return EINVAL;
}

void sssd_krb5_locator_close(void *private_data)
{
    struct sssd_ctx *ctx;

    if (private_data == NULL) return;

    ctx = (struct sssd_ctx *) private_data;
    DEBUG(("sssd_krb5_locator_close called\n"));

    freeaddrinfo(ctx->sssd_kdc_addrinfo);
    free(ctx->sssd_realm);
    free(ctx);
    private_data = NULL;

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
    struct addrinfo *ai;
    struct sssd_ctx *ctx;
    char hostip[NI_MAXHOST];

    if (private_data == NULL) return KRB5_PLUGIN_NO_HANDLE;
    ctx = (struct sssd_ctx *) private_data;

    DEBUG(("sssd_realm[%s] requested realm[%s] family[%d] socktype[%d] "
          "locate_service[%d]\n", ctx->sssd_realm, realm, family, socktype,
          svc));

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
        case AF_INET6:
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

    for (ai = ctx->sssd_kdc_addrinfo; ai != NULL; ai = ai->ai_next) {
        ret = getnameinfo(ai->ai_addr, ai->ai_addrlen, hostip, NI_MAXHOST,
                          NULL, 0, NI_NUMERICHOST);
        if (ret != 0) {
            DEBUG(("getnameinfo failed [%d][%s].\n", ret, gai_strerror(ret)));
            if (ret == EAI_SYSTEM) {
                DEBUG(("getnameinfo failed [%d][%s].\n", errno, strerror(errno)));
            }
        }
        DEBUG(("addr[%s] family[%d] socktype[%d] - ", hostip, ai->ai_family,
                                                      ai->ai_socktype));

        if ((family == AF_UNSPEC || ai->ai_family == family) &&
            ai->ai_socktype == socktype) {

            ret = cbfunc(cbdata, socktype, ai->ai_addr);
            if (ret != 0) {
                DEBUG(("\ncbfunc failed\n"));
            } else {
                DEBUG(("used\n"));
            }
        } else {
            DEBUG((" NOT used\n"));
        }
    }

    return 0;
}

const krb5plugin_service_locate_ftable service_locator = {
    0, /* version */
    sssd_krb5_locator_init,
    sssd_krb5_locator_close,
    sssd_krb5_locator_lookup,
};
