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
#include <sys/stat.h>
#include <fcntl.h>

#include <krb5/locate_plugin.h>

#include "providers/krb5/krb5_common.h"

#define BUFSIZE 512
#define SSSD_KRB5_LOCATOR_DEBUG "SSSD_KRB5_LOCATOR_DEBUG"
#define DEBUG_KEY "[sssd_krb5_locator] "
#define PLUGIN_DEBUG(body) do { \
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

static int get_kdcinfo(const char *realm, struct sssd_ctx *ctx)
{
    int ret;
    char *kdcinfo_name = NULL;
    size_t len;
    uint8_t buf[BUFSIZE + 1];
    uint8_t *p;
    int fd = -1;

    len = strlen(realm) + strlen(KDCINFO_TMPL);

    kdcinfo_name = calloc(1, len + 1);
    if (kdcinfo_name == NULL) {
        PLUGIN_DEBUG(("malloc failed.\n"));
        return ENOMEM;
    }

    ret = snprintf(kdcinfo_name, len, KDCINFO_TMPL, realm);
    if (ret < 0) {
        PLUGIN_DEBUG(("snprintf failed"));
        ret = EINVAL;
    }
    kdcinfo_name[len] = '\0';

    fd = open(kdcinfo_name, O_RDONLY);
    if (fd == -1) {
        PLUGIN_DEBUG(("open failed [%d][%s].\n", errno, strerror(errno)));
        ret = errno;
        goto done;
    }

    len = BUFSIZE;
    p = buf;
    memset(buf, 0, BUFSIZE+1);
    while (len != 0 && (ret = read(fd, p, len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR) continue;
            PLUGIN_DEBUG(("read failed [%d][%s].\n", errno, strerror(errno)));
            close(fd);
            goto done;
        }

        len -= ret;
        p += ret;
    }
    close(fd);

    if (len == 0) {
        PLUGIN_DEBUG(("Content of kdcinfo file [%s] is [%d] or larger.\n",
                      kdcinfo_name, BUFSIZE));
    }
    PLUGIN_DEBUG(("Found kdcinfo [%s].\n", buf));

    ret = getaddrinfo((char *) buf, "kerberos", NULL, &ctx->sssd_kdc_addrinfo);
    if (ret != 0) {
        PLUGIN_DEBUG(("getaddrinfo failed [%d][%s].\n", ret,
                                                        gai_strerror(ret)));
        if (ret == EAI_SYSTEM) {
            PLUGIN_DEBUG(("getaddrinfo failed [%d][%s].\n", errno,
                                                            strerror(errno)));
        }
        goto done;
    }

    ctx->sssd_realm = strdup(realm);
    if (ctx->sssd_realm == NULL) {
        PLUGIN_DEBUG(("strdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }



done:
    free(kdcinfo_name);
    return ret;
}

krb5_error_code sssd_krb5_locator_init(krb5_context context,
                                       void **private_data)
{
    struct sssd_ctx *ctx;
    const char *dummy;

    ctx = calloc(1,sizeof(struct sssd_ctx));
    if (ctx == NULL) return ENOMEM;

    dummy = getenv(SSSD_KRB5_LOCATOR_DEBUG);
    if (dummy == NULL) {
        ctx->debug = false;
    } else {
        ctx->debug = true;
        PLUGIN_DEBUG(("sssd_krb5_locator_init called\n"));
    }

    *private_data = ctx;

    return 0;
}

void sssd_krb5_locator_close(void *private_data)
{
    struct sssd_ctx *ctx;

    if (private_data == NULL) return;

    ctx = (struct sssd_ctx *) private_data;
    PLUGIN_DEBUG(("sssd_krb5_locator_close called\n"));

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

    if (ctx->sssd_realm == NULL || strcmp(ctx->sssd_realm, realm) != 0) {
        freeaddrinfo(ctx->sssd_kdc_addrinfo);
        ctx->sssd_kdc_addrinfo = NULL;
        free(ctx->sssd_realm);
        ctx->sssd_realm = NULL;
        ret = get_kdcinfo(realm, ctx);
        if (ret != EOK) {
            PLUGIN_DEBUG(("get_kdcinfo failed.\n"));
            return KRB5_PLUGIN_NO_HANDLE;
        }
    }

    PLUGIN_DEBUG(("sssd_realm[%s] requested realm[%s] family[%d] socktype[%d] "
                  "locate_service[%d]\n", ctx->sssd_realm, realm, family,
                                          socktype, svc));

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
            PLUGIN_DEBUG(("getnameinfo failed [%d][%s].\n", ret,
                          gai_strerror(ret)));
            if (ret == EAI_SYSTEM) {
                PLUGIN_DEBUG(("getnameinfo failed [%d][%s].\n", errno,
                              strerror(errno)));
            }
        }
        PLUGIN_DEBUG(("addr[%s] family[%d] socktype[%d] - ", hostip,
                      ai->ai_family, ai->ai_socktype));

        if ((family == AF_UNSPEC || ai->ai_family == family) &&
            ai->ai_socktype == socktype) {

            ret = cbfunc(cbdata, socktype, ai->ai_addr);
            if (ret != 0) {
                PLUGIN_DEBUG(("\ncbfunc failed\n"));
            } else {
                PLUGIN_DEBUG(("used\n"));
            }
        } else {
            PLUGIN_DEBUG((" NOT used\n"));
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
