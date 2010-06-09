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
#include <ctype.h>

#include <krb5/locate_plugin.h>

#include "providers/krb5/krb5_common.h"

#define DEFAULT_KERBEROS_PORT 88
#define DEFAULT_KADMIN_PORT 749
#define DEFAULT_KPASSWD_PORT 464

#define BUFSIZE 512
#define PORT_STR_SIZE 7
#define SSSD_KRB5_LOCATOR_DEBUG "SSSD_KRB5_LOCATOR_DEBUG"
#define DEBUG_KEY "[sssd_krb5_locator] "
#define PLUGIN_DEBUG(body) do { \
    if (ctx->debug) { \
        debug_fn body; \
    } \
} while(0);

struct sssd_ctx {
    char *sssd_realm;
    char *kdc_addr;
    uint16_t kdc_port;
    char *kpasswd_addr;
    uint16_t kpasswd_port;
    bool debug;
};

void debug_fn(const char *format, ...)
{
    va_list ap;
    char *s = NULL;
    int ret;

    va_start(ap, format);

    ret = vasprintf(&s, format, ap);
    va_end(ap);
    if (ret < 0) {
        /* ENOMEM */
        return;
    }

    fprintf(stderr, DEBUG_KEY "%s", s);
    free(s);
}

static int get_krb5info(const char *realm, struct sssd_ctx *ctx,
                        enum locate_service_type svc)
{
    int ret;
    char *krb5info_name = NULL;
    size_t len;
    uint8_t buf[BUFSIZE + 1];
    uint8_t *p;
    int fd = -1;
    const char *name_tmpl = NULL;
    char *port_str;
    long port;
    char *endptr;

    switch (svc) {
        case locate_service_kdc:
            name_tmpl = KDCINFO_TMPL;
            break;
        case locate_service_kpasswd:
            name_tmpl = KPASSWDINFO_TMPL;
            break;
        default:
            PLUGIN_DEBUG(("Unsupported service [%d].\n", svc));
            return EINVAL;
    }


    len = strlen(realm) + strlen(name_tmpl);

    krb5info_name = calloc(1, len + 1);
    if (krb5info_name == NULL) {
        PLUGIN_DEBUG(("malloc failed.\n"));
        return ENOMEM;
    }

    ret = snprintf(krb5info_name, len, name_tmpl, realm);
    if (ret < 0) {
        PLUGIN_DEBUG(("snprintf failed.\n"));
        ret = EINVAL;
        goto done;
    }
    krb5info_name[len] = '\0';

    fd = open(krb5info_name, O_RDONLY);
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
            if (errno == EINTR || errno == EAGAIN) continue;
            PLUGIN_DEBUG(("read failed [%d][%s].\n", errno, strerror(errno)));
            close(fd);
            goto done;
        }

        len -= ret;
        p += ret;
    }
    close(fd);

    if (len == 0) {
        PLUGIN_DEBUG(("Content of krb5info file [%s] is [%d] or larger.\n",
                      krb5info_name, BUFSIZE));
    }
    PLUGIN_DEBUG(("Found [%s] in [%s].\n", buf, krb5info_name));

    port_str = strrchr((char *) buf, ':');
    if (port_str == NULL) {
        port = 0;
    } else {
        *port_str = '\0';
        ++port_str;

        if (isdigit(*port_str)) {
            errno = 0;
            port = strtol(port_str, &endptr, 10);
            if (errno != 0) {
                ret = errno;
                PLUGIN_DEBUG(("strtol failed on [%s]: [%d][%s], "
                            "assuming default.\n", port_str, ret, strerror(ret)));
                port = 0;
            }
            if (*endptr != '\0') {
                PLUGIN_DEBUG(("Found additional characters [%s] in port number "
                            "[%s], assuming default.\n", endptr, port_str));
                port = 0;
            }

            if (port < 0 || port > 65535) {
                PLUGIN_DEBUG(("Illegal port number [%d], assuming default.\n",
                            port));
                port = 0;
            }
        } else {
            PLUGIN_DEBUG(("Illegal port number [%s], assuming default.\n",
                        port_str));
            port = 0;
        }
    }

    switch (svc) {
        case locate_service_kdc:
            free(ctx->kdc_addr);
            ctx->kdc_addr = strdup((char *) buf);
            if (ctx->kdc_addr == NULL) {
                PLUGIN_DEBUG(("strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
            ctx->kdc_port = (uint16_t) port;
            break;
        case locate_service_kpasswd:
            free(ctx->kpasswd_addr);
            ctx->kpasswd_addr = strdup((char *) buf);
            if (ctx->kpasswd_addr == NULL) {
                PLUGIN_DEBUG(("strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
            ctx->kpasswd_port = (uint16_t) port;
            break;
        default:
            PLUGIN_DEBUG(("Unsupported service [%d].\n", svc));
            ret = EINVAL;
            goto done;
    }

done:
    free(krb5info_name);
    return ret;
}

krb5_error_code sssd_krb5_locator_init(krb5_context context,
                                       void **private_data)
{
    struct sssd_ctx *ctx;
    const char *dummy;

    ctx = calloc(1,sizeof(struct sssd_ctx));
    if (ctx == NULL) return KRB5_PLUGIN_NO_HANDLE;

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

    free(ctx->kdc_addr);
    free(ctx->kpasswd_addr);
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
    struct addrinfo ai_hints;
    uint16_t port = 0;
    const char *addr = NULL;
    char port_str[PORT_STR_SIZE];

    if (private_data == NULL) return KRB5_PLUGIN_NO_HANDLE;
    ctx = (struct sssd_ctx *) private_data;

    if (ctx->sssd_realm == NULL || strcmp(ctx->sssd_realm, realm) != 0) {
        free(ctx->sssd_realm);
        ctx->sssd_realm = strdup(realm);
        if (ctx->sssd_realm == NULL) {
            PLUGIN_DEBUG(("strdup failed.\n"));
            return KRB5_PLUGIN_NO_HANDLE;
        }

        ret = get_krb5info(realm, ctx, locate_service_kdc);
        if (ret != EOK) {
            PLUGIN_DEBUG(("get_krb5info failed.\n"));
            return KRB5_PLUGIN_NO_HANDLE;
        }

        if (svc == locate_service_kadmin || svc == locate_service_kpasswd ||
            svc == locate_service_master_kdc) {
            ret = get_krb5info(realm, ctx, locate_service_kpasswd);
            if (ret != EOK) {
                PLUGIN_DEBUG(("reading kpasswd address failed, "
                              "using kdc address.\n"));
                free(ctx->kpasswd_addr);
                ctx->kpasswd_addr = strdup(ctx->kdc_addr);
                ctx->kpasswd_port = 0;
            }
        }
    }

    PLUGIN_DEBUG(("sssd_realm[%s] requested realm[%s] family[%d] socktype[%d] "
                  "locate_service[%d]\n", ctx->sssd_realm, realm, family,
                                          socktype, svc));

    switch (svc) {
        case locate_service_kdc:
            addr = ctx->kdc_addr;
            port = ctx->kdc_port ? ctx->kdc_port : DEFAULT_KERBEROS_PORT;
            break;
        case locate_service_master_kdc:
            addr = ctx->kpasswd_addr;
            port = DEFAULT_KERBEROS_PORT;
            break;
        case locate_service_kadmin:
            addr = ctx->kpasswd_addr;
            port = DEFAULT_KADMIN_PORT;
            break;
        case locate_service_kpasswd:
            addr = ctx->kpasswd_addr;
            port = ctx->kpasswd_port ? ctx->kpasswd_port : DEFAULT_KPASSWD_PORT;
            break;
        case locate_service_krb524:
            return KRB5_PLUGIN_NO_HANDLE;
        default:
            return KRB5_PLUGIN_NO_HANDLE;
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
            return KRB5_PLUGIN_NO_HANDLE;
    }

    if (strcmp(realm, ctx->sssd_realm) != 0)
        return KRB5_PLUGIN_NO_HANDLE;

    memset(port_str, 0, PORT_STR_SIZE);
    ret = snprintf(port_str, PORT_STR_SIZE-1, "%u", port);
    if (ret < 0 || ret >= (PORT_STR_SIZE-1)) {
        PLUGIN_DEBUG(("snprintf failed.\n"));
        return KRB5_PLUGIN_NO_HANDLE;
    }

    memset(&ai_hints, 0, sizeof(struct addrinfo));
    ai_hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
    ai_hints.ai_socktype = socktype;

    ret = getaddrinfo(addr, port_str, &ai_hints, &ai);
    if (ret != 0) {
        PLUGIN_DEBUG(("getaddrinfo failed [%d][%s].\n", ret,
                                                        gai_strerror(ret)));
        if (ret == EAI_SYSTEM) {
            PLUGIN_DEBUG(("getaddrinfo failed [%d][%s].\n", errno,
                                                            strerror(errno)));
        }
        return KRB5_PLUGIN_NO_HANDLE;
    }

    PLUGIN_DEBUG(("addr[%s:%s] family[%d] socktype[%d]\n", addr, port_str,
                 ai->ai_family, ai->ai_socktype));

    if ((family == AF_UNSPEC || ai->ai_family == family) &&
        ai->ai_socktype == socktype) {

        ret = cbfunc(cbdata, socktype, ai->ai_addr);
        if (ret != 0) {
            PLUGIN_DEBUG(("cbfunc failed\n"));
            return ret;
        } else {
            PLUGIN_DEBUG(("[%s] used\n", addr));
        }
    } else {
        PLUGIN_DEBUG(("[%s] NOT used\n", addr));
    }

    return 0;
}

const krb5plugin_service_locate_ftable service_locator = {
    0, /* version */
    sssd_krb5_locator_init,
    sssd_krb5_locator_close,
    sssd_krb5_locator_lookup,
};
