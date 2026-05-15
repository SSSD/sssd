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

#include "util/sss_krb5.h"
#include <krb5/locate_plugin.h>

#include "providers/krb5/krb5_common.h"

/* The following override of KDCINFO_TMPL and KPASSWDINFO_TMPL is not very
 * elegant but since they are defined in krb5_common.h with the help of
 * PUBCONF_PATH from config.h and PUBCONF_PATH can by set by a configure
 * options I didn't found another way to change the path for a unit test. */
#ifdef TEST_PUBCONF_PATH
#ifdef KDCINFO_TMPL
#undef KDCINFO_TMPL
#endif
#define KDCINFO_TMPL TEST_PUBCONF_PATH"/kdcinfo.%s"

#ifdef KPASSWDINFO_TMPL
#undef KPASSWDINFO_TMPL
#endif
#define KPASSWDINFO_TMPL TEST_PUBCONF_PATH"/kpasswdinfo.%s"
#endif /* TEST_PUBCONF_PATH */

#define DEFAULT_KERBEROS_PORT 88
#define DEFAULT_KADMIN_PORT 749
#define DEFAULT_KPASSWD_PORT 464

#define BUFSIZE 4096
#define PORT_STR_SIZE 7
#define SSSD_KRB5_LOCATOR_DEBUG "SSSD_KRB5_LOCATOR_DEBUG"
#define SSSD_KRB5_LOCATOR_DISABLE "SSSD_KRB5_LOCATOR_DISABLE"
#define SSSD_KRB5_LOCATOR_IGNORE_DNS_FAILURES "SSSD_KRB5_LOCATOR_IGNORE_DNS_FAILURES"
#define DEBUG_KEY "[sssd_krb5_locator] "
#define PLUGIN_DEBUG(format, ...) do { \
    if (ctx->debug) { \
        plugin_debug_fn(format, ##__VA_ARGS__); \
    } \
} while(0)

struct addr_port {
    char *addr;
    uint16_t port;
};

struct sssd_ctx {
    char *sssd_realm;
    struct addr_port *kdc_addr;
    struct addr_port *kpasswd_addr;
    bool debug;
    bool disabled;
    bool kpasswdinfo_used;
    bool ignore_dns_failure;
};

#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
__attribute__((format(printf, 1, 2)))
#endif
static void plugin_debug_fn(const char *format, ...)
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


static void free_addr_port_list(struct addr_port **list)
{
    size_t c;

    if (list == NULL || *list == NULL) {
        return;
    }

    for (c = 0; (*list)[c].addr != NULL; c++) {
        free((*list)[c].addr);
    }
    free(*list);
    *list = NULL;
}

static int copy_addr_port_list(struct addr_port *src, bool clear_port,
                               struct addr_port **dst)
{
    size_t c;
    struct addr_port *d = NULL;
    int ret;

    /* only copy if dst is initialized to NULL */
    if (dst == NULL || *dst != NULL) {
        return EINVAL;
    }

    if (src == NULL) {
        return 0;
    }

    for (c = 0; src[c].addr != NULL; c++);

    d = calloc((c + 1), sizeof(struct addr_port));
    if (d == NULL) {
        return ENOMEM;
    }

    for (c = 0; src[c].addr != NULL; c++) {
        d[c].addr = strdup(src[c].addr);
        if (d[c].addr == NULL) {
            ret = ENOMEM;
            goto done;
        }
        if (clear_port) {
            d[c].port = 0;
        } else {
            d[c].port = src[c].port;
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        free_addr_port_list(&d);
    } else {
        *dst = d;
    }

    return ret;
}

static int buf_to_addr_port_list(struct sssd_ctx *ctx,
                                 uint8_t *buf, size_t buf_size,
                                 struct addr_port **list)
{
    struct addr_port *l = NULL;
    int ret;
    uint8_t *p;
    uint8_t *pn;
    size_t c;
    size_t len;
    size_t addr_len;
    char *addr_str = NULL;
    char *tmp = NULL;
    char *port_str;
    long port;
    char *endptr;

    /* only create if list is initialized to NULL */
    if (buf == NULL || buf_size == 0 || list == NULL || *list != NULL) {
        return EINVAL;
    }

    c = 1; /* to account for a missing \n at the very end */
    p = buf;
    while ((p - buf) < buf_size
                && (p = memchr(p, '\n', buf_size - (p - buf))) != NULL) {
        p++;
        c++;
    }

    l = calloc((c + 1), sizeof(struct addr_port));
    if (l == NULL) {
        return ENOMEM;
    }

    c = 0;
    p = buf;
    do {
        pn = memchr(p, '\n', buf_size - (p - buf));
        if (pn != NULL) {
            len = pn - p;
        } else {
            len = buf_size - (p - buf);
        }
        if (len == 0) {
            /* empty line no more processing */
            break;
        }

        free(tmp);
        tmp = strndup((char *) p, len);
        if (tmp == NULL) {
            ret = ENOMEM;
            goto done;
        }

        port_str = strrchr(tmp, ':');
        if (port_str == NULL) {
            port = 0;
        } else if (tmp[0] == '[' && *(port_str - 1) != ']') {
            /* IPv6 address without port number */
            port = 0;
        } else {
            *port_str = '\0';
            ++port_str;

            if (isdigit(*port_str)) {
                errno = 0;
                port = strtol(port_str, &endptr, 10);
                if (errno != 0) {
                    ret = errno;
                    PLUGIN_DEBUG("strtol failed on [%s]: [%d][%s], "
                                 "assuming default.\n",
                                 port_str, ret, strerror(ret));
                    port = 0;
                }
                if (*endptr != '\0') {
                    PLUGIN_DEBUG("Found additional characters [%s] in port "
                                 "number [%s], assuming default.\n",
                                 endptr, port_str);
                    port = 0;
                }

                if (port < 0 || port > 65535) {
                    PLUGIN_DEBUG("Illegal port number [%ld], assuming "
                                 "default.\n", port);
                    port = 0;
                }
            } else {
                PLUGIN_DEBUG("Illegal port number [%s], assuming default.\n",
                             port_str);
                port = 0;
            }
        }

        /* make sure tmp is not modified so that it can be freed later */
        addr_str = tmp;
        /* strip leading '[' and trailing ']' from IPv6 addresses */
        if (addr_str[0] == '['
                && (addr_len = strlen(addr_str))
                && addr_str[addr_len - 1] == ']') {
            addr_str[addr_len -1] = '\0';
            addr_str++;
        }

        PLUGIN_DEBUG("Found [%s][%ld].\n", addr_str, port);

        l[c].addr = strdup(addr_str);
        if (l[c].addr == NULL) {
            ret = ENOMEM;
            goto done;
        }
        l[c].port = port;

        c++;
        p = pn == NULL ? NULL : (pn + 1);
    } while (p != NULL);

    ret = EOK;

done:
    free(tmp);
    if (ret != EOK) {
        free_addr_port_list(&l);
    } else {
        *list = l;
    }

    return ret;
}

static int get_krb5info(const char *realm, struct sssd_ctx *ctx,
                        enum locate_service_type svc)
{
    int ret;
    char *krb5info_name = NULL;
    size_t len;
    uint8_t buf[BUFSIZE + 1];
    int fd = -1;
    const char *name_tmpl = NULL;

    switch (svc) {
        case locate_service_kdc:
            name_tmpl = KDCINFO_TMPL;
            break;
        case locate_service_kpasswd:
            name_tmpl = KPASSWDINFO_TMPL;
            break;
        default:
            PLUGIN_DEBUG("Unsupported service [%d].\n", svc);
            return EINVAL;
    }


    len = strlen(realm) + strlen(name_tmpl);

    krb5info_name = calloc(1, len + 1);
    if (krb5info_name == NULL) {
        PLUGIN_DEBUG("calloc failed.\n");
        return ENOMEM;
    }

    ret = snprintf(krb5info_name, len, name_tmpl, realm);
    if (ret < 0) {
        PLUGIN_DEBUG("snprintf failed.\n");
        ret = EINVAL;
        goto done;
    }
    krb5info_name[len] = '\0';

    fd = open(krb5info_name, O_RDONLY);
    if (fd == -1) {
        ret = errno;
        PLUGIN_DEBUG("open failed [%s][%d][%s].\n",
                     krb5info_name, ret, strerror(ret));
        goto done;
    }

    memset(buf, 0, BUFSIZE+1);

    errno = 0;
    len = sss_atomic_read_s(fd, buf, BUFSIZE);
    if (len == -1) {
        ret = errno;
        PLUGIN_DEBUG("read failed [%d][%s].\n", ret, strerror(ret));
        close(fd);
        goto done;
    }
    close(fd);

    if (len == BUFSIZE) {
        PLUGIN_DEBUG("Content of krb5info file [%s] is [%d] or larger.\n",
                     krb5info_name, BUFSIZE);
    }

    switch (svc) {
        case locate_service_kdc:
            free_addr_port_list(&(ctx->kdc_addr));
            ret = buf_to_addr_port_list(ctx, buf, len, &(ctx->kdc_addr));
            if (ret != EOK) {
                goto done;
            }
            break;
        case locate_service_kpasswd:
            free_addr_port_list(&(ctx->kpasswd_addr));
            ret = buf_to_addr_port_list(ctx, buf, len, &(ctx->kpasswd_addr));
            if (ret != EOK) {
                goto done;
            }
            break;
        default:
            PLUGIN_DEBUG("Unsupported service [%d].\n", svc);
            ret = EINVAL;
            goto done;
    }

    ret = 0;
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
        PLUGIN_DEBUG("sssd_krb5_locator_init called\n");
    }

    dummy = getenv(SSSD_KRB5_LOCATOR_DISABLE);
    if (dummy == NULL) {
        ctx->disabled = false;
    } else {
        ctx->disabled = true;
        PLUGIN_DEBUG("SSSD KRB5 locator plugin is disabled.\n");
    }

    ctx->kpasswdinfo_used = false;

    dummy = getenv(SSSD_KRB5_LOCATOR_IGNORE_DNS_FAILURES);
    if (dummy == NULL) {
        ctx->ignore_dns_failure = false;
    } else {
        ctx->ignore_dns_failure = true;
        PLUGIN_DEBUG("SSSD KRB5 locator plugin ignores DNS resolving errors.\n");
    }

    *private_data = ctx;

    return 0;
}

void sssd_krb5_locator_close(void *private_data)
{
    struct sssd_ctx *ctx;

    if (private_data == NULL) return;

    ctx = (struct sssd_ctx *) private_data;
    PLUGIN_DEBUG("sssd_krb5_locator_close called\n");

    free_addr_port_list(&(ctx->kdc_addr));
    free_addr_port_list(&(ctx->kpasswd_addr));
    free(ctx->sssd_realm);
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
    struct addrinfo *ai, *ai_item;
    struct sssd_ctx *ctx;
    struct addrinfo ai_hints;
    uint16_t port = 0;
    uint16_t default_port = 0;
    struct addr_port *addr = NULL;
    char port_str[PORT_STR_SIZE];
    size_t c;
    bool force_port = false;
    char address[NI_MAXHOST];

    if (private_data == NULL) return KRB5_PLUGIN_NO_HANDLE;
    ctx = (struct sssd_ctx *) private_data;

    if (realm == NULL || cbfunc == NULL || cbdata == NULL) {
        return KRB5_PLUGIN_NO_HANDLE;
    }

    if (ctx->disabled) {
        PLUGIN_DEBUG("Plugin disabled, nothing to do.\n");
        return KRB5_PLUGIN_NO_HANDLE;
    }

    if (ctx->sssd_realm == NULL || strcmp(ctx->sssd_realm, realm) != 0) {
        free(ctx->sssd_realm);
        ctx->sssd_realm = strdup(realm);
        if (ctx->sssd_realm == NULL) {
            PLUGIN_DEBUG("strdup failed.\n");
            return KRB5_PLUGIN_NO_HANDLE;
        }

        ret = get_krb5info(realm, ctx, locate_service_kdc);
        if (ret != EOK) {
            PLUGIN_DEBUG("get_krb5info failed.\n");
            return KRB5_PLUGIN_NO_HANDLE;
        }

    }

    if (ctx->kpasswd_addr == NULL
            && (svc == locate_service_kadmin || svc == locate_service_kpasswd ||
                svc == locate_service_master_kdc)) {
        ret = get_krb5info(realm, ctx, locate_service_kpasswd);
        if (ret != EOK) {
            PLUGIN_DEBUG("reading kpasswd address failed, "
                         "using kdc address.\n");
            free_addr_port_list(&(ctx->kpasswd_addr));
            ret = copy_addr_port_list(ctx->kdc_addr, true,
                                      &(ctx->kpasswd_addr));
            if (ret != EOK) {
                PLUGIN_DEBUG("copying address list failed.\n");
                return KRB5_PLUGIN_NO_HANDLE;
            }
        } else {
            ctx->kpasswdinfo_used = true;
        }
    }

    PLUGIN_DEBUG("sssd_realm[%s] requested realm[%s] family[%d] socktype[%d] "
                 "locate_service[%d]\n",
                 ctx->sssd_realm, realm, family, socktype, svc);

    switch (svc) {
        case locate_service_kdc:
            addr = ctx->kdc_addr;
            default_port = DEFAULT_KERBEROS_PORT;
            break;
        case locate_service_master_kdc:
            addr = ctx->kpasswd_addr;
            default_port = DEFAULT_KERBEROS_PORT;
            if (ctx->kpasswdinfo_used) {
                /* Use default port if the addresses from the kpasswdinfo
                 * files are used because the port numbers from the file will
                 * most probably not be suitable. */
                force_port = true;
            }
            break;
        case locate_service_kadmin:
            addr = ctx->kpasswd_addr;
            default_port = DEFAULT_KADMIN_PORT;
            break;
        case locate_service_kpasswd:
            addr = ctx->kpasswd_addr;
            default_port = DEFAULT_KPASSWD_PORT;
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

    if (strcmp(realm, ctx->sssd_realm) != 0 || addr == NULL) {
        return KRB5_PLUGIN_NO_HANDLE;
    }

    for (c = 0; addr[c].addr != NULL; c++) {
        port = ((addr[c].port == 0 || force_port) ? default_port
                                                  : addr[c].port);
        memset(port_str, 0, PORT_STR_SIZE);
        ret = snprintf(port_str, PORT_STR_SIZE-1, "%u", port);
        if (ret < 0 || ret >= (PORT_STR_SIZE-1)) {
            PLUGIN_DEBUG("snprintf failed.\n");
            return KRB5_PLUGIN_NO_HANDLE;
        }

        memset(&ai_hints, 0, sizeof(struct addrinfo));
        ai_hints.ai_flags = AI_NUMERICSERV;
        ai_hints.ai_socktype = socktype;

        ret = getaddrinfo(addr[c].addr, port_str, &ai_hints, &ai);
        if (ret != 0) {
            PLUGIN_DEBUG("getaddrinfo failed [%d][%s].\n",
                         ret, gai_strerror(ret));
            if (ret == EAI_SYSTEM) {
                PLUGIN_DEBUG("getaddrinfo failed [%d][%s].\n",
                             errno, strerror(errno));
            }

            if (ctx->ignore_dns_failure) {
                continue;
            }

            return KRB5_PLUGIN_NO_HANDLE;
        }

        for (ai_item = ai; ai_item != NULL; ai_item = ai_item->ai_next) {
            if (ctx->debug) {
                ret = getnameinfo(ai_item->ai_addr, ai_item->ai_addrlen,
                                  address, NI_MAXHOST,
                                  NULL, 0,
                                  NI_NUMERICHOST);
                if (ret != 0) {
                    address[0] = 0;
                }

                PLUGIN_DEBUG("addr[%s (%s)] port[%s] family[%d] socktype[%d]\n",
                             addr[c].addr, address,
                             port_str, ai_item->ai_family,
                             ai_item->ai_socktype);
            }

            if ((family == AF_UNSPEC || ai_item->ai_family == family) &&
                ai_item->ai_socktype == socktype) {

                ret = cbfunc(cbdata, socktype, ai_item->ai_addr);
                if (ret != 0) {
                    PLUGIN_DEBUG("cbfunc failed\n");
                    freeaddrinfo(ai);
                    return ret;
                } else {
                    PLUGIN_DEBUG("[%s (%s)] used\n", addr[c].addr, address);
                }
            } else {
                PLUGIN_DEBUG("[%s (%s)] NOT used\n", addr[c].addr, address);
            }
        }
        freeaddrinfo(ai);
    }

    return 0;
}

const krb5plugin_service_locate_ftable service_locator = {
    0, /* version */
    sssd_krb5_locator_init,
    sssd_krb5_locator_close,
    sssd_krb5_locator_lookup,
};
