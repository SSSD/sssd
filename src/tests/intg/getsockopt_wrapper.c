/* gcc -Wall -fPIC -shared -o getsockopt_wrapper.so getsockopt_wrapper.c -ldl */

/* for RTLD_NEXT */
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>

static bool is_dbus_socket(int fd)
{
    int ret;
    struct sockaddr_storage addr = { 0 };
    socklen_t addrlen = sizeof(addr);
    struct sockaddr_un *unix_socket;

    ret = getsockname(fd, (struct sockaddr *)&addr, &addrlen);
    if (ret != 0) return false;

    if (addr.ss_family != AF_UNIX) return false;

    unix_socket = (struct sockaddr_un *)&addr;

    return NULL != strstr(unix_socket->sun_path, "system_bus_socket");
}

static bool is_secrets_socket(int fd)
{
    int ret;
    struct sockaddr_storage addr = { 0 };
    socklen_t addrlen = sizeof(addr);
    struct sockaddr_un *unix_socket;

    ret = getsockname(fd, (struct sockaddr *)&addr, &addrlen);
    if (ret != 0) return false;

    if (addr.ss_family != AF_UNIX) return false;

    unix_socket = (struct sockaddr_un *)&addr;

    return NULL != strstr(unix_socket->sun_path, "secrets.socket");
}

static uid_t fake_secret_peer(uid_t orig_id)
{
    char *val;

    val = getenv("SSSD_INTG_SECRETS_PEER");
    if (val == NULL) {
        return orig_id;
    }

    return atoi(val);
}

typedef typeof(getsockopt) getsockopt_fn_t;

static getsockopt_fn_t *orig_getsockopt = NULL;

int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen)
{
    int ret;
#ifdef __OpenBSD__
    struct sockpeercred *cr;
#else
    struct ucred *cr;
#endif

    if (orig_getsockopt == NULL) {
        orig_getsockopt = (getsockopt_fn_t *)dlsym(RTLD_NEXT, "getsockopt");
    }

    ret = orig_getsockopt(sockfd, level, optname, optval, optlen);

    if (ret == 0 && level == SOL_SOCKET && optname == SO_PEERCRED
            && *optlen == sizeof(*cr)) {
        cr = optval;
        if (cr->uid != 0 && is_dbus_socket(sockfd)) {
            cr->uid = 0;
        } else if (is_secrets_socket(sockfd)) {
            cr->uid = fake_secret_peer(cr->uid);
        }
    }

    return ret;
}
