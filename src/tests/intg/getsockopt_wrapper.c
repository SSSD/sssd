/* gcc -Wall -fPIC -shared -o getsockopt_wrapper.so getsockopt_wrapper.c -ldl */

/* for RTLD_NEXT */
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

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

static bool peer_is_pam(int fd)
{
    int ret;
    struct sockaddr_storage addr = { 0 };
    socklen_t addrlen = sizeof(addr);
    struct sockaddr_un *unix_socket;

    ret = getpeername(fd, (struct sockaddr *)&addr, &addrlen);
    if (ret != 0) return false;

    if (addr.ss_family != AF_UNIX) return false;

    unix_socket = (struct sockaddr_un *)&addr;

    return NULL != strstr(unix_socket->sun_path, "pipes/pam");
}

static bool peer_is_sssctl(const struct ucred *cr)
{
    char proc_path[32];
    char cmd_line[255] = { 0 };
    int proc_fd;
    int ret;

    if (cr->pid < 0) {
        return false;
    }

    ret = snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline",
                   (int)cr->pid);
    if ((ret < 0) || (ret >= sizeof(proc_path))) {
        return false;
    }

    proc_fd = open(proc_path, O_RDONLY);
    if (proc_fd != -1) {
        ret = read(proc_fd, cmd_line, sizeof(cmd_line)-1);
        close(proc_fd);
        if (ret > 0) {
            cmd_line[ret] = 0;
            if (strncmp(cmd_line, "sssctl", 6) == 0) {
                return true;
            }
        }
    }

    return false;
}

static void fake_peer_uid_gid(uid_t *uid, gid_t *gid)
{
    char *val;

    val = getenv("SSSD_INTG_PEER_UID");
    if (val != NULL) {
        *uid = atoi(val);
    }

    val = getenv("SSSD_INTG_PEER_GID");
    if (val != NULL) {
        *gid = atoi(val);
    }
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
        } else if (peer_is_pam(sockfd) || peer_is_sssctl(cr)) {
            fake_peer_uid_gid(&cr->uid, &cr->gid);
        }
    }

    return ret;
}
