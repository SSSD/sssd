/*
 * System Security Services Daemon. NSS client interface
 *
 * Copyright (C) Simo Sorce 2007
 *
 * Winbind derived code:
 * Copyright (C) Tim Potter 2000
 * Copyright (C) Andrew Tridgell 2000
 * Copyright (C) Andrew Bartlett 2002
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <nss.h>
#include <security/pam_modules.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include <libintl.h>
#define _(STRING) dgettext (PACKAGE, STRING)
#include "sss_cli.h"
#include "common_private.h"
#include "util/util_errors.h"

#if HAVE_PTHREAD
#include <pthread.h>
#endif

/*
* Note we set MSG_NOSIGNAL to avoid
* having to fiddle with signal masks
* but also do not want to die in case
* SIGPIPE gets raised and the application
* does not handle it.
*/
#ifdef MSG_NOSIGNAL
#define SSS_DEFAULT_WRITE_FLAGS MSG_NOSIGNAL
#else
#define SSS_DEFAULT_WRITE_FLAGS 0
#endif

/* common functions */

static int sss_cli_sd = -1; /* the sss client socket descriptor */
static struct stat sss_cli_sb; /* the sss client stat buffer */

#if HAVE_FUNCTION_ATTRIBUTE_DESTRUCTOR
__attribute__((destructor))
#endif
static void sss_cli_close_socket(void)
{
    if (sss_cli_sd != -1) {
        close(sss_cli_sd);
        sss_cli_sd = -1;
    }
}

/* Requests:
 *
 * byte 0-3: 32bit unsigned with length (the complete packet length: 0 to X)
 * byte 4-7: 32bit unsigned with command code
 * byte 8-11: 32bit unsigned (reserved)
 * byte 12-15: 32bit unsigned (reserved)
 * byte 16-X: (optional) request structure associated to the command code used
 */
static enum sss_status sss_cli_send_req(enum sss_cli_command cmd,
                                        struct sss_cli_req_data *rd,
                                        int timeout,
                                        int *errnop)
{
    uint32_t header[4];
    size_t datasent;

    header[0] = SSS_NSS_HEADER_SIZE + (rd?rd->len:0);
    header[1] = cmd;
    header[2] = 0;
    header[3] = 0;

    datasent = 0;

    while (datasent < header[0]) {
        struct pollfd pfd;
        int rdsent;
        int res, error;

        *errnop = 0;
        pfd.fd = sss_cli_sd;
        pfd.events = POLLOUT;

        do {
            errno = 0;
            res = poll(&pfd, 1, timeout);
            error = errno;

            /* If error is EINTR here, we'll try again
             * If it's any other error, we'll catch it
             * below.
             */
        } while (error == EINTR);

        switch (res) {
        case -1:
            *errnop = error;
            break;
        case 0:
            *errnop = ETIME;
            break;
        case 1:
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                *errnop = EPIPE;
            }
            if (!(pfd.revents & POLLOUT)) {
                *errnop = EBUSY;
            }
            break;
        default: /* more than one available!? */
            *errnop = EBADF;
            break;
        }
        if (*errnop) {
            sss_cli_close_socket();
            return SSS_STATUS_UNAVAIL;
        }

        errno = 0;
        if (datasent < SSS_NSS_HEADER_SIZE) {
            res = send(sss_cli_sd,
                       (char *)header + datasent,
                       SSS_NSS_HEADER_SIZE - datasent,
                       SSS_DEFAULT_WRITE_FLAGS);
        } else {
            rdsent = datasent - SSS_NSS_HEADER_SIZE;
            res = send(sss_cli_sd,
                       (const char *)rd->data + rdsent,
                       rd->len - rdsent,
                       SSS_DEFAULT_WRITE_FLAGS);
        }
        error = errno;

        if ((res == -1) || (res == 0)) {
            if ((error == EINTR) || error == EAGAIN) {
                /* If the write was interrupted, go back through
                 * the loop and try again
                 */
                continue;
            }

            /* Write failed */
            sss_cli_close_socket();
            *errnop = error;
            return SSS_STATUS_UNAVAIL;
        }

        datasent += res;
    }

    return SSS_STATUS_SUCCESS;
}

/* Replies:
 *
 * byte 0-3: 32bit unsigned with length (the complete packet length: 0 to X)
 * byte 4-7: 32bit unsigned with command code
 * byte 8-11: 32bit unsigned with the request status (server errno)
 * byte 12-15: 32bit unsigned (reserved)
 * byte 16-X: (optional) reply structure associated to the command code used
 */

static enum sss_status sss_cli_recv_rep(enum sss_cli_command cmd,
                                        int timeout,
                                        uint8_t **_buf, int *_len,
                                        int *errnop)
{
    uint32_t header[4];
    size_t datarecv;
    uint8_t *buf = NULL;
    bool pollhup = false;
    int len;
    int ret;

    header[0] = SSS_NSS_HEADER_SIZE; /* until we know the real length */
    header[1] = 0;
    header[2] = 0;
    header[3] = 0;

    datarecv = 0;
    buf = NULL;
    len = 0;
    *errnop = 0;

    while (datarecv < header[0]) {
        struct pollfd pfd;
        int bufrecv;
        int res, error;

        pfd.fd = sss_cli_sd;
        pfd.events = POLLIN;

        do {
            errno = 0;
            res = poll(&pfd, 1, timeout);
            error = errno;

            /* If error is EINTR here, we'll try again
             * If it's any other error, we'll catch it
             * below.
             */
        } while (error == EINTR);

        switch (res) {
        case -1:
            *errnop = error;
            break;
        case 0:
            *errnop = ETIME;
            break;
        case 1:
            if (pfd.revents & (POLLHUP)) {
                pollhup = true;
            }
            if (pfd.revents & (POLLERR | POLLNVAL)) {
                *errnop = EPIPE;
            }
            if (!(pfd.revents & POLLIN)) {
                *errnop = EBUSY;
            }
            break;
        default: /* more than one available!? */
            *errnop = EBADF;
            break;
        }
        if (*errnop) {
            sss_cli_close_socket();
            ret = SSS_STATUS_UNAVAIL;
            goto failed;
        }

        errno = 0;
        if (datarecv < SSS_NSS_HEADER_SIZE) {
            res = read(sss_cli_sd,
                       (char *)header + datarecv,
                       SSS_NSS_HEADER_SIZE - datarecv);
        } else {
            bufrecv = datarecv - SSS_NSS_HEADER_SIZE;
            res = read(sss_cli_sd,
                       (char *) buf + bufrecv,
                       header[0] - datarecv);
        }
        error = errno;

        if ((res == -1) || (res == 0)) {
            if ((error == EINTR) || error == EAGAIN) {
                /* If the read was interrupted, go back through
                 * the loop and try again
                 */
                continue;
            }

            /* Read failed.  I think the only useful thing
             * we can do here is just return -1 and fail
             * since the transaction has failed half way
             * through. */

            sss_cli_close_socket();
            *errnop = error;
            ret = SSS_STATUS_UNAVAIL;
            goto failed;
        }

        datarecv += res;

        if (datarecv == SSS_NSS_HEADER_SIZE && len == 0) {
            /* at this point recv buf is not yet
             * allocated and the header has just
             * been read, do checks and proceed */
            if (header[2] != 0) {
                /* server side error */
                sss_cli_close_socket();
                *errnop = header[2];
                if (*errnop == EAGAIN) {
                    ret = SSS_STATUS_TRYAGAIN;
                    goto failed;
                } else {
                    ret = SSS_STATUS_UNAVAIL;
                    goto failed;
                }
            }
            if (header[1] != cmd) {
                /* wrong command id */
                sss_cli_close_socket();
                *errnop = EBADMSG;
                ret = SSS_STATUS_UNAVAIL;
                goto failed;
            }
            if (header[0] > SSS_NSS_HEADER_SIZE) {
                len = header[0] - SSS_NSS_HEADER_SIZE;
                buf = malloc(len);
                if (!buf) {
                    sss_cli_close_socket();
                    *errnop = ENOMEM;
                    ret = SSS_STATUS_UNAVAIL;
                    goto failed;
                }
            }
        }
    }

    if (pollhup) {
        sss_cli_close_socket();
    }

    *_len = len;
    *_buf = buf;

    return SSS_STATUS_SUCCESS;

failed:
    free(buf);
    return ret;
}

/* this function will check command codes match and returned length is ok */
/* repbuf and replen report only the data section not the header */
static enum sss_status sss_cli_make_request_nochecks(
                                       enum sss_cli_command cmd,
                                       struct sss_cli_req_data *rd,
                                       int timeout,
                                       uint8_t **repbuf, size_t *replen,
                                       int *errnop)
{
    enum sss_status ret;
    uint8_t *buf = NULL;
    int len = 0;

    /* send data */
    ret = sss_cli_send_req(cmd, rd, timeout, errnop);
    if (ret != SSS_STATUS_SUCCESS) {
        return ret;
    }

    /* data sent, now get reply */
    ret = sss_cli_recv_rep(cmd, timeout, &buf, &len, errnop);
    if (ret != SSS_STATUS_SUCCESS) {
        return ret;
    }

    /* we got through, now we have the custom data in buf if any,
     * return it if requested */
    if (repbuf && buf) {
        *repbuf = buf;
        if (replen) {
            *replen = len;
        }
    } else {
        free(buf);
        if (replen) {
            *replen = 0;
        }
    }

    return SSS_STATUS_SUCCESS;
}

/* GET_VERSION Reply:
 * 0-3: 32bit unsigned version number
 */

static bool sss_cli_check_version(const char *socket_name, int timeout)
{
    uint8_t *repbuf = NULL;
    size_t replen;
    enum sss_status nret;
    int errnop;
    uint32_t expected_version;
    uint32_t obtained_version;
    struct sss_cli_req_data req;

    if (strcmp(socket_name, SSS_NSS_SOCKET_NAME) == 0) {
        expected_version = SSS_NSS_PROTOCOL_VERSION;
    } else if (strcmp(socket_name, SSS_PAM_SOCKET_NAME) == 0 ||
               strcmp(socket_name, SSS_PAM_PRIV_SOCKET_NAME) == 0) {
        expected_version = SSS_PAM_PROTOCOL_VERSION;
    } else if (strcmp(socket_name, SSS_SUDO_SOCKET_NAME) == 0) {
        expected_version = SSS_SUDO_PROTOCOL_VERSION;
    } else if (strcmp(socket_name, SSS_AUTOFS_SOCKET_NAME) == 0) {
        expected_version = SSS_AUTOFS_PROTOCOL_VERSION;
    } else if (strcmp(socket_name, SSS_SSH_SOCKET_NAME) == 0) {
        expected_version = SSS_SSH_PROTOCOL_VERSION;
    } else if (strcmp(socket_name, SSS_PAC_SOCKET_NAME) == 0) {
        expected_version = SSS_PAC_PROTOCOL_VERSION;
    } else {
        return false;
    }

    req.len = sizeof(expected_version);
    req.data = &expected_version;

    nret = sss_cli_make_request_nochecks(SSS_GET_VERSION, &req, timeout,
                                         &repbuf, &replen, &errnop);
    if (nret != SSS_STATUS_SUCCESS) {
        return false;
    }

    if (!repbuf) {
        return false;
    }

    SAFEALIGN_COPY_UINT32(&obtained_version, repbuf, NULL);
    free(repbuf);

    return (obtained_version == expected_version);
}

/* this 2 functions are adapted from samba3 winbind's wb_common.c */

/* Make sure socket handle isn't stdin (0), stdout(1) or stderr(2) by setting
 * the limit to 3 */
#define RECURSION_LIMIT 3

static int make_nonstd_fd_internals(int fd, int limit)
{
    int new_fd;
    if (fd >= 0 && fd <= 2) {
#ifdef F_DUPFD
        if ((new_fd = fcntl(fd, F_DUPFD, 3)) == -1) {
            return -1;
        }
        /* Paranoia */
        if (new_fd < 3) {
            close(new_fd);
            return -1;
        }
        close(fd);
        return new_fd;
#else
        if (limit <= 0)
            return -1;

        new_fd = dup(fd);
        if (new_fd == -1)
            return -1;

        /* use the program stack to hold our list of FDs to close */
        new_fd = make_nonstd_fd_internals(new_fd, limit - 1);
        close(fd);
        return new_fd;
#endif
    }
    return fd;
}

/****************************************************************************
 Ensures fd isn't std[in/out/err] (duplicates it if needed) and
 set it into nonblocking mode. Uses POSIX O_NONBLOCK if available,
 else
 if SYSV use O_NDELAY
 if BSD use FNDELAY
 Set close on exec also.
****************************************************************************/

static int make_safe_fd(int fd)
{
    int result, flags;
    int new_fd = make_nonstd_fd_internals(fd, RECURSION_LIMIT);
    if (new_fd == -1) {
        close(fd);
        return -1;
    }

    /* Socket should be nonblocking. */
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

    if ((flags = fcntl(new_fd, F_GETFL)) == -1) {
        close(new_fd);
        return -1;
    }

    flags |= FLAG_TO_SET;
    if (fcntl(new_fd, F_SETFL, flags) == -1) {
        close(new_fd);
        return -1;
    }

#undef FLAG_TO_SET

    /* Socket should be closed on exec() */
#ifdef FD_CLOEXEC
    result = flags = fcntl(new_fd, F_GETFD, 0);
    if (flags >= 0) {
        flags |= FD_CLOEXEC;
        result = fcntl( new_fd, F_SETFD, flags );
    }
    if (result < 0) {
        close(new_fd);
        return -1;
    }
#endif
    return new_fd;
}

static int sss_cli_open_socket(int *errnop, const char *socket_name, int timeout)
{
    struct sockaddr_un nssaddr;
    bool inprogress = true;
    bool connected = false;
    unsigned int wait_time;
    unsigned int sleep_time;
    time_t start_time = time(NULL);
    int ret;
    int sd;

    if (sizeof(nssaddr.sun_path) < strlen(socket_name) + 1) {
        *errnop = EINVAL;
        return -1;
    }

    memset(&nssaddr, 0, sizeof(struct sockaddr_un));
    nssaddr.sun_family = AF_UNIX;
    strcpy(nssaddr.sun_path, socket_name); /* safe due to above check */

    sd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sd == -1) {
        *errnop = errno;
        return -1;
    }

    /* set as non-blocking, close on exec, and make sure standard
     * descriptors are not used */
    sd = make_safe_fd(sd);
    if (sd == -1) {
        *errnop = errno;
        return -1;
    }

    /* this piece is adapted from winbind client code */
    wait_time = 0;
    sleep_time = 0;
    while (inprogress) {
        int connect_errno = 0;
        socklen_t errnosize;
        struct pollfd pfd;

        wait_time += sleep_time;

        ret = connect(sd, (struct sockaddr *)&nssaddr,
                      sizeof(nssaddr));
        if (ret == 0) {
            connected = true;
            break;
        }

        switch(errno) {
        case EINPROGRESS:
            pfd.fd = sd;
            pfd.events = POLLOUT;

            ret = poll(&pfd, 1, timeout - wait_time);

            if (ret > 0) {
                errnosize = sizeof(connect_errno);
                ret = getsockopt(sd, SOL_SOCKET, SO_ERROR,
                                 &connect_errno, &errnosize);
                if (ret >= 0 && connect_errno == 0) {
                    connected = true;
                    break;
                }
            }
            wait_time = time(NULL) - start_time;
            break;
        case EAGAIN:
            if (wait_time < timeout) {
                sleep_time = 1;
                sleep(sleep_time);
            }
            break;
        default:
            *errnop = errno;
            inprogress = false;
            break;
        }

        if (wait_time >= timeout) {
            inprogress = false;
        }

        if (connected) {
            inprogress = false;
        }
    }

    if (!connected) {
        close(sd);
        return -1;
    }

    ret = fstat(sd, &sss_cli_sb);
    if (ret != 0) {
        close(sd);
        return -1;
    }

    return sd;
}

static enum sss_status sss_cli_check_socket(int *errnop,
                                            const char *socket_name,
                                            int timeout)
{
    static pid_t mypid;
    struct stat mysb;
    int mysd;
    int ret;

    if (getpid() != mypid) {
        ret = fstat(sss_cli_sd, &mysb);
        if (ret == 0) {
            if (S_ISSOCK(mysb.st_mode) &&
                mysb.st_dev == sss_cli_sb.st_dev &&
                mysb.st_ino == sss_cli_sb.st_ino) {
                sss_cli_close_socket();
            }
        }
        sss_cli_sd = -1;
        mypid = getpid();
    }

    /* check if the socket has been closed on the other side */
    if (sss_cli_sd != -1) {
        struct pollfd pfd;
        int res, error;

        *errnop = 0;
        pfd.fd = sss_cli_sd;
        pfd.events = POLLIN | POLLOUT;

        do {
            errno = 0;
            res = poll(&pfd, 1, timeout);
            error = errno;

            /* If error is EINTR here, we'll try again
             * If it's any other error, we'll catch it
             * below.
             */
        } while (error == EINTR);

        switch (res) {
        case -1:
            *errnop = error;
            break;
        case 0:
            *errnop = ETIME;
            break;
        case 1:
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                *errnop = EPIPE;
            }
            if (!(pfd.revents & (POLLIN | POLLOUT))) {
                *errnop = EBUSY;
            }
            break;
        default: /* more than one available!? */
            *errnop = EBADF;
            break;
        }
        if (*errnop == 0) {
            return SSS_STATUS_SUCCESS;
        }

        sss_cli_close_socket();
    }

    mysd = sss_cli_open_socket(errnop, socket_name, timeout);
    if (mysd == -1) {
        return SSS_STATUS_UNAVAIL;
    }

    sss_cli_sd = mysd;

    if (sss_cli_check_version(socket_name, timeout)) {
        return SSS_STATUS_SUCCESS;
    }

    sss_cli_close_socket();
    *errnop = EFAULT;
    return SSS_STATUS_UNAVAIL;
}

/* this function will check command codes match and returned length is ok */
/* repbuf and replen report only the data section not the header */
enum nss_status sss_nss_make_request_timeout(enum sss_cli_command cmd,
                                             struct sss_cli_req_data *rd,
                                             int timeout,
                                             uint8_t **repbuf, size_t *replen,
                                             int *errnop)
{
    enum sss_status ret;
    char *envval;

    /* avoid looping in the nss daemon */
    envval = getenv("_SSS_LOOPS");
    if (envval && strcmp(envval, "NO") == 0) {
        return NSS_STATUS_NOTFOUND;
    }

    ret = sss_cli_check_socket(errnop, SSS_NSS_SOCKET_NAME, timeout);
    if (ret != SSS_STATUS_SUCCESS) {
#ifdef NONSTANDARD_SSS_NSS_BEHAVIOUR
        *errnop = 0;
        errno = 0;
        return NSS_STATUS_NOTFOUND;
#else
        return NSS_STATUS_UNAVAIL;
#endif
    }

    ret = sss_cli_make_request_nochecks(cmd, rd, timeout, repbuf, replen,
                                        errnop);
    if (ret == SSS_STATUS_UNAVAIL && *errnop == EPIPE) {
        /* try reopen socket */
        ret = sss_cli_check_socket(errnop, SSS_NSS_SOCKET_NAME, timeout);
        if (ret != SSS_STATUS_SUCCESS) {
#ifdef NONSTANDARD_SSS_NSS_BEHAVIOUR
            *errnop = 0;
            errno = 0;
            return NSS_STATUS_NOTFOUND;
#else
            return NSS_STATUS_UNAVAIL;
#endif
        }

        /* and make request one more time */
        ret = sss_cli_make_request_nochecks(cmd, rd, timeout, repbuf, replen,
                                            errnop);
    }
    switch (ret) {
    case SSS_STATUS_TRYAGAIN:
        return NSS_STATUS_TRYAGAIN;
    case SSS_STATUS_SUCCESS:
        return NSS_STATUS_SUCCESS;
    case SSS_STATUS_UNAVAIL:
    default:
#ifdef NONSTANDARD_SSS_NSS_BEHAVIOUR
        *errnop = 0;
        errno = 0;
        return NSS_STATUS_NOTFOUND;
#else
        return NSS_STATUS_UNAVAIL;
#endif
    }
}

enum nss_status sss_nss_make_request(enum sss_cli_command cmd,
                                     struct sss_cli_req_data *rd,
                                     uint8_t **repbuf, size_t *replen,
                                     int *errnop)
{
    return sss_nss_make_request_timeout(cmd, rd, SSS_CLI_SOCKET_TIMEOUT,
                                        repbuf, replen, errnop);
}

int sss_pac_check_and_open(void)
{
    enum sss_status ret;
    int errnop;

    ret = sss_cli_check_socket(&errnop, SSS_PAC_SOCKET_NAME,
                               SSS_CLI_SOCKET_TIMEOUT);
    if (ret != SSS_STATUS_SUCCESS) {
        return EIO;
    }

    return EOK;
}

int sss_pac_make_request(enum sss_cli_command cmd,
                         struct sss_cli_req_data *rd,
                         uint8_t **repbuf, size_t *replen,
                         int *errnop)
{
    enum sss_status ret;
    char *envval;
    int timeout = SSS_CLI_SOCKET_TIMEOUT;

    /* avoid looping in the nss daemon */
    envval = getenv("_SSS_LOOPS");
    if (envval && strcmp(envval, "NO") == 0) {
        return NSS_STATUS_NOTFOUND;
    }

    ret = sss_cli_check_socket(errnop, SSS_PAC_SOCKET_NAME, timeout);
    if (ret != SSS_STATUS_SUCCESS) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = sss_cli_make_request_nochecks(cmd, rd, timeout, repbuf, replen,
                                        errnop);
    if (ret == SSS_STATUS_UNAVAIL && *errnop == EPIPE) {
        /* try reopen socket */
        ret = sss_cli_check_socket(errnop, SSS_PAC_SOCKET_NAME, timeout);
        if (ret != SSS_STATUS_SUCCESS) {
            return NSS_STATUS_UNAVAIL;
        }

        /* and make request one more time */
        ret = sss_cli_make_request_nochecks(cmd, rd, timeout, repbuf, replen,
                                            errnop);
    }
    switch (ret) {
    case SSS_STATUS_TRYAGAIN:
        return NSS_STATUS_TRYAGAIN;
    case SSS_STATUS_SUCCESS:
        return NSS_STATUS_SUCCESS;
    case SSS_STATUS_UNAVAIL:
    default:
        return NSS_STATUS_UNAVAIL;
    }
}

int sss_pac_make_request_with_lock(enum sss_cli_command cmd,
                                   struct sss_cli_req_data *rd,
                                   uint8_t **repbuf, size_t *replen,
                                   int *errnop)
{
    int ret;

    sss_pac_lock();

    ret = sss_pac_make_request(cmd, rd, repbuf, replen, errnop);

    sss_pac_unlock();

    return ret;
}

errno_t check_server_cred(int sockfd)
{
#ifdef HAVE_UCRED
    int ret;
    struct ucred server_cred;
    socklen_t server_cred_len = sizeof(server_cred);

    ret = getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &server_cred,
                     &server_cred_len);
    if (ret != 0) {
        return errno;
    }

    if (server_cred_len != sizeof(struct ucred)) {
        return ESSS_BAD_CRED_MSG;
    }

    if (server_cred.uid != 0 || server_cred.gid != 0) {
        return ESSS_SERVER_NOT_TRUSTED;
    }
#endif
    return 0;
}

int sss_pam_make_request(enum sss_cli_command cmd,
                      struct sss_cli_req_data *rd,
                      uint8_t **repbuf, size_t *replen,
                      int *errnop)
{
    int ret, statret;
    errno_t error;
    enum sss_status status;
    char *envval;
    struct stat stat_buf;
    const char *socket_name;
    int timeout = SSS_CLI_SOCKET_TIMEOUT;

    sss_pam_lock();

    /* avoid looping in the pam daemon */
    envval = getenv("_SSS_LOOPS");
    if (envval && strcmp(envval, "NO") == 0) {
        ret = PAM_SERVICE_ERR;
        goto out;
    }

    /* only UID 0 shall use the privileged pipe */
    if (getuid() == 0) {
        socket_name = SSS_PAM_PRIV_SOCKET_NAME;
        errno = 0;
        statret = stat(socket_name, &stat_buf);
        if (statret != 0) {
            if (errno == ENOENT) {
                *errnop = ESSS_NO_SOCKET;
            } else {
                *errnop = ESSS_SOCKET_STAT_ERROR;
            }
            ret = PAM_SERVICE_ERR;
            goto out;
        }
        if ( ! (stat_buf.st_uid == 0 &&
                stat_buf.st_gid == 0 &&
                S_ISSOCK(stat_buf.st_mode) &&
                (stat_buf.st_mode & ~S_IFMT) == 0600 )) {
            *errnop = ESSS_BAD_PRIV_SOCKET;
            ret = PAM_SERVICE_ERR;
            goto out;
        }
    } else {
        socket_name = SSS_PAM_SOCKET_NAME;
        errno = 0;
        statret = stat(socket_name, &stat_buf);
        if (statret != 0) {
            if (errno == ENOENT) {
                *errnop = ESSS_NO_SOCKET;
            } else {
                *errnop = ESSS_SOCKET_STAT_ERROR;
            }
            ret = PAM_SERVICE_ERR;
            goto out;
        }
        if ( ! (stat_buf.st_uid == 0 &&
                stat_buf.st_gid == 0 &&
                S_ISSOCK(stat_buf.st_mode) &&
                (stat_buf.st_mode & ~S_IFMT) == 0666 )) {
            *errnop = ESSS_BAD_PUB_SOCKET;
            ret = PAM_SERVICE_ERR;
            goto out;
        }
    }

    status = sss_cli_check_socket(errnop, socket_name, timeout);
    if (status != SSS_STATUS_SUCCESS) {
        ret = PAM_SERVICE_ERR;
        goto out;
    }

    error = check_server_cred(sss_cli_sd);
    if (error != 0) {
        sss_cli_close_socket();
        *errnop = error;
        ret = PAM_SERVICE_ERR;
        goto out;
    }

    status = sss_cli_make_request_nochecks(cmd, rd, timeout, repbuf, replen,
                                           errnop);
    if (status == SSS_STATUS_UNAVAIL && *errnop == EPIPE) {
        /* try reopen socket */
        status = sss_cli_check_socket(errnop, socket_name, timeout);
        if (status != SSS_STATUS_SUCCESS) {
            ret = PAM_SERVICE_ERR;
            goto out;
        }

        /* and make request one more time */
        status = sss_cli_make_request_nochecks(cmd, rd, timeout, repbuf, replen,
                                               errnop);
    }

    if (status == SSS_STATUS_SUCCESS) {
        ret = PAM_SUCCESS;
    } else {
        ret = PAM_SERVICE_ERR;
    }

out:
    sss_pam_unlock();
    return ret;
}

void sss_pam_close_fd(void)
{
    sss_pam_lock();

    if (sss_cli_sd != -1) {
        close(sss_cli_sd);
        sss_cli_sd = -1;
    }

    sss_pam_unlock();
}

static enum sss_status
sss_cli_make_request_with_checks(enum sss_cli_command cmd,
                                 struct sss_cli_req_data *rd,
                                 int timeout,
                                 uint8_t **repbuf, size_t *replen,
                                 int *errnop,
                                 const char *socket_name)
{
    enum sss_status ret = SSS_STATUS_UNAVAIL;

    ret = sss_cli_check_socket(errnop, socket_name, timeout);
    if (ret != SSS_STATUS_SUCCESS) {
        return SSS_STATUS_UNAVAIL;
    }

    ret = sss_cli_make_request_nochecks(cmd, rd, timeout, repbuf, replen,
                                        errnop);
    if (ret == SSS_STATUS_UNAVAIL && *errnop == EPIPE) {
        /* try reopen socket */
        ret = sss_cli_check_socket(errnop, socket_name, timeout);
        if (ret != SSS_STATUS_SUCCESS) {
            return SSS_STATUS_UNAVAIL;
        }

        /* and make request one more time */
        ret = sss_cli_make_request_nochecks(cmd, rd, timeout, repbuf, replen,
                                            errnop);
    }

    return ret;
}

int sss_sudo_make_request(enum sss_cli_command cmd,
                          struct sss_cli_req_data *rd,
                          uint8_t **repbuf, size_t *replen,
                          int *errnop)
{
    return sss_cli_make_request_with_checks(cmd, rd, SSS_CLI_SOCKET_TIMEOUT,
                                            repbuf, replen, errnop,
                                            SSS_SUDO_SOCKET_NAME);
}

int sss_autofs_make_request(enum sss_cli_command cmd,
                            struct sss_cli_req_data *rd,
                            uint8_t **repbuf, size_t *replen,
                            int *errnop)
{
    enum sss_status status;

    status = sss_cli_make_request_with_checks(cmd, rd, SSS_CLI_SOCKET_TIMEOUT,
                                              repbuf, replen, errnop,
                                              SSS_AUTOFS_SOCKET_NAME);

    if (*errnop == ERR_OFFLINE) {
        *errnop = EHOSTDOWN;
    }

    return status;
}

int sss_ssh_make_request(enum sss_cli_command cmd,
                         struct sss_cli_req_data *rd,
                         uint8_t **repbuf, size_t *replen,
                         int *errnop)
{
    return sss_cli_make_request_with_checks(cmd, rd, SSS_CLI_SOCKET_TIMEOUT,
                                            repbuf, replen, errnop,
                                            SSS_SSH_SOCKET_NAME);
}


const char *ssscli_err2string(int err)
{
    const char *m;

    switch(err) {
        case ESSS_BAD_PRIV_SOCKET:
            return _("Privileged socket has wrong ownership or permissions.");
            break;
        case ESSS_BAD_PUB_SOCKET:
            return _("Public socket has wrong ownership or permissions.");
            break;
        case ESSS_BAD_CRED_MSG:
            return _("Unexpected format of the server credential message.");
            break;
        case ESSS_SERVER_NOT_TRUSTED:
            return _("SSSD is not run by root.");
            break;
        case ESSS_NO_SOCKET:
            return _("SSSD socket does not exist.");
            break;
        case ESSS_SOCKET_STAT_ERROR:
            return _("Cannot get stat of SSSD socket.");
            break;
        default:
            m = strerror(err);
            if (m == NULL) {
                return _("An error occurred, but no description can be found.");
            }
            return m;
            break;
    }

    return _("Unexpected error while looking for an error description");
}

/* Return strlen(str) or maxlen, whichever is shorter
 * Returns EINVAL if str is NULL, EFBIG if str is longer than maxlen
 * _len will return the result
 *
 * This function is useful for preventing buffer overflow attacks.
 */
errno_t sss_strnlen(const char *str, size_t maxlen, size_t *len)
{
    if (!str) {
        return EINVAL;
    }

#if defined __USE_GNU
    *len = strnlen(str, maxlen);
#else
    *len = 0;
    while (*len < maxlen) {
        if (str[*len] == '\0') break;
        (*len)++;
    }
#endif

    if (*len == maxlen && str[*len] != '\0') {
        return EFBIG;
    }

    return 0;
}

#if HAVE_PTHREAD
typedef void (*sss_mutex_init)(void);

struct sss_mutex sss_nss_mtx = { .mtx  = PTHREAD_MUTEX_INITIALIZER };

static struct sss_mutex sss_pam_mtx = { .mtx  = PTHREAD_MUTEX_INITIALIZER };

static struct sss_mutex sss_nss_mc_mtx = { .mtx  = PTHREAD_MUTEX_INITIALIZER };

static struct sss_mutex sss_pac_mtx = { .mtx  = PTHREAD_MUTEX_INITIALIZER };

static void sss_mt_lock(struct sss_mutex *m)
{
    pthread_mutex_lock(&m->mtx);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &m->old_cancel_state);
}

static void sss_mt_unlock(struct sss_mutex *m)
{
    pthread_setcancelstate(m->old_cancel_state, NULL);
    pthread_mutex_unlock(&m->mtx);
}

/* NSS mutex wrappers */
void sss_nss_lock(void)
{
    sss_mt_lock(&sss_nss_mtx);
}
void sss_nss_unlock(void)
{
    sss_mt_unlock(&sss_nss_mtx);
}

/* NSS mutex wrappers */
void sss_pam_lock(void)
{
    sss_mt_lock(&sss_pam_mtx);
}
void sss_pam_unlock(void)
{
    sss_mt_unlock(&sss_pam_mtx);
}

/* NSS mutex wrappers */
void sss_nss_mc_lock(void)
{
    sss_mt_lock(&sss_nss_mc_mtx);
}
void sss_nss_mc_unlock(void)
{
    sss_mt_unlock(&sss_nss_mc_mtx);
}

/* PAC mutex wrappers */
void sss_pac_lock(void)
{
    sss_mt_lock(&sss_pac_mtx);
}
void sss_pac_unlock(void)
{
    sss_mt_unlock(&sss_pac_mtx);
}

#else

/* sorry no mutexes available */
void sss_nss_lock(void) { return; }
void sss_nss_unlock(void) { return; }
void sss_pam_lock(void) { return; }
void sss_pam_unlock(void) { return; }
void sss_nss_mc_lock(void) { return; }
void sss_nss_mc_unlock(void) { return; }
void sss_pac_lock(void) { return; }
void sss_pac_unlock(void) { return; }
#endif


errno_t sss_readrep_copy_string(const char *in,
                                size_t *offset,
                                size_t *slen,
                                size_t *dlen,
                                char **out,
                                size_t *size)
{
    size_t i = 0;
    while (*slen > *offset && *dlen > 0) {
        (*out)[i] = in[*offset];
        if ((*out)[i] == '\0') break;
        i++;
        (*offset)++;
        (*dlen)--;
    }
    if (*slen <= *offset) { /* premature end of buf */
        return EBADMSG;
    }
    if (*dlen == 0) { /* not enough memory */
        return ERANGE; /* not ENOMEM, ERANGE is what glibc looks for */
    }
    (*offset)++;
    (*dlen)--;
    if (size) {
        *size = i;
    }

    return EOK;
}
