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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* for struct ucred */
#define _GNU_SOURCE

#include <nss.h>
#include <security/pam_modules.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>

#include <libintl.h>
#define _(STRING) dgettext (PACKAGE, STRING)
#include "config.h"
#include "sss_cli.h"

/* common functions */

int sss_cli_sd = -1; /* the sss client socket descriptor */

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
static enum nss_status sss_nss_send_req(enum sss_cli_command cmd,
                                        struct sss_cli_req_data *rd,
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
            res = poll(&pfd, 1, SSS_CLI_SOCKET_TIMEOUT);
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
        default: /* more than one avail ?? */
            *errnop = EBADF;
            break;
        }
        if (*errnop) {
            sss_cli_close_socket();
            return NSS_STATUS_UNAVAIL;
        }

        errno = 0;
        if (datasent < SSS_NSS_HEADER_SIZE) {
            res = write(sss_cli_sd,
                        (char *)header + datasent,
                        SSS_NSS_HEADER_SIZE - datasent);
        } else {
            rdsent = datasent - SSS_NSS_HEADER_SIZE;
            res = write(sss_cli_sd,
                        (const char *)rd->data + rdsent,
                        rd->len - rdsent);
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
            *errnop = errno;
            return NSS_STATUS_UNAVAIL;
        }

        datasent += res;
    }

    return NSS_STATUS_SUCCESS;
}

/* Replies:
 *
 * byte 0-3: 32bit unsigned with length (the complete packet length: 0 to X)
 * byte 4-7: 32bit unsigned with command code
 * byte 8-11: 32bit unsigned with the request status (server errno)
 * byte 12-15: 32bit unsigned (reserved)
 * byte 16-X: (optional) reply structure associated to the command code used
 */

static enum nss_status sss_nss_recv_rep(enum sss_cli_command cmd,
                                        uint8_t **buf, int *len,
                                        int *errnop)
{
    uint32_t header[4];
    size_t datarecv;

    header[0] = SSS_NSS_HEADER_SIZE; /* unitl we know the real lenght */
    header[1] = 0;
    header[2] = 0;
    header[3] = 0;

    datarecv = 0;
    *buf = NULL;
    *len = 0;
    *errnop = 0;

    while (datarecv < header[0]) {
        struct pollfd pfd;
        int bufrecv;
        int res, error;

        pfd.fd = sss_cli_sd;
        pfd.events = POLLIN;

        do {
            errno = 0;
            res = poll(&pfd, 1, SSS_CLI_SOCKET_TIMEOUT);
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
            if (!(pfd.revents & POLLIN)) {
                *errnop = EBUSY;
            }
            break;
        default: /* more than one avail ?? */
            *errnop = EBADF;
            break;
        }
        if (*errnop) {
            sss_cli_close_socket();
            return NSS_STATUS_UNAVAIL;
        }

        errno = 0;
        if (datarecv < SSS_NSS_HEADER_SIZE) {
            res = read(sss_cli_sd,
                       (char *)header + datarecv,
                       SSS_NSS_HEADER_SIZE - datarecv);
        } else {
            bufrecv = datarecv - SSS_NSS_HEADER_SIZE;
            res = read(sss_cli_sd,
                       (char *)(*buf) + bufrecv,
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
            *errnop = errno;
            return NSS_STATUS_UNAVAIL;
        }

        datarecv += res;

        if (datarecv == SSS_NSS_HEADER_SIZE && *len == 0) {
            /* at this point recv buf is not yet
             * allocated and the header has just
             * been read, do checks and proceed */
            if (header[2] != 0) {
                /* server side error */
                sss_cli_close_socket();
                *errnop = header[2];
                if (*errnop == EAGAIN) {
                    return NSS_STATUS_TRYAGAIN;
                } else {
                    return NSS_STATUS_UNAVAIL;
                }
            }
            if (header[1] != cmd) {
                /* wrong command id */
                sss_cli_close_socket();
                *errnop = EBADMSG;
                return NSS_STATUS_UNAVAIL;
            }
            if (header[0] > SSS_NSS_HEADER_SIZE) {
                *len = header[0] - SSS_NSS_HEADER_SIZE;
                *buf = malloc(*len);
                if (!*buf) {
                    sss_cli_close_socket();
                    *errnop =  ENOMEM;
                    return NSS_STATUS_UNAVAIL;
                }
            }
        }
    }

    return NSS_STATUS_SUCCESS;
}

/* this function will check command codes match and returned length is ok */
/* repbuf and replen report only the data section not the header */
static enum nss_status sss_nss_make_request_nochecks(
                                       enum sss_cli_command cmd,
                                       struct sss_cli_req_data *rd,
                                       uint8_t **repbuf, size_t *replen,
                                       int *errnop)
{
    enum nss_status ret;
    uint8_t *buf = NULL;
    int len = 0;

    /* send data */
    ret = sss_nss_send_req(cmd, rd, errnop);
    if (ret != NSS_STATUS_SUCCESS) {
        return ret;
    }

    /* data sent, now get reply */
    ret = sss_nss_recv_rep(cmd, &buf, &len, errnop);
    if (ret != NSS_STATUS_SUCCESS) {
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

    return NSS_STATUS_SUCCESS;
}

/* GET_VERSION Reply:
 * 0-3: 32bit unsigned version number
 */

static int sss_nss_check_version(const char *socket_name)
{
    uint8_t *repbuf;
    size_t replen;
    enum nss_status nret;
    int errnop;
    int res = NSS_STATUS_UNAVAIL;
    uint32_t expected_version;
    struct sss_cli_req_data req;

    if (strcmp(socket_name, SSS_NSS_SOCKET_NAME) == 0) {
        expected_version = SSS_NSS_PROTOCOL_VERSION;
    } else if (strcmp(socket_name, SSS_PAM_SOCKET_NAME) == 0 ||
               strcmp(socket_name, SSS_PAM_PRIV_SOCKET_NAME) == 0) {
        expected_version = SSS_PAM_PROTOCOL_VERSION;
    } else {
        return NSS_STATUS_UNAVAIL;
    }

    req.len = sizeof(expected_version);
    req.data = &expected_version;

    nret = sss_nss_make_request_nochecks(SSS_GET_VERSION, &req,
                                         &repbuf, &replen, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        return nret;
    }

    if (!repbuf) {
        return res;
    }

    if (((uint32_t *)repbuf)[0] == expected_version) {
        res = NSS_STATUS_SUCCESS;
    }

    free(repbuf);
    return res;
}

/* this 2 functions are adapted from samba3 winbinbd's wb_common.c */

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
 Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
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

static int sss_nss_open_socket(int *errnop, const char *socket_name)
{
    struct sockaddr_un nssaddr;
    int inprogress = 1;
    int wait_time, sleep_time;
    int sd;

    memset(&nssaddr, 0, sizeof(struct sockaddr_un));
    nssaddr.sun_family = AF_UNIX;
    strncpy(nssaddr.sun_path, socket_name,
            strlen(socket_name) + 1);

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
    while(inprogress) {
        int connect_errno = 0;
        socklen_t errnosize;
        struct timeval tv;
        fd_set w_fds;
        int ret;

        wait_time += sleep_time;

        ret = connect(sd, (struct sockaddr *)&nssaddr,
                      sizeof(nssaddr));
        if (ret == 0) {
            return sd;
        }

        switch(errno) {
        case EINPROGRESS:
            FD_ZERO(&w_fds);
            FD_SET(sd, &w_fds);
            tv.tv_sec = SSS_CLI_SOCKET_TIMEOUT - wait_time;
            tv.tv_usec = 0;

            ret = select(sd + 1, NULL, &w_fds, NULL, &tv);

            if (ret > 0) {
                errnosize = sizeof(connect_errno);
                ret = getsockopt(sd, SOL_SOCKET, SO_ERROR,
                                 &connect_errno, &errnosize);
                if (ret >= 0 && connect_errno == 0) {
                    return sd;
                }
            }
            wait_time += SSS_CLI_SOCKET_TIMEOUT;
            break;
        case EAGAIN:
            if (wait_time < SSS_CLI_SOCKET_TIMEOUT) {
                sleep_time = rand() % 2 + 1;
                sleep(sleep_time);
            }
            break;
        default:
            *errnop = errno;
            inprogress = 0;
            break;
        }

        if (wait_time >= SSS_CLI_SOCKET_TIMEOUT) {
            inprogress = 0;
        }
    }

    /* if we get here connect() failed or we timed out */

    close(sd);
    return -1;
}

static enum sss_status sss_cli_check_socket(int *errnop, const char *socket_name)
{
    static pid_t mypid;
    int mysd;

    if (getpid() != mypid) {
        sss_cli_close_socket();
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
            res = poll(&pfd, 1, SSS_CLI_SOCKET_TIMEOUT);
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
        default: /* more than one avail ?? */
            *errnop = EBADF;
            break;
        }
        if (*errnop == 0) {
            return SSS_STATUS_SUCCESS;
        }

        sss_cli_close_socket();
    }

    mysd = sss_nss_open_socket(errnop, socket_name);
    if (mysd == -1) {
        return SSS_STATUS_UNAVAIL;
    }

    sss_cli_sd = mysd;

    if (sss_nss_check_version(socket_name) == NSS_STATUS_SUCCESS) {
        return SSS_STATUS_SUCCESS;
    }

    sss_cli_close_socket();
    *errnop = EFAULT;
    return SSS_STATUS_UNAVAIL;
}

/* this function will check command codes match and returned length is ok */
/* repbuf and replen report only the data section not the header */
enum nss_status sss_nss_make_request(enum sss_cli_command cmd,
                      struct sss_cli_req_data *rd,
                      uint8_t **repbuf, size_t *replen,
                      int *errnop)
{
    enum nss_status ret;
    char *envval;

    /* avoid looping in the nss daemon */
    envval = getenv("_SSS_LOOPS");
    if (envval && strcmp(envval, "NO") == 0) {
        return NSS_STATUS_NOTFOUND;
    }

    ret = sss_cli_check_socket(errnop, SSS_NSS_SOCKET_NAME);
    if (ret != SSS_STATUS_SUCCESS) {
        return NSS_STATUS_UNAVAIL;
    }

    return sss_nss_make_request_nochecks(cmd, rd, repbuf, replen, errnop);
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
    int ret;
    char *envval;
    struct stat stat_buf;

    /* avoid looping in the pam daemon */
    envval = getenv("_SSS_LOOPS");
    if (envval && strcmp(envval, "NO") == 0) {
        return PAM_SERVICE_ERR;
    }

    /* only root shall use the privileged pipe */
    if (getuid() == 0 && getgid() == 0) {
        ret = stat(SSS_PAM_PRIV_SOCKET_NAME, &stat_buf);
        if (ret != 0) return PAM_SERVICE_ERR;
        if ( ! (stat_buf.st_uid == 0 &&
                stat_buf.st_gid == 0 &&
                S_ISSOCK(stat_buf.st_mode) &&
                (stat_buf.st_mode & ~S_IFMT) == 0600 )) {
            *errnop = ESSS_BAD_PRIV_SOCKET;
            return PAM_SERVICE_ERR;
        }

        ret = sss_cli_check_socket(errnop, SSS_PAM_PRIV_SOCKET_NAME);
    } else {
        ret = stat(SSS_PAM_SOCKET_NAME, &stat_buf);
        if (ret != 0) return PAM_SERVICE_ERR;
        if ( ! (stat_buf.st_uid == 0 &&
                stat_buf.st_gid == 0 &&
                S_ISSOCK(stat_buf.st_mode) &&
                (stat_buf.st_mode & ~S_IFMT) == 0666 )) {
            *errnop = ESSS_BAD_PUB_SOCKET;
            return PAM_SERVICE_ERR;
        }

        ret = sss_cli_check_socket(errnop, SSS_PAM_SOCKET_NAME);
    }
    if (ret != NSS_STATUS_SUCCESS) {
        return PAM_SERVICE_ERR;
    }

    ret = check_server_cred(sss_cli_sd);
    if (ret != 0) {
        sss_cli_close_socket();
        *errnop = ret;
        return PAM_SERVICE_ERR;
    }

    return sss_nss_make_request_nochecks(cmd, rd, repbuf, replen, errnop);
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
