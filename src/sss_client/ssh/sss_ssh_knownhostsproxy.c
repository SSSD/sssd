/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <stdio.h>
#include <talloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <popt.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"
#include "sss_client/sss_cli.h"
#include "sss_client/ssh/sss_ssh_client.h"

#define BUFFER_SIZE 8192

/* connect to server using socket */
static int
connect_socket(const char *host,
               const char *port)
{
    struct addrinfo ai_hint;
    struct addrinfo *ai = NULL;
    int flags;
    int sock = -1;
    struct pollfd fds[2];
    char buffer[BUFFER_SIZE];
    int i;
    ssize_t res;
    int ret;

    /* get IP addresses of the host */
    memset(&ai_hint, 0, sizeof(struct addrinfo));
    ai_hint.ai_family = AF_UNSPEC;
    ai_hint.ai_socktype = SOCK_STREAM;
    ai_hint.ai_protocol = IPPROTO_TCP;
    ai_hint.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;

    ret = getaddrinfo(host, port, &ai_hint, &ai);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("getaddrinfo() failed (%d): %s\n", ret, gai_strerror(ret)));
        ret = ENOENT;
        goto done;
    }

    /* set O_NONBLOCK on standard input */
    flags = fcntl(0, F_GETFL);
    if (flags == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fcntl() failed (%d): %s\n",
                ret, strerror(ret)));
        goto done;
    }

    ret = fcntl(0, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fcntl() failed (%d): %s\n",
                ret, strerror(ret)));
        goto done;
    }

    /* create socket */
    sock = socket(ai[0].ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("socket() failed (%d): %s\n",
                ret, strerror(ret)));
        ERROR("Failed to open a socket\n");
        goto done;
    }

    /* connect to the server */
    ret = connect(sock, ai[0].ai_addr, ai[0].ai_addrlen);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("connect() failed (%d): %s\n",
                ret, strerror(ret)));
        ERROR("Failed to connect to the server\n");
        goto done;
    }

    /* set O_NONBLOCK on the socket */
    flags = fcntl(sock, F_GETFL);
    if (flags == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fcntl() failed (%d): %s\n",
                ret, strerror(ret)));
        goto done;
    }

    ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fcntl() failed (%d): %s\n",
                ret, strerror(ret)));
        goto done;
    }

    fds[0].fd = 0;
    fds[0].events = POLLIN;
    fds[1].fd = sock;
    fds[1].events = POLLIN;

    while (1) {
        ret = poll(fds, 2, -1);
        if (ret == -1) {
            ret = errno;
            if (ret == EINTR || ret == EAGAIN) {
                continue;
            }
            DEBUG(SSSDBG_OP_FAILURE,
                  ("poll() failed (%d): %s\n", ret, strerror(ret)));
            goto done;
        }

        /* read from standard input & write to socket */
        /* read from socket & write to standard output */
        for (i = 0; i < 2; i++) {
            if (fds[i].revents & POLLIN) {
                res = read(fds[i].fd, buffer, BUFFER_SIZE);
                if (res == -1) {
                    ret = errno;
                    if (ret == EAGAIN || ret == EINTR || ret == EWOULDBLOCK) {
                        continue;
                    }
                    DEBUG(SSSDBG_OP_FAILURE,
                          ("read() failed (%d): %s\n", ret, strerror(ret)));
                    goto done;
                } else if (res == 0) {
                    break;
                }

                res = sss_atomic_write(i == 0 ? sock : 1, buffer, res);
                if (res == -1) {
                    ret = errno;
                    DEBUG(SSSDBG_OP_FAILURE,
                          ("sss_atomic_write() failed (%d): %s\n",
                           ret, strerror(ret)));
                    goto done;
                }
            }
            if (fds[i].revents & POLLHUP) {
                break;
            }
        }
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_FUNC, ("Connection closed\n"));

done:
    if (ai) freeaddrinfo(ai);
    if (sock >= 0) close(sock);

    return ret;
}

/* connect to server using proxy command */
static int
connect_proxy_command(char **args)
{
    int ret;

    execv(args[0], (char * const *)args);

    ret = errno;
    DEBUG(SSSDBG_OP_FAILURE, ("execv() failed (%d): %s\n",
            ret, strerror(ret)));
    ERROR("Failed to execute proxy command\n");

    return ret;
}

int main(int argc, const char **argv)
{
    TALLOC_CTX *mem_ctx = NULL;
    int pc_debug = SSSDBG_DEFAULT;
    const char *pc_port = "22";
    const char *pc_domain = NULL;
    const char *pc_host = NULL;
    const char **pc_args = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0,
          _("The debug level to run with"), NULL },
        { "port", 'p', POPT_ARG_STRING, &pc_port, 0,
          _("The port to use to connect to the host"), NULL },
        { "domain", 'd', POPT_ARG_STRING, &pc_domain, 0,
          _("The SSSD domain to use"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    const char *host;
    struct sss_ssh_ent *ent;
    int ret;

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("set_locale() failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    mem_ctx = talloc_new(NULL);
    if (!mem_ctx) {
        ERROR("Not enough memory\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* parse parameters */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "HOST [PROXY_COMMAND]");
    while ((ret = poptGetNextOpt(pc)) > 0)
        ;

    debug_level = debug_convert_old_level(pc_debug);

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    pc_host = poptGetArg(pc);
    if (pc_host == NULL) {
        BAD_POPT_PARAMS(pc, _("Host not specified\n"), ret, fini);
    }

    pc_args = poptGetArgs(pc);
    if (pc_args && pc_args[0] && pc_args[0][0] != '/') {
        BAD_POPT_PARAMS(pc,
                _("The path to the proxy command must be absolute\n"),
                ret, fini);
    }

    /* append domain to hostname if domain is specified */
    if (pc_domain) {
        host = talloc_asprintf(mem_ctx, "%s@%s", pc_host, pc_domain);
        if (!host) {
            ERROR("Not enough memory\n");
            ret = EXIT_FAILURE;
            goto fini;
        }
    } else {
        host = pc_host;
    }

    /* look up public keys */
    ret = sss_ssh_get_ent(mem_ctx, SSS_SSH_GET_HOST_PUBKEYS, host, &ent);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sss_ssh_get_ent() failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error looking up public keys\n");
    }

    /* connect to server */
    if (pc_args) {
        ret = connect_proxy_command(discard_const(pc_args));
    } else {
        ret = connect_socket(pc_host, pc_port);
    }
    ret = (ret == EOK) ? EXIT_SUCCESS : EXIT_FAILURE;

fini:
    poptFreeContext(pc);
    talloc_free(mem_ctx);

    return ret;
}
