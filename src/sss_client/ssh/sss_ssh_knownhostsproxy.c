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
connect_socket(int family, struct sockaddr *addr, size_t addr_len, int *sd)
{
    int sock = -1;
    int ret;

    /* create socket */
    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, "socket() failed (%d): %s\n",
                ret, strerror(ret));
        goto done;
    }

    /* connect to the server */
    ret = connect(sock, addr, addr_len);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, "connect() failed (%d): %s\n",
                ret, strerror(ret));
        goto done;
    }

done:
    if (ret != 0) {
        if (sock >= 0) {
            close(sock);
        }
    } else {
        *sd = sock;
    }
    return ret;
}

static int proxy_data(int sock)
{
    struct pollfd fds[2];
    char buffer[BUFFER_SIZE];
    int i;
    ssize_t res;
    int ret;

    /* set O_NONBLOCK on standard input */
    ret = sss_fd_nonblocking(0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to make fd=0 nonblocking\n");
        goto done;
    }

    /* set O_NONBLOCK on the socket */
    ret = sss_fd_nonblocking(sock);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to make socket nonblocking\n");
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
                  "poll() failed (%d): %s\n", ret, strerror(ret));
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
                          "read() failed (%d): %s\n", ret, strerror(ret));
                    goto done;
                } else if (res == 0) {
                    ret = EOK;
                    goto done;
                }

                errno = 0;
                res = sss_atomic_write_s(i == 0 ? sock : 1, buffer, res);
                ret = errno;
                if (res == -1) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sss_atomic_write_s() failed (%d): %s\n",
                           ret, strerror(ret));
                    goto done;
                } else if (ret == EPIPE) {
                    ret = EOK;
                    goto done;
                }
            }
            if (fds[i].revents & POLLHUP) {
                ret = EOK;
                goto done;
            }
        }
    }

done:
    close(sock);
    return ret;
}

/* connect to server using proxy command */
static int
connect_proxy_command(char **args)
{
    int ret;

    execv(args[0], (char * const *)args);

    ret = errno;
    DEBUG(SSSDBG_OP_FAILURE, "execv() failed (%d): %s\n",
            ret, strerror(ret));

    return ret;
}

int main(int argc, const char **argv)
{
    TALLOC_CTX *mem_ctx = NULL;
    int pc_debug = SSSDBG_TOOLS_DEFAULT;
    int pc_port = 22;
    const char *pc_domain = NULL;
    const char *pc_host = NULL;
    const char **pc_args = NULL;
    int pc_pubkeys = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0,
          _("The debug level to run with"), NULL },
        { "port", 'p', POPT_ARG_INT, &pc_port, 0,
          _("The port to use to connect to the host"), NULL },
        { "domain", 'd', POPT_ARG_STRING, &pc_domain, 0,
          _("The SSSD domain to use"), NULL },
        { "pubkey", 'k', POPT_ARG_NONE, &pc_pubkeys, 0,
          _("Print the host ssh public keys"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    char strport[6];
    struct addrinfo ai_hint;
    struct addrinfo *ai = NULL;
    char canonhost[NI_MAXHOST];
    const char *host = NULL;
    struct sss_ssh_ent *ent = NULL;
    int ret;

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "set_locale() failed (%d): %s\n", ret, strerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    mem_ctx = talloc_new(NULL);
    if (!mem_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Not enough memory\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* parse parameters */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "HOST [PROXY_COMMAND]");
    while ((ret = poptGetNextOpt(pc)) > 0)
        ;

    DEBUG_CLI_INIT(pc_debug);

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    if (pc_port < 1 || pc_port > 65535) {
        BAD_POPT_PARAMS(pc, _("Invalid port\n"), ret, fini);
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

    /* canonicalize hostname */
    snprintf(strport, 6, "%d", pc_port);

    memset(&ai_hint, 0, sizeof(struct addrinfo));
    ai_hint.ai_family = AF_UNSPEC;
    ai_hint.ai_socktype = SOCK_STREAM;
    ai_hint.ai_protocol = IPPROTO_TCP;
    ai_hint.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST | AI_NUMERICSERV;

    ret = getaddrinfo(pc_host, strport, &ai_hint, &ai);
    if (ret) {
        ai_hint.ai_flags = AI_ADDRCONFIG | AI_CANONNAME | AI_NUMERICSERV;

        ret = getaddrinfo(pc_host, strport, &ai_hint, &ai);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "getaddrinfo() failed (%d): %s\n", ret, gai_strerror(ret));
        } else {
            host = ai->ai_canonname;
        }
    } else {
        ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                          canonhost, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "getnameinfo() failed (%d): %s\n", ret, gai_strerror(ret));
        } else {
            host = canonhost;
        }
    }

    if (host) {
        /* look up public keys */
        ret = sss_ssh_get_ent(mem_ctx, SSS_SSH_GET_HOST_PUBKEYS,
                              host, pc_domain, pc_host, &ent);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_ssh_get_ent() failed (%d): %s\n", ret, strerror(ret));
        }
    }

    if (pc_pubkeys) {
        /* print results */
        if (ent != NULL) {
            for (size_t i = 0; i < ent->num_pubkeys; i++) {
                ret = sss_ssh_print_pubkey(&ent->pubkeys[i], NULL);
                if (ret != EOK && ret != EINVAL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "ssh_ssh_print_pubkey() failed (%d): %s\n",
                          ret, strerror(ret));
                    ret = EXIT_FAILURE;
                    goto fini;
                }
            }
        }

        ret = EXIT_SUCCESS;
        goto fini;
    }

    /* connect to server */
    if (pc_args) {
        ret = connect_proxy_command(discard_const(pc_args));
    } else if (ai) {
        /* Try all IP addresses before giving up */
        int socket_descriptor = -1;
        for (struct addrinfo *ti = ai; ti != NULL; ti = ti->ai_next) {
            ret = connect_socket(ti->ai_family, ti->ai_addr, ti->ai_addrlen,
                                 &socket_descriptor);
            if (ret == EOK) {
                break;
            }
        }

        if (ret == EOK) {
            ret = proxy_data(socket_descriptor);
            if (ret != EOK) {
                ERROR("sss_ssh_knownhostsproxy: unable to proxy data: "
                      "%s\n", strerror(ret));
            }
        } else {
            ERROR("sss_ssh_knownhostsproxy: connect to host %s port %d: "
                  "%s\n", pc_host, pc_port, strerror(ret));
        }
    } else {
        ERROR("sss_ssh_knownhostsproxy: Could not resolve hostname %s\n",
              pc_host);
        ret = EFAULT;
    }

    ret = (ret == EOK) ? EXIT_SUCCESS : EXIT_FAILURE;

fini:
    poptFreeContext(pc);
    if (ai) freeaddrinfo(ai);
    talloc_free(mem_ctx);

    return ret;
}
