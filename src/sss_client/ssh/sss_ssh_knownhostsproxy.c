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
#include <pwd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <popt.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"
#include "tools/tools_util.h"
#include "sss_client/sss_cli.h"
#include "sss_client/ssh/sss_ssh_client.h"

#define DEFAULT_FILE ".ssh/sss_known_hosts"

#define BUFFER_SIZE 8192

/* run proxy command */
static int run_proxy(char **args)
{
    int ret;

    execv(args[0], (char * const *)args);

    ret = errno;
    DEBUG(SSSDBG_OP_FAILURE, ("execv() failed (%d): %s\n",
            ret, strerror(ret)));
    ERROR("Failed to execute proxy command\n");

    return EXIT_FAILURE;
}

/* connect to server */
static int run_connect(int af, struct sockaddr *addr, size_t addr_len)
{
    int flags;
    int sock;
    fd_set fds;
    char buffer[BUFFER_SIZE];
    ssize_t rd_len, wr_len, wr_offs;
    int ret;

    /* set O_NONBLOCK on standard input */
    flags = fcntl(0, F_GETFL);
    if (flags == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fcntl() failed (%d): %s\n",
                ret, strerror(ret)));
        return EXIT_FAILURE;
    }

    ret = fcntl(0, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fcntl() failed (%d): %s\n",
                ret, strerror(ret)));
        return EXIT_FAILURE;
    }

    /* create socket */
    sock = socket(af, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("socket() failed (%d): %s\n",
                ret, strerror(ret)));
        ERROR("Failed to open a socket\n");
        return EXIT_FAILURE;
    }

    /* connect to the server */
    ret = connect(sock, addr, addr_len);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("connect() failed (%d): %s\n",
                ret, strerror(ret)));
        ERROR("Failed to connect to the server\n");
        close(sock);
        return EXIT_FAILURE;
    }

    /* set O_NONBLOCK on the socket */
    flags = fcntl(sock, F_GETFL);
    if (flags == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fcntl() failed (%d): %s\n",
                ret, strerror(ret)));
        close(sock);
        return EXIT_FAILURE;
    }

    ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fcntl() failed (%d): %s\n",
                ret, strerror(ret)));
        close(sock);
        return EXIT_FAILURE;
    }

    while (1) {
        FD_SET(0, &fds);
        FD_SET(sock, &fds);

        ret = select(sock+1, &fds, NULL, NULL, NULL);
        if (ret == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }

            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE, ("select() failed (%d): %s\n",
                    ret, strerror(ret)));
            close(sock);
            return EXIT_FAILURE;
        }

        /* read from standard input & write to socket */
        if (FD_ISSET(0, &fds)) {
            rd_len = read(0, buffer, BUFFER_SIZE);
            if (rd_len == -1) {
                if (errno == EAGAIN) {
                    continue;
                }

                ret = errno;
                DEBUG(SSSDBG_OP_FAILURE, ("read() failed (%d): %s\n",
                        ret, strerror(ret)));
                close(sock);
                return EXIT_FAILURE;
            }

            wr_offs = 0;
            do {
                wr_len = send(sock, buffer+wr_offs, rd_len-wr_offs, 0);
                if (wr_len == -1) {
                    if (errno == EAGAIN) {
                        continue;
                    }

                    ret = errno;
                    DEBUG(SSSDBG_OP_FAILURE, ("send() failed (%d): %s\n",
                            ret, strerror(ret)));
                    close(sock);
                    return EXIT_FAILURE;
                }

                if (wr_len == 0) {
                    close(sock);
                    return EXIT_SUCCESS;
                }

                wr_offs += wr_len;
            } while(wr_offs < rd_len);
        }

        /* read from socket & write to standard output */
        if (FD_ISSET(sock, &fds)) {
            rd_len = recv(sock, buffer, BUFFER_SIZE, 0);
            if (rd_len == -1) {
                if (errno == EAGAIN) {
                    continue;
                }

                ret = errno;
                DEBUG(SSSDBG_OP_FAILURE, ("recv() failed (%d): %s\n",
                        ret, strerror(ret)));
                close(sock);
                return EXIT_FAILURE;
            }

            if (rd_len == 0) {
                close(sock);
                return EXIT_SUCCESS;
            }

            wr_offs = 0;
            do {
                wr_len = write(1, buffer+wr_offs, rd_len-wr_offs);
                if (wr_len == -1) {
                    if (errno == EAGAIN) {
                        continue;
                    }

                    ret = errno;
                    DEBUG(SSSDBG_OP_FAILURE, ("write() failed (%d): %s\n",
                            ret, strerror(ret)));
                    close(sock);
                    return EXIT_FAILURE;
                }

                wr_offs += wr_len;
            } while(wr_offs < rd_len);
        }
    }
}

int main(int argc, const char **argv)
{
    TALLOC_CTX *mem_ctx;
    int pc_debug = SSSDBG_DEFAULT;
    const char *pc_file = DEFAULT_FILE;
    const char *pc_port = "22";
    const char *pc_domain = NULL;
    const char *pc_host = NULL;
    const char **pc_args = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0,
          _("The debug level to run with"), NULL },
        { "file", 'f', POPT_ARG_STRING, &pc_file, 0,
          _("The known_hosts file to use"), NULL },
        { "port", 'p', POPT_ARG_STRING, &pc_port, 0,
          _("The port to use to connect to the host"), NULL },
        { "domain", 'd', POPT_ARG_STRING, &pc_domain, 0,
          _("The SSSD domain to use"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    const char *file;
    struct passwd *pwd;
    const char *host;
    FILE *f;
    struct addrinfo ai_hint, *ai = NULL;
    struct sss_ssh_ent *ent;
    size_t i;
    char *repr;
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

    /* get absolute filename of the known_hosts file */
    if (pc_file && pc_file[0] != '/') {
        pwd = getpwuid(getuid());
        if (!pwd) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE, ("getpwuid() failed (%d): %s\n",
                  ret, strerror(ret)));
            ERROR("Failed to get user's home directory\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        file = talloc_asprintf(mem_ctx, "%s/%s", pwd->pw_dir, pc_file);
        if (!file) {
            ERROR("Not enough memory\n");
            ret = EXIT_FAILURE;
            goto fini;
        }
    } else {
        file = pc_file;
    }

    /* get canonic hostname and IP addresses of the host */
    memset(&ai_hint, 0, sizeof(struct addrinfo));
    ai_hint.ai_family = AF_UNSPEC;
    ai_hint.ai_socktype = SOCK_STREAM;
    ai_hint.ai_protocol = IPPROTO_TCP;
    ai_hint.ai_flags = AI_CANONNAME | AI_ADDRCONFIG | AI_NUMERICSERV;

    ret = getaddrinfo(pc_host, pc_port, &ai_hint, &ai);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("getaddrinfo() failed (%d): %s\n", ret, gai_strerror(ret)));
        ERROR("Error looking up host\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* append domain to hostname if domain is specified */
    if (pc_domain) {
        host = talloc_asprintf(mem_ctx, "%s@%s", ai[0].ai_canonname, pc_domain);
        if (!host) {
            ERROR("Not enough memory\n");
            ret = EXIT_FAILURE;
            goto fini;
        }
    } else {
        host = ai[0].ai_canonname;
    }

    /* look up public keys */
    ret = sss_ssh_get_ent(mem_ctx, SSS_SSH_GET_HOST_PUBKEYS, host, &ent);
    if (ret != EOK) {
        ERROR("Error looking up public keys\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* write known_hosts file */
    /* FIXME: Do not overwrite the file, handle concurrent access */
    f = fopen(file, "w");
    if (!f) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fopen() failed (%d): %s\n",
                ret, strerror(ret)));
        ERROR("Can't open known hosts file\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    fprintf(f,
            "# Generated by sss_ssh_knownhostsproxy. Please do not modify.\n");

    for (i = 0; i < ent->num_pubkeys; i++) {
        repr = sss_ssh_format_pubkey(mem_ctx, ent, &ent->pubkeys[i],
                                     SSS_SSH_FORMAT_OPENSSH);
        if (!repr) {
            continue;
        }

        fprintf(f, "%s %s\n", pc_host, repr);
    }

    fclose(f);

    /* connect to server */
    if (pc_args) {
        ret = run_proxy(discard_const(pc_args));
    } else {
        ret = run_connect(ai->ai_family, ai->ai_addr, ai->ai_addrlen);
    }

fini:
    poptFreeContext(pc);
    talloc_free(mem_ctx);
    if (ai) freeaddrinfo(ai);

    return ret;
}
