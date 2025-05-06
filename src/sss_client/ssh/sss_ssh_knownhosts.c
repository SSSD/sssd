/*
    Authors:
        Alejandro Lopez <allopez@redhat.com>

    Copyright (C) 2024 Red Hat, Inc.

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
#include <popt.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>

#include "util/util.h"
#include "util/sss_ssh.h"
#include "sss_client/sss_cli.h"
#include "sss_client/ssh/sss_ssh_client.h"


/*
 * Parse the received hostname, which is expected in the format described in
 * the “SSH_KNOWN_HOSTS FILE FORMAT” section of sshd(8). The parsed host name
 * and port are returned as strings allocated with malloc(3), and not talloc(3),
 * and must be freed by the caller.
 *
 * Some of the recognized formats are not expected from ssh, but it is easier
 * to identify them and useful in the case the tool is launched manually by a
 * user.
 *
 * If any of the expected values (host or port) is not found, their respective
 * output arguments will NOT be modified.
 */
static errno_t parse_ssh_host(const char *ssh_host,
                              const char **_host, const char **_port)
{
    int values;

    /* Host name between brackets and with a port number.
     * ssh can use this format.
     */
    values = sscanf(ssh_host, "[%m[^]]]:%ms", _host, _port);
    if (values == 2) {
        return EOK;
    }
    /* Just a host name enclosed between brackets.
     * ssh is not expected to use this format but... who knows?
     */
    if (values == 1) {
        return EOK;
    }

    /* A host name without brackets but with a port number.
     * This is not expected from ssh, but users will certainly use it.
     */
    values = sscanf(ssh_host, "%m[^:]:%ms", _host, _port);
    if (values == 2) {
        return EOK;
    }
    /* A host name without brackets or port number.
     * This is probably the most common case.
     */
    if (values == 1) {
        return EOK;
    }

    return EINVAL;
}

static errno_t known_hosts(TALLOC_CTX *mem_ctx, const char *domain,
                           const char *ssh_host, int only_host_name)
{
    errno_t ret;
    struct addrinfo ai_hint;
    struct addrinfo *ai = NULL;
    char canonhost[NI_MAXHOST];
    const char *host = NULL;
    const char *port = NULL;
    const char *canonname = NULL;
    struct sss_ssh_ent *ent = NULL;
    size_t i;

    /* WARNING:
     * Memory for host and port is allocated with malloc(3) instead of talloc(3)
     */
    ret = parse_ssh_host(ssh_host, &host, &port);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse the host name: %s\n", ssh_host);
        goto done;
    }
    DEBUG(SSSDBG_FUNC_DATA, "Parsed hostname: %s, port: %s\n",
          host, port == NULL ? "default" : port);

    /* Canonicalize the host name in case the user used an alias or IP address */
    memset(&ai_hint, 0, sizeof(struct addrinfo));
    ai_hint.ai_family = AF_UNSPEC;
    ai_hint.ai_socktype = SOCK_STREAM;
    ai_hint.ai_protocol = IPPROTO_TCP;
    ai_hint.ai_flags = AI_NUMERICHOST;

    ret = getaddrinfo(host, port, &ai_hint, &ai);
    if (ret != EOK) {
        ai_hint.ai_flags = AI_CANONNAME;
        ret = getaddrinfo(host, port, &ai_hint, &ai);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "getaddrinfo() failed (%d): %s\n", ret, gai_strerror(ret));
            canonname = host;
        } else {
            canonname = ai->ai_canonname;
        }
    } else {
        ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                          canonhost, sizeof(canonhost), NULL, 0, NI_NAMEREQD);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "getnameinfo() failed (%d): %s\n", ret, gai_strerror(ret));
            canonname = host;
        } else {
            canonname = canonhost;
        }
    }
    DEBUG(SSSDBG_FUNC_DATA, "Looking for name: %s\n", canonname);

    /* look up public keys */
    ret = sss_ssh_get_ent(mem_ctx, SSS_SSH_GET_HOST_PUBKEYS,
                          canonname, domain, host, &ent);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_FUNC_DATA,
              "sss_ssh_get_ent() found no entry\n");
        goto done;
    } else if (ret == ECONNREFUSED) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to connect to the 'ssh' responder. "
              "Is SSSD's 'ssh' service enabled?\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_ssh_get_ent() failed (%d): %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Print the results.
     * We pass the host name to handle the case when the key doesn't include
     * the host name */
    for (i = 0; i < ent->num_pubkeys; i++) {
        ret = sss_ssh_print_pubkey(&ent->pubkeys[i],
                                   only_host_name ? host : ssh_host,
                                   host);
        if (ret != EOK && ret != EINVAL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ssh_ssh_print_pubkey() failed (%d): %s\n",
                  ret, strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(ent);
    /* These two strings were allocated with malloc() */
    free(discard_const(host));
    free(discard_const(port));
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
    return ret;
}

int main(int argc, const char **argv)
{
    TALLOC_CTX *mem_ctx = NULL;
    int pc_debug = SSSDBG_TOOLS_DEFAULT;
    int pc_only_host_name = false;
    const char *pc_domain = NULL;
    const char *pc_host = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0,
          _("The debug level to run with"), NULL },
        { "domain", 'd', POPT_ARG_STRING, &pc_domain, 0,
          _("The SSSD domain to use"), _("domain name") },
        { "only-host-name", 'o', POPT_ARG_VAL, &pc_only_host_name, true,
          _("When the key has no host name, add only the host name"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    int ret;
    errno_t res;

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "set_locale() failed (%d): %s\n", ret, strerror(ret));
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
    poptSetOtherOptionHelp(pc, _("HOST"));
    while ((ret = poptGetNextOpt(pc)) > 0)
        ;

    DEBUG_CLI_INIT(pc_debug);

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    pc_host = poptGetArg(pc);
    if (pc_host == NULL) {
        BAD_POPT_PARAMS(pc, _("Host not specified\n"), ret, fini);
    }

    /* If the other side closes its end of the pipe, we don't want this tool
     * to exit abruptly, but to finish gracefully instead because the valid
     * key can be present in the data already written
     */
    signal(SIGPIPE, SIG_IGN);

    /* look up the public keys */
    res = known_hosts(mem_ctx, pc_domain, pc_host, pc_only_host_name);
    if (res != EOK) {
        /* On a successful execution, even if no key was found,
         * ssh expects EXIT_SUCCESS.
         * Do not return an error if the ssh service is not running.*/
        ret = (res == ENOENT || res == ECONNREFUSED ? EXIT_SUCCESS : EXIT_FAILURE);
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    poptFreeContext(pc);
    talloc_free(mem_ctx);

    return ret;
}
