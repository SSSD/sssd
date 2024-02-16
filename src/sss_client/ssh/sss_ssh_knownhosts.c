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

#include "util/util.h"
#include "util/sss_ssh.h"
#include "sss_client/sss_cli.h"
#include "sss_client/ssh/sss_ssh_client.h"

static errno_t known_hosts(TALLOC_CTX *mem_ctx, const char *domain,
                           const char *host, struct sss_ssh_ent **_ent)
{
    errno_t ret;
    struct addrinfo ai_hint;
    struct addrinfo *ai = NULL;
    char canonhost[NI_MAXHOST];
    const char *canonname = NULL;
    struct sss_ssh_ent *ent = NULL;

    if (_ent == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "NULL _ent received\n");
        ERROR("Internal error\n");
        return EINVAL;
    }

    memset(&ai_hint, 0, sizeof(struct addrinfo));
    ai_hint.ai_family = AF_UNSPEC;
    ai_hint.ai_socktype = SOCK_STREAM;
    ai_hint.ai_protocol = IPPROTO_TCP;
    ai_hint.ai_flags = AI_NUMERICHOST;

    DEBUG(SSSDBG_FUNC_DATA, "Looking up canonical name for: %s\n", host);
    ret = getaddrinfo(host, NULL, &ai_hint, &ai);
    if (ret != EOK) {
        ai_hint.ai_flags = AI_CANONNAME;
        ret = getaddrinfo(host, NULL, &ai_hint, &ai);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "getaddrinfo() failed (%d): %s\n", ret, gai_strerror(ret));
            goto done;
        } else {
            canonname = ai->ai_canonname;
        }
    } else {
        ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                          canonhost, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "getnameinfo() failed (%d): %s\n", ret, gai_strerror(ret));
            goto done;
        } else {
            canonname = canonhost;
        }
    }
    DEBUG(SSSDBG_FUNC_DATA, "Found canonical name: %s\n", canonname);

    /* look up public keys */
    ret = sss_ssh_get_ent(mem_ctx, SSS_SSH_GET_HOST_PUBKEYS,
                          canonname, domain, host, &ent);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_FUNC_DATA,
              "sss_ssh_get_ent() found no entry\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_ssh_get_ent() failed (%d): %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_ent = ent;
    ret = EOK;

done:
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
    return ret;
}

int main(int argc, const char **argv)
{
    TALLOC_CTX *mem_ctx = NULL;
    int pc_debug = SSSDBG_TOOLS_DEFAULT;
    const char *pc_domain = NULL;
    const char *pc_host = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0,
          _("The debug level to run with"), NULL },
        { "domain", 'd', POPT_ARG_STRING, &pc_domain, 0,
          _("The SSSD domain to use"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct sss_ssh_ent *ent;
    size_t i;
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

    /* look up the public keys */
    res = known_hosts(mem_ctx, pc_domain, pc_host, &ent);
    if (res != EOK) {
        /* On a successful execution, even if no key was found,
         * ssh expects EXIT_SUCCESS. */
        ret = (res == ENOENT ? EXIT_SUCCESS : EXIT_FAILURE);
        goto fini;
    }

    /* If the other side closes its end of the pipe, we don't want this tool
     * to exit abruptly, but to finish gracefully instead because the valid
     * key can be present in the data already written
     */
    signal(SIGPIPE, SIG_IGN);

    /* print results */
    for (i = 0; i < ent->num_pubkeys; i++) {
        ret = sss_ssh_print_pubkey(&ent->pubkeys[i], pc_host);
        if (ret != EOK && ret != EINVAL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ssh_ssh_print_pubkey() failed (%d): %s\n",
                  ret, strerror(ret));
            goto fini;
        }
    }

    ret = EXIT_SUCCESS;

fini:
    poptFreeContext(pc);
    talloc_free(mem_ctx);

    return ret;
}
