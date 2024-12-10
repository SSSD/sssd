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
#include <popt.h>
#include <signal.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"
#include "sss_client/sss_cli.h"
#include "sss_client/ssh/sss_ssh_client.h"

int main(int argc, const char **argv)
{
    TALLOC_CTX *mem_ctx = NULL;
    int pc_debug = SSSDBG_TOOLS_DEFAULT;
    const char *pc_domain = NULL;
    const char *pc_user = NULL;
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
    poptSetOtherOptionHelp(pc, "USER");
    while ((ret = poptGetNextOpt(pc)) > 0)
        ;

    DEBUG_CLI_INIT(pc_debug);

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    pc_user = poptGetArg(pc);
    if (pc_user == NULL) {
        BAD_POPT_PARAMS(pc, _("User not specified\n"), ret, fini);
    }

    /* look up public keys */
    ret = sss_ssh_get_ent(mem_ctx, SSS_SSH_GET_USER_PUBKEYS,
                          pc_user, pc_domain, NULL, &ent);
    if (ret == ERR_NON_SSSD_USER) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "The user %s is valid, but not handled by sssd\n", pc_user);
        ret = EXIT_SUCCESS;
        goto fini;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_ssh_get_ent() failed (%d): %s\n", ret, strerror(ret));
        ERROR("Error looking up public keys\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* if sshd closes its end of the pipe, we don't want sss_ssh_authorizedkeys
     * to exit abruptly, but to finish gracefully instead because the valid
     * key can be present in the data already written
     */
    signal(SIGPIPE, SIG_IGN);

    /* print results */
    for (i = 0; i < ent->num_pubkeys; i++) {
        ret = sss_ssh_print_pubkey(&ent->pubkeys[i], NULL, NULL);
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
