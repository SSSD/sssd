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

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"
#include "sss_client/sss_cli.h"
#include "sss_client/ssh/sss_ssh_client.h"

int main(int argc, const char **argv)
{
    TALLOC_CTX *mem_ctx = NULL;
    int pc_debug = SSSDBG_DEFAULT;
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
    const char *user;
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
    poptSetOtherOptionHelp(pc, "USER");
    while ((ret = poptGetNextOpt(pc)) > 0)
        ;

    debug_level = debug_convert_old_level(pc_debug);

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    pc_user = poptGetArg(pc);
    if (pc_user == NULL) {
        BAD_POPT_PARAMS(pc, _("User not specified\n"), ret, fini);
    }

    /* append domain to username if domain is specified */
    if (pc_domain) {
        user = talloc_asprintf(mem_ctx, "%s@%s", pc_user, pc_domain);
        if (!user) {
            ERROR("Not enough memory\n");
            ret = EXIT_FAILURE;
            goto fini;
        }
    } else {
        user = pc_user;
    }

    /* look up public keys */
    ret = sss_ssh_get_ent(mem_ctx, SSS_SSH_GET_USER_PUBKEYS,
                          user, NULL, &ent);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sss_ssh_get_ent() failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error looking up public keys\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* print results */
    for (i = 0; i < ent->num_pubkeys; i++) {
        repr = sss_ssh_format_pubkey(mem_ctx, ent, &ent->pubkeys[i],
                                     SSS_SSH_FORMAT_OPENSSH);
        if (!repr) {
            ERROR("Not enough memory\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        printf("%s\n", repr);
    }

    ret = EXIT_SUCCESS;

fini:
    poptFreeContext(pc);
    talloc_free(mem_ctx);

    return ret;
}
