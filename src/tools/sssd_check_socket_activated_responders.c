/*
    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include "config.h"

#include <popt.h>
#include <stdio.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "common/sss_tools.h"

static errno_t check_socket_activated_responder(const char *responder)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct confdb_ctx *confdb;
    char **services = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_tool_confdb_init(tmp_ctx, &confdb);
    if (ret != EOK) {
        goto done;
    }

    ret = confdb_get_services_as_list(confdb, tmp_ctx, &services);
    if (ret != EOK) {
        goto done;
    }

    if (string_in_list(responder, services, false)) {
        ret = EEXIST;
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

int main(int argc, const char *argv[])
{
    int ret;
    int opt;
    poptContext pc;
    char *responder = NULL;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"responders", 'r', POPT_ARG_STRING, &responder, 0,
         _("The name of the responder to be checked"), NULL},
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            ret = 1;
            goto done;
        }
    }

    if (responder == NULL) {
        poptPrintUsage(pc, stderr, 0);
        ret = 1;
        goto done;
    }

    ret = check_socket_activated_responder(responder);
    if (ret != EOK) {
        sss_log(SSS_LOG_ERR,
              "Misconfiguration found for the '%s' responder.\n"
              "It has been configured to be socket-activated but "
              "it's still mentioned in the services' line of the config file.\n"
              "Please consider either adjusting services' line "
              "or disabling the socket by calling:\n"
              "\"systemctl disable sssd-%s.socket\"",
              responder, responder);
        goto done;
    }

    ret = EOK;
done:
    poptFreeContext(pc);
    return ret;
}
