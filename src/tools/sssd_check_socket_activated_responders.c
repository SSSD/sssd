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
#include "util/sss_ini.h"
#include "confdb/confdb.h"

static errno_t check_socket_activated_responder(const char *responder)
{
    errno_t ret;
    char *services = NULL;
    const char *str;
    TALLOC_CTX *tmp_ctx;
    struct sss_ini *init_data;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    init_data = sss_ini_new(tmp_ctx);
    if (init_data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_ini_read_sssd_conf(init_data,
                                 SSSD_CONFIG_FILE,
                                 CONFDB_DEFAULT_CONFIG_DIR);
    if (ret != EOK) {
        DEBUG(SSSDBG_DEFAULT,
              "Failed to read configuration: [%d] [%s]. No reason to run "
              "a responder if SSSD isn't configured.",
              ret,
              sss_strerror(ret));
        goto done;
    }

    ret = sss_ini_get_cfgobj(init_data, "sssd", "services");

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_ini_get_cfgobj() failed [%d].\n", ret);
        goto done;
    }

    ret = sss_ini_check_config_obj(init_data);
    if (ret == ENOENT) {
        /* In case there's no services' line at all, just return EOK. */
        ret = EOK;
        goto done;
    }

    services = sss_ini_get_string_config_value(init_data, &ret);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_ini_get_string_config_value() failed [%d]\n",
              ret);
        goto done;
    }

    str = strstr(services, responder);
    if (str != NULL) {
        ret = EEXIST;
        goto done;
    }

    ret = EOK;

done:
    free(services);
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
        DEBUG(SSSDBG_DEFAULT,
              "Misconfiguration found for the %s responder.\n"
              "The %s responder has been configured to be socket-activated "
              "but it's still mentioned in the services' line in %s.\n"
              "Please, consider either adjusting your services' line in %s "
              "or disabling the %s's socket by calling:\n"
              "\"systemctl disable sssd-%s.socket\"",
              responder, responder, SSSD_CONFIG_FILE, SSSD_CONFIG_FILE,
              responder, responder);
        goto done;
    }

    ret = EOK;
done:
    poptFreeContext(pc);
    return ret;
}
