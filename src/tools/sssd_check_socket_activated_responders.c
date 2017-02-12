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
#include <ini_configobj.h>

#include "util/util.h"
#include "confdb/confdb.h"

static errno_t check_socket_activated_responder(const char *responder)
{
    errno_t ret;
    struct ini_cfgfile *file_ctx = NULL;
    struct ini_cfgobj *ini_config = NULL;
    struct ini_cfgobj *modified_ini_config = NULL;
    struct value_obj *vobj = NULL;
    struct access_check snip_check;
    const char *services;
    const char *patterns[] = { "^[^\\.].*\\.conf$", NULL };
    const char *sections[] = { "sssd", NULL };
    const char *str;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ini_config_create(&ini_config);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ini_config_create() failed [%d][%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ini_config_file_open(SSSD_CONFIG_FILE, 0, &file_ctx);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ini_config_file_open() failed [%d][%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Using the same flags used by sss_ini_get_config(), which is used to
     * load the config file ... */
    ret = ini_config_parse(file_ctx,
                           INI_STOP_ON_ANY,
                           INI_MV1S_OVERWRITE,
                           INI_PARSE_NOWRAP,
                           ini_config);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ini_config_parse() failed [%d][%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* And also check the snippets ... */
    snip_check.flags = INI_ACCESS_CHECK_MODE |
                       INI_ACCESS_CHECK_UID |
                       INI_ACCESS_CHECK_GID;
    snip_check.uid = 0; /* owned by root */
    snip_check.gid = 0; /* owned by root */
    snip_check.mode = S_IRUSR; /* r**------ */
    snip_check.mask = ALLPERMS & ~(S_IWUSR | S_IXUSR);

    ret = ini_config_augment(ini_config,
                             CONFDB_DEFAULT_CONFIG_DIR,
                             patterns,
                             sections,
                             &snip_check,
                             INI_STOP_ON_ANY,
                             INI_MV1S_OVERWRITE,
                             INI_PARSE_NOWRAP,
                             INI_MV2S_OVERWRITE,
                             &modified_ini_config,
                             NULL,
                             NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ini_config_augment failed [%d][%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (modified_ini_config != NULL) {
        ini_config_destroy(ini_config);
        ini_config = modified_ini_config;
    }

    ret = ini_get_config_valueobj("sssd", "services", ini_config,
                                  INI_GET_FIRST_VALUE, &vobj);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_get_config_valueobj() failed [%d][%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* In case there's no services' line at all, just return EOK. */
    if (vobj == NULL) {
        ret = EOK;
        goto done;
    }

    services = ini_get_string_config_value(vobj, &ret);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_get_string_config_value() failed [%d][%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    str = strstr(services, responder);
    if (str != NULL) {
        ret = EEXIST;
        goto done;
    }

    ret = EOK;

done:
    ini_config_file_destroy(file_ctx);
    ini_config_destroy(ini_config);
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
