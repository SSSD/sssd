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

static errno_t
check_socket_activated_responder_in_sssd_conf(const char *responder)
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
    if (ret == ENOENT) {
        ret = EOK;
        goto done;
    } else if (ret != 0) {
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

static errno_t
check_socket_activated_responder_in_confdb(const char *responder)
{
    TALLOC_CTX *tmp_ctx;
    struct confdb_ctx *cdb;
    char *cdb_file = NULL;
    char **services;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    cdb_file = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (cdb_file == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_init(tmp_ctx, &cdb, cdb_file);
    if (ret != EOK) {
        goto done;
    }

    ret = confdb_get_string_as_list(cdb, tmp_ctx,
                                    CONFDB_MONITOR_CONF_ENTRY,
                                    CONFDB_MONITOR_ACTIVE_SERVICES,
                                    &services);
    if (ret == ENOENT) {
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    for (int i = 0; services[i] != NULL; i++) {
        if (strcmp(services[i], responder) == 0) {
            ret = EEXIST;
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
check_socket_activated_responder(const char *responder)
{
    errno_t ret;

    ret = check_socket_activated_responder_in_sssd_conf(responder);
    if (ret != EOK) {
        return ret;
    }

    ret = check_socket_activated_responder_in_confdb(responder);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

int main(int argc, const char *argv[])
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    int opt;
    poptContext pc;
    char *responder = NULL;
    char *err_msg = NULL;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"responders", 'r', POPT_ARG_STRING, &responder, 0,
         _("The name of the responder to be checked"), NULL},
        POPT_TABLEEND
    };

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

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
        err_msg = talloc_asprintf(
                tmp_ctx,
                "There's a misconfiguration in the \"services\" line of "
                "\"%s\" or the responder is being implicitly started!\n"
                "The \"services\" line contains \"%s\", meaning that the "
                "responder's process will be started and managed by SSSD's "
                "monitor. "
                "However, SSSD relies on systemd to start "
                "sssd-%s.socket and then manage the responder's process, "
                "causing then a configuration conflict.\n"
                "In order to solve this misconfiguration, please, either "
                "remove \"%s\" from the \"services\" line in \"%s\" or call "
                "`systemctl mask sssd-%s.socket`\n"
                "Please, refer to \"sssd.conf\" man page for more info and "
                "mind that the recommended way to go is to take advantage "
                "of systemd, as much as possible, avoiding then to have a "
                "\"services\" line in \"%s\"!",
                SSSD_CONFIG_FILE, responder, responder, responder,
                SSSD_CONFIG_FILE, responder, SSSD_CONFIG_FILE);
        if (err_msg == NULL) {
            goto done;
        }

        DEBUG(SSSDBG_IMPORTANT_INFO, "%s\n", err_msg);
        sss_log(SSS_LOG_WARNING, "%s\n", err_msg);
        goto done;
    }

    ret = EOK;
done:
    poptFreeContext(pc);
    talloc_zfree(tmp_ctx);
    return ret;
}
