/*
    Authors:
        Michal Židek <mzidek@redhat.com>

    Copyright (C) 2016 Red Hat

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
#include "util/sss_ini.h"
#include "tools/common/sss_tools.h"
#include "tools/common/sss_process.h"
#include "tools/sssctl/sssctl.h"
#include "confdb/confdb.h"



static char *sssctl_config_snippet_path(TALLOC_CTX *ctx, const char *path)
{
    char *tmp = NULL;
    const char delimiter = '/';
    char *dpos = NULL;

    tmp = talloc_strdup(ctx, path);
    if (!tmp) {
        return NULL;
    }

    dpos = strrchr(tmp, delimiter);
    if (dpos != NULL) {
        ++dpos;
        *dpos = '\0';
    } else {
        *tmp = '\0';
    }

    return talloc_strdup_append(tmp, CONFDB_DEFAULT_CONFIG_DIR_NAME);
}

errno_t sssctl_config_check(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt)
{
    errno_t ret;
    struct sss_ini *init_data;
    struct ref_array *ra_error, *ra_success;
    char *msg;
    uint32_t i = 0;
    size_t num_errors;
    size_t num_ra_error, num_ra_success;
    char **strs = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *config_path = NULL;
    const char *config_snippet_path = NULL;
    struct poptOption long_options[] = {
        SSSD_CONFIG_OPTS(config_path)
        {"snippet", 's', POPT_ARG_STRING, &config_snippet_path,
            0, _("Specify a non-default snippet dir (The default is to look in "
                 "the same place where the main config file is located. For "
                 "example if the config is set to \"/my/path/sssd.conf\", "
                 "the snippet dir \"/my/path/conf.d\" is used)"), NULL},
        POPT_TABLEEND
    };

    ret = sss_tool_popt(cmdline, long_options, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    tmp_ctx = talloc_new(NULL);
    init_data = sss_ini_new(tmp_ctx);
    if (!init_data) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory.\n");
        ret = ENOMEM;
        goto done;
    }

    if (config_path == NULL) {
        config_path = SSSD_CONFIG_FILE;
    }

    if (config_snippet_path == NULL) {
        config_snippet_path = sssctl_config_snippet_path(tmp_ctx, config_path);
        if (config_snippet_path == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create snippet path\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sss_ini_read_sssd_conf(init_data,
                                 config_path,
                                 config_snippet_path);

    if (ret == ERR_INI_EMPTY_CONFIG) {
        PRINT("File %1$s does not exist.\n", config_path);
        PRINT("There is no configuration.\n");
        ret = ERR_INI_OPEN_FAILED;
        goto done;
    }
    else if (ret != EOK) {
        PRINT("Failed to read '%s': %s\n", config_path, sss_strerror(ret));
        goto done;
    }

    /* Run validators */
    ret = sss_ini_call_validators_strs(tmp_ctx, init_data,
                                       SSSDDATADIR"/cfg_rules.ini",
                                       &strs, &num_errors);
    if (ret) {
        PRINT("Failed to run validators");
        goto done;
    }

    PRINT("Issues identified by validators: %zu\n", num_errors);
    for (i = 0; i < num_errors; i++) {
        printf("%s\n", strs[i]);
    }

    printf("\n");

    /* Merging issues */
    ra_error = sss_ini_get_ra_error_list(init_data);
    num_ra_error = ref_array_len(ra_error);

    PRINT("Messages generated during configuration merging: %zu\n", num_ra_error);

    i = 0;
    while (ref_array_get(ra_error, i, &msg) != NULL) {
        printf("%s\n", msg);
        i++;
    }

    printf("\n");

    /* Used snippets */
    ra_success = sss_ini_get_ra_success_list(init_data);
    num_ra_success = ref_array_len(ra_success);
    PRINT("Used configuration snippet files: %zu\n", num_ra_success);

    i = 0;
    while (ref_array_get(ra_success, i, &msg) != NULL) {
        printf("%s\n", msg);
        i++;
    }

    if (num_errors != 0 || num_ra_error != 0) {
        ret = EINVAL;
    } else {
        ret = EOK;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}
