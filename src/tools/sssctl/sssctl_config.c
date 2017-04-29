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

#ifdef HAVE_LIBINI_CONFIG_V1_3
errno_t sssctl_config_check(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt)
{
    errno_t ret;
    struct ini_errobj *errobj = NULL;
    struct sss_ini_initdata *init_data;
    struct ref_array *ra;
    char *msg;
    uint32_t i = 0;
    size_t num_errors;
    size_t num_ra_error;
    char **strs = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    ret = sss_tool_popt(cmdline, NULL, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    tmp_ctx = talloc_new(NULL);
    init_data = sss_ini_initdata_init(tmp_ctx);
    if (!init_data) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Open config file */
    ret = sss_ini_config_file_open(init_data, SSSD_CONFIG_FILE);
    if (ret == ENOENT) {
        PRINT("File %1$s does not exist. SSSD will use default "
              "configuration with files provider.\n", SSSD_CONFIG_FILE);
        ret = EOK;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "sss_ini_config_file_open failed: %s [%d]\n",
              sss_strerror(ret),
              ret);
        goto done;
    }

    /* Check the file permissions */
    ret = sss_ini_config_access_check(init_data);
    if (ret != EOK) {
        printf(_("File ownership and permissions check failed. "
               "Expected root:root and 0600.\n"));
        ret = EPERM;
        goto done;
    }

    ret = sss_ini_get_config(init_data,
                             SSSD_CONFIG_FILE,
                             CONFDB_DEFAULT_CONFIG_DIR);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to load configuration\n");
        goto done;
    }

    /* Read rules */
    ret = sss_ini_call_validators_strs(tmp_ctx, init_data,
                                       SSSDDATADIR"/cfg_rules.ini",
                                       &strs, &num_errors);
    if (ret) {
        goto done;
    }

    /* Output from validators */
    printf(_("Issues identified by validators: %zu\n"), num_errors);
    for (i = 0; i < num_errors; i++) {
        printf("%s\n", strs[i]);
    }

    /* Merging issues */
    ra = sss_ini_get_ra_error_list(init_data);
    num_ra_error = ref_array_len(ra);

    printf("\n");
    printf(_("Messages generated during configuration merging: %zu\n"),
           num_ra_error);

    i = 0;
    while (ref_array_get(ra, i, &msg) != NULL) {
        printf("%s\n", msg);
        i++;
    }

    /* Used snippet files */
    ra = sss_ini_get_ra_success_list(init_data);

    printf("\n");
    printf(_("Used configuration snippet files: %u\n"),
           ref_array_len(ra));

    i = 0;
    while (ref_array_get(ra, i, &msg) != NULL) {
        printf("%s\n", msg);
        i++;
    }

    if (num_errors != 0 || num_ra_error != 0) {
        ret = EINVAL;
    } else {
        ret = EOK;
    }

done:
    ini_errobj_destroy(&errobj);
    sss_ini_config_destroy(init_data);
    return ret;
}
#endif /* HAVE_LIBINI_CONFIG_V1_3 */
