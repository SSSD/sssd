/*
    SSSD

    sss_config.c

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2026 SUSE LINUX GmbH, Nuernberg, Germany.

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

#include "util/util.h"

#ifdef USE_VENDORDIR
#include <sys/stat.h>
#endif

const char *sss_get_default_config_file(TALLOC_CTX *mem_ctx)
{
    char *config_file = NULL;

    config_file = talloc_strdup(mem_ctx, SSSD_CONFIG_FILE);
    if (config_file == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory.\n");
        return NULL;
    }

#if defined(USE_VENDORDIR)
    struct stat stats = {0};
    if (stat(config_file, &stats) < 0 && errno == ENOENT) {
        TALLOC_FREE(config_file);
        config_file = talloc_strdup(mem_ctx, SSSD_VENDOR_CONFIG_FILE);
        if (config_file == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory.\n");
            return NULL;
        }
        DEBUG(SSSDBG_CONF_SETTINGS, "Using vendor config file %s\n", config_file);
    }
#endif /* USE_VENDORDIR */

    return config_file;
}
