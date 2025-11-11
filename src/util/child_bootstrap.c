/*
    SSSD

    Copyright (C) 2025 Red Hat

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

#include <unistd.h>
#include <talloc.h>

#include "util/debug.h"
#include "util/sss_prctl.h"
#include "util/sss_chain_id.h"
#include "util/child_bootstrap.h"


struct sss_child_basic_settings_t sss_child_basic_settings = {
    .opt_logger = NULL,
    .dumpable = 1,
    .ignore_dumpable = false,
    .backtrace = 1,
    .debug_fd = -1,
    .chain_id = 0,
    .name = NULL,
    .is_responder_invoked = false
};

bool sss_child_setup_basics(struct sss_child_basic_settings_t *settings)
{
    int ret;

    if (!settings->ignore_dumpable) {
        sss_prctl_set_dumpable((settings->dumpable == 0) ? 0 : 1);
    }

    if (settings->chain_id != 0) {
        if (settings->is_responder_invoked) {
            sss_chain_id_set_format(DEBUG_CHAIN_ID_FMT_CID);
        } else {
            sss_chain_id_set_format(DEBUG_CHAIN_ID_FMT_RID);
        }
        sss_chain_id_set((uint64_t)settings->chain_id);
    }

    if (settings->name != NULL) {
        debug_prg_name = talloc_asprintf(NULL, "%s[%d]", settings->name, (int)getpid());
        if (debug_prg_name == NULL) {
            ERROR("talloc_asprintf() failed\n");
            return false;
        }
    }

    if (settings->debug_fd != -1) {
        settings->opt_logger = sss_logger_str[FILES_LOGGER];
        ret = set_debug_file_from_fd(settings->debug_fd);
        if (ret != EOK) {
            ERROR("set_debug_file_from_fd() failed\n");
            return false;
        }
    }

    DEBUG_INIT(debug_level, settings->opt_logger);
    sss_set_debug_backtrace_enable((settings->backtrace == 0) ? false : true);

    return true;
}
