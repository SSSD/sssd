/*
   SSSD

   Service monitor bootstrap

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

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <grp.h>

#include "util/util.h"


/* Attention!
 * When those routines are being executed, internal logger isn't yet initialized.
 */


#ifdef SSSD_NON_ROOT_USER
/* returns: -1 on error, 0 - group not set, 1 - group set */
static int check_supplementary_group(gid_t gid)
{
    int size;
    gid_t *supp_gids = NULL;

    if (getegid() == gid) {
        return 1;
    }

    size = getgroups(0, NULL);
    if (size == -1) {
        return -1;
    }

    if (size > 0) {
        supp_gids = talloc_zero_array(NULL, gid_t, size);
        if (supp_gids == NULL) {
            return -1;
        }

        size = getgroups(size, supp_gids);
        if (size == -1) {
            talloc_free(supp_gids);
            return -1;
        }

        for (int i = 0; i < size; i++) {
            if (supp_gids[i] == gid) {
                talloc_free(supp_gids);
                return 1;
            }
        }

        talloc_free(supp_gids);
    }

    return 0;
}
#endif /* SSSD_NON_ROOT_USER */

int bootstrap_monitor_process(void)
{

#ifdef SSSD_NON_ROOT_USER
    /* In case SSSD is built with non-root user support,
     * a number of files are sssd:sssd owned.
     * Make sure all processes are added to sssd supplementary
     * group to avoid the need for CAP_DAC_OVERRIDE.
     *
     * TODO: read 'sssd.conf::user' first and in case it is set
     * to 'sssd' become_user(sssd) instead.
     */
    int ret;
    gid_t sssd_gid = 0;
    if ((getuid() == 0) || (geteuid() == 0)) {
        sss_sssd_user_uid_and_gid(NULL, &sssd_gid);
        ret = check_supplementary_group(sssd_gid);
        if (ret == -1) {
            sss_log(SSS_LOG_ALERT, "Can't check own supplementary groups.");
            return 1;
        }
        /* Expected outcome is 'ret == 1' since supplementary group should be set
           by systemd service description. */
        if (ret == 0) {
            /* Probably non-systemd based system or service file was edited,
               let's try to set group manually. */
            sss_log(SSS_LOG_WARNING,
                    "SSSD is built with support of 'run under non-root user' "
                    "feature but started under 'root'. Trying to add process "
                    "to SSSD supplementary group.");
            ret = setgroups(1, &sssd_gid);
            if (ret != 0) {
                sss_log(SSS_LOG_CRIT,
                        "Failed to add process to the "SSSD_USER" supplementary group. "
                        "Either run under '"SSSD_USER"' or make sure that run-under-root "
                        "main SSSD process has CAP_SETGID.");
                return 1;
            }
        }

        /* TODO: drop CAP_SET_GID capability */
    }
#endif /* SSSD_NON_ROOT_USER */

    return 0;
}
