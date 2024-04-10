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
#ifdef USE_KEYRING
#include <keyutils.h>
#endif

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

#ifdef BUILD_CONF_SERVICE_USER_SUPPORT
int bootstrap_monitor_process(uid_t target_uid, gid_t target_gid)
#else
int bootstrap_monitor_process(void)
#endif
{
#ifdef SSSD_NON_ROOT_USER
    int ret;
    gid_t sssd_gid = 0;

    if (geteuid() == 0) {
#ifdef BUILD_CONF_SERVICE_USER_SUPPORT
        if (target_uid != 0) {
            /* Started under root but non-root 'sssd.conf::user' configured -
             * deprecated method.
             */
            sss_log(SSS_LOG_WARNING, "'sssd.conf::"CONFDB_MONITOR_USER_RUNAS"' "
                    "option is deprecated. Run under '"SSSD_USER"' initially instead.");
            ret = become_user(target_uid, target_gid, false); /* drops all caps */
            if (ret != 0) {
                sss_log(SSS_LOG_ALERT, "Failed to change uid:gid");
                return 1;
            }
        } else
#endif /* BUILD_CONF_SERVICE_USER_SUPPORT */
        {
            /* In case SSSD is built with non-root user support, but
             * runs under 'root', a number of files are still sssd:sssd owned.
             * Make sure all processes are added to 'sssd' supplementary
             * group to avoid the need for CAP_DAC_OVERRIDE.
             */
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
                sss_log(SSS_LOG_NOTICE,
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
        }
    } else {
        /* SSSD started under non 'root' initially - nothing to do */
    }
#endif /* SSSD_NON_ROOT_USER */

    sss_drop_all_caps();

    return 0;
}

void setup_keyring(void)
{
#ifdef USE_KEYRING
    int ret;

    /* Do this before all the forks, it sets the session key ring so all
     * keys are private to the daemon and cannot be read by any other process
     * tree */

    /* make a new session */
    ret = keyctl_join_session_keyring(NULL);
    if (ret == -1) {
        sss_log(SSS_LOG_ALERT,
                "Could not create private keyring session. "
                "If you store password there they may be easily accessible "
                "to the root user. (%d, %s)", errno, strerror(errno));
    }

    ret = keyctl_setperm(KEY_SPEC_SESSION_KEYRING, KEY_POS_ALL);
    if (ret == -1) {
        sss_log(SSS_LOG_ALERT,
                "Could not set permissions on private keyring. "
                "If you store password there they may be easily accessible "
                "to the root user. (%d, %s)", errno, strerror(errno));
    }
#endif
}
