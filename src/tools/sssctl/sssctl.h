/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#ifndef _SSSCTL_H_
#define _SSSCTL_H_

#include "tools/common/sss_tools.h"

#define PRINT_IFP_WARNING(ret) do { \
    if (ret == ERR_SBUS_UNKNOWN_SERVICE || ret == ERR_SBUS_NO_REPLY || ret == ETIMEDOUT) { \
        fprintf(stderr, _("InfoPipe operation failed. Check that SSSD " \
                "is running and the InfoPipe responder is enabled. Make sure " \
                "'ifp' is listed in the 'services' option in sssd.conf.")); \
    } \
} while (0)

enum sssctl_prompt_result {
    SSSCTL_PROMPT_YES,
    SSSCTL_PROMPT_NO,
    SSSCTL_PROMPT_ERROR
};

enum sssctl_svc_action {
    SSSCTL_SVC_START,
    SSSCTL_SVC_STOP,
    SSSCTL_SVC_RESTART
};

enum sssctl_prompt_result
sssctl_prompt(const char *message,
              enum sssctl_prompt_result defval);

errno_t sssctl_wrap_command(const char *command,
                            const char *subcommand,
                            struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt);
errno_t sssctl_run_command(const char *const argv[]); /* argv[0] - command */
bool sssctl_start_sssd(bool force);
bool sssctl_stop_sssd(bool force);
bool sssctl_restart_sssd(bool force);

errno_t sssctl_systemd_start(void);
errno_t sssctl_systemd_stop(void);
errno_t sssctl_systemd_restart(void);

errno_t sssctl_domain_list(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt);

errno_t sssctl_domain_status(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt);

errno_t sssctl_client_data_backup(struct sss_cmdline *cmdline,
                                  struct sss_tool_ctx *tool_ctx,
                                  void *pvt);

errno_t sssctl_client_data_restore(struct sss_cmdline *cmdline,
                                   struct sss_tool_ctx *tool_ctx,
                                   void *pvt);

errno_t sssctl_cache_remove(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt);

errno_t sssctl_cache_expire(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt);

errno_t sssctl_cache_index(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt);

errno_t sssctl_logs_remove(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt);

errno_t sssctl_logs_fetch(struct sss_cmdline *cmdline,
                          struct sss_tool_ctx *tool_ctx,
                          void *pvt);

errno_t sssctl_debug_level(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt);

errno_t sssctl_analyze(struct sss_cmdline *cmdline,
                       struct sss_tool_ctx *tool_ctx,
                       void *pvt);

errno_t sssctl_user_show(struct sss_cmdline *cmdline,
                         struct sss_tool_ctx *tool_ctx,
                         void *pvt);

errno_t sssctl_group_show(struct sss_cmdline *cmdline,
                          struct sss_tool_ctx *tool_ctx,
                          void *pvt);

errno_t sssctl_netgroup_show(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt);

errno_t sssctl_config_check(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt);

errno_t sssctl_user_checks(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt);

errno_t sssctl_access_report(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt);

errno_t sssctl_cert_show(struct sss_cmdline *cmdline,
                         struct sss_tool_ctx *tool_ctx,
                         void *pvt);

errno_t sssctl_cert_map(struct sss_cmdline *cmdline,
                        struct sss_tool_ctx *tool_ctx,
                        void *pvt);
#ifdef BUILD_PASSKEY
errno_t sssctl_passkey_register(struct sss_cmdline *cmdline,
                                struct sss_tool_ctx *tool_ctx,
                                void *pvt);
#endif /* BUILD_PASSKEY */

errno_t sssctl_cert_eval_rule(struct sss_cmdline *cmdline,
                              struct sss_tool_ctx *tool_ctx,
                              void *pvt);

errno_t sssctl_gpo_show(struct sss_cmdline *cmdline,
                        struct sss_tool_ctx *tool_ctx,
                        void *pvt);

errno_t sssctl_gpo_list(struct sss_cmdline *cmdline,
                        struct sss_tool_ctx *tool_ctx,
                        void *pvt);

errno_t sssctl_gpo_remove(struct sss_cmdline *cmdline,
                          struct sss_tool_ctx *tool_ctx,
                          void *pvt);

errno_t sssctl_gpo_purge(struct sss_cmdline *cmdline,
                         struct sss_tool_ctx *tool_ctx,
                         void *pvt);

#endif /* _SSSCTL_H_ */
