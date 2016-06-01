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

#include "lib/sifp/sss_sifp.h"
#include "lib/sifp/sss_sifp_dbus.h"
#include "tools/common/sss_tools.h"

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

errno_t sssctl_run_command(const char *command);
bool sssctl_start_sssd(bool force);
bool sssctl_stop_sssd(bool force);
bool sssctl_restart_sssd(bool force);

sss_sifp_error sssctl_sifp_init(struct sss_tool_ctx *tool_ctx,
                                sss_sifp_ctx **_sifp);

void _sssctl_sifp_error(sss_sifp_ctx *sifp,
                        sss_sifp_error error,
                        const char *message);

#define sssctl_sifp_error(sifp, error, message) \
    _sssctl_sifp_error(sifp, error, _(message))

errno_t sssctl_list_domains(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt);

errno_t sssctl_domain_status(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt);

errno_t sssctl_backup_local_data(struct sss_cmdline *cmdline,
                                 struct sss_tool_ctx *tool_ctx,
                                 void *pvt);

errno_t sssctl_restore_local_data(struct sss_cmdline *cmdline,
                                  struct sss_tool_ctx *tool_ctx,
                                  void *pvt);

errno_t sssctl_remove_cache(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt);

errno_t sssctl_remove_logs(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt);

errno_t sssctl_fetch_logs(struct sss_cmdline *cmdline,
                          struct sss_tool_ctx *tool_ctx,
                          void *pvt);

errno_t sssctl_user(struct sss_cmdline *cmdline,
                    struct sss_tool_ctx *tool_ctx,
                    void *pvt);

errno_t sssctl_group(struct sss_cmdline *cmdline,
                     struct sss_tool_ctx *tool_ctx,
                     void *pvt);

errno_t sssctl_netgroup(struct sss_cmdline *cmdline,
                        struct sss_tool_ctx *tool_ctx,
                        void *pvt);

#endif /* _SSSCTL_H_ */
