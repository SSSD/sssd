/*
   SSSD

   PAC Responder

   Copyright (C) Sumit Bose <sbose@redhat.com> 2012
                 Jan Zeleny <jzeleny@redhat.com> 2012

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
#include "responder/pac/pacsrv.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version pac_cli_protocol_version[] = {
        {1, "2011-04-12", "initial version"},
        {0, NULL, NULL}
    };

    return pac_cli_protocol_version;
}

static struct sss_cmd_table pac_cmds[] = {
    {SSS_GET_VERSION, sss_cmd_get_version},
    {SSS_CLI_NULL, NULL}
};

struct sss_cmd_table *get_pac_cmds(void) {
    return pac_cmds;
}

int pac_cmd_execute(struct cli_ctx *cctx)
{
    enum sss_cli_command cmd;
    int i;

    cmd = sss_packet_get_cmd(cctx->creq->in);

    for (i = 0; pac_cmds[i].cmd != SSS_CLI_NULL; i++) {
        if (cmd == pac_cmds[i].cmd) {
            return pac_cmds[i].fn(cctx);
        }
    }

    return EINVAL;
}
