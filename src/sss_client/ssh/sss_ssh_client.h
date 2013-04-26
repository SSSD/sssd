/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef _SSS_SSH_CLIENT_H_
#define _SSS_SSH_CLIENT_H_

void usage(poptContext pc, const char *error);
int set_locale(void);

#define BAD_POPT_PARAMS(pc, msg, val, label) do { \
        usage(pc, msg);                           \
        val = EXIT_FAILURE;                       \
        goto label;                               \
} while(0)

errno_t
sss_ssh_get_ent(TALLOC_CTX *mem_ctx,
                enum sss_cli_command command,
                const char *name,
                const char *domain,
                const char *alias,
                struct sss_ssh_ent **result);

#endif /* _SSS_SSH_CLIENT_H_ */
