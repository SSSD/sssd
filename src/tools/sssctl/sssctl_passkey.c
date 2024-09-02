/*
    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Passkey related utilities

    Copyright (C) 2022 Red Hat

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

#include <popt.h>
#include <stdio.h>
#include <talloc.h>

#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/sssctl/sssctl.h"

#define SSS_PASSKEY_CHILD SSSD_LIBEXEC_PATH"/passkey_child"

errno_t sssctl_passkey_register(struct sss_cmdline *cmdline,
                                struct sss_tool_ctx *)
{
    errno_t ret;

    ret = sssctl_wrap_command(SSS_PASSKEY_CHILD, "--register", cmdline);

    return ret;
}
