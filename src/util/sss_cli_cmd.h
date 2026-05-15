/*
   SSSD - cmd2str util

   Copyright (C) Petr Cech <pcech@redhat.com> 2015

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

#ifndef __SSS_CLI_CMD_H__
#define __SSS_CLI_CMD_H__

#include "sss_client/sss_cli.h"

/* Translate sss_cli_command to human readable form. */
const char *sss_cmd2str(enum sss_cli_command cmd);

#endif /* __SSS_CLI_CMD_H__ */
