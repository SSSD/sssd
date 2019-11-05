/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>
        David Mulder <dmulder@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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

#ifndef SYSDB_COMPUTERS_H_
#define SYSDB_COMPUTERS_H_

#include "db/sysdb.h"

#define COMPUTERS_SUBDIR            "computers"
#define SYSDB_COMPUTER_CLASS        "computer"
#define SYSDB_COMPUTERS_CONTAINER   "cn="COMPUTERS_SUBDIR
#define SYSDB_TMPL_COMPUTER_BASE    SYSDB_COMPUTERS_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_COMPUTER         SYSDB_NAME"=%s,"SYSDB_TMPL_COMPUTER_BASE
#define SYSDB_COMP_FILTER           "(&("SYSDB_NAME"=%s)("SYSDB_OBJECTCLASS"="SYSDB_COMPUTER_CLASS"))"

int
sysdb_get_computer(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *computer_name,
                   const char **attrs,
                   struct ldb_message **computer);

int
sysdb_set_computer(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *computer_name,
                   const char *sid_str,
                   int cache_timeout,
                   time_t now);

#endif /* SYSDB_COMPUTERS_H_ */
