/*
   SSSD

   Configuration Database

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>    2009

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

#ifndef CONFDB_PRIVATE_H_
#define CONFDB_PRIVATE_H_

struct confdb_ctx {
    struct tevent_context *pev;
    struct ldb_context *ldb;

    struct sss_domain_info *doms;
};

int parse_section(TALLOC_CTX *mem_ctx, const char *section,
                  char **sec_dn, const char **rdn_name);

#endif /* CONFDB_PRIVATE_H_ */
