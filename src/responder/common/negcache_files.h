/*
   SSSD

   NSS Responder

   Copyright (C) Petr Čech <pcech@redhat.com>	2016

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

#ifndef _NEGCACHE_FILES_H_
#define _NEGCACHE_FILES_H_

#include <stdbool.h>

struct sss_nss_ops;

bool is_user_local_by_name(const struct sss_nss_ops *ops, const char *name);
bool is_user_local_by_uid(const struct sss_nss_ops *ops, uid_t uid);

bool is_group_local_by_name(const struct sss_nss_ops *ops, const char *name);
bool is_group_local_by_gid(const struct sss_nss_ops *ops, uid_t gid);

#endif /* _NEGCACHE_FILES_H_ */
