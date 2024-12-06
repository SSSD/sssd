/*
    SSSD

    SELinux-related utility functions

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

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

#ifndef SSS_SELINUX_H_
#define SSS_SELINUX_H_

#include <talloc.h>
#include <errno.h>

#include <db/sysdb.h>

#define SELINUX_PRIORITY_USER_CAT 1
#define SELINUX_PRIORITY_USER_GROUP 2
#define SELINUX_PRIORITY_USER_NAME 4
/* According to specification, host has higher priority */
#define SELINUX_PRIORITY_HOST_CAT 8
#define SELINUX_PRIORITY_HOST_GROUP 16
#define SELINUX_PRIORITY_HOST_NAME 32

errno_t
sss_selinux_extract_user(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *username,
                         struct sysdb_attrs **_user_attrs);

bool sss_selinux_match(struct sysdb_attrs *usermap,
                       struct sysdb_attrs *user,
                       struct sysdb_attrs *host,
                       uint32_t *_priority);

const char *sss_selinux_map_get_seuser(struct sysdb_attrs *usermap);

#endif /* SSS_SELINUX_H_ */
