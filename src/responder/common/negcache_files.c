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

#include "util/util.h"
#include "util/nss_dl_load.h"
#include "responder/common/negcache_files.h"

#define BUFFER_SIZE 16384
static char s_nss_buffer[BUFFER_SIZE];

bool is_user_local_by_name(const struct sss_nss_ops *ops, const char *name)
{
    struct passwd pwd = { 0 };
    int errnop;
    enum nss_status ret;
    char *shortname = NULL;
    int parse_ret;

    parse_ret = sss_parse_internal_fqname(NULL, name, &shortname, NULL);
    if (parse_ret != EOK) {
        return false;
    }

    ret = ops->getpwnam_r(shortname, &pwd, s_nss_buffer, BUFFER_SIZE, &errnop);
    talloc_free(shortname);
    if (ret == NSS_STATUS_SUCCESS) {
        DEBUG(SSSDBG_TRACE_FUNC, "User %s is a local user\n", name);
        return true;
    }

    return false;
}

bool is_user_local_by_uid(const struct sss_nss_ops *ops, uid_t uid)
{
    struct passwd pwd = { 0 };
    int errnop;
    enum nss_status ret;

    ret = ops->getpwuid_r(uid, &pwd, s_nss_buffer, BUFFER_SIZE, &errnop);
    if (ret == NSS_STATUS_SUCCESS) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "User with UID %"SPRIuid" is a local user\n", uid);
        return true;
    }

    return false;
}

bool is_group_local_by_name(const struct sss_nss_ops *ops, const char *name)
{
    struct group grp = { 0 };
    int errnop;
    enum nss_status ret;
    char *shortname = NULL;
    int parse_ret;

    parse_ret = sss_parse_internal_fqname(NULL, name, &shortname, NULL);
    if (parse_ret != EOK) {
        return false;
    }

    ret = ops->getgrnam_r(shortname, &grp, s_nss_buffer, BUFFER_SIZE, &errnop);
    talloc_free(shortname);
    if (ret == NSS_STATUS_SUCCESS) {
        DEBUG(SSSDBG_TRACE_FUNC, "Group %s is a local group\n", name);
        return true;
    }

    return false;
}

bool is_group_local_by_gid(const struct sss_nss_ops *ops, uid_t gid)
{
    struct group grp = { 0 };
    int errnop;
    enum nss_status ret;

    ret = ops->getgrgid_r(gid, &grp, s_nss_buffer, BUFFER_SIZE, &errnop);
    if (ret == NSS_STATUS_SUCCESS) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Group with GID %"SPRIgid" is a local group\n", gid);
        return true;
    }

    return false;
}
