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

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "util/util.h"
#include "responder/common/negcache_files.h"

#define BUFFER_SIZE 16384

bool is_user_local_by_name(const char *name)
{
    struct passwd pwd = { 0 };
    struct passwd *pwd_result;
    char buffer[BUFFER_SIZE];
    bool is_local = false;
    int ret;
    char *shortname = NULL;

    ret = sss_parse_internal_fqname(NULL, name, &shortname, NULL);
    if (ret != EOK) {
        return false;
    }

    ret = getpwnam_r(shortname, &pwd, buffer, BUFFER_SIZE, &pwd_result);
    talloc_free(shortname);
    if (ret == EOK && pwd_result != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "User %s is a local user\n", name);
        is_local = true;
    }

    return is_local;
}

bool is_user_local_by_uid(uid_t uid)
{
    struct passwd pwd = { 0 };
    struct passwd *pwd_result;
    char buffer[BUFFER_SIZE];
    bool is_local = false;
    int ret;

    ret = getpwuid_r(uid, &pwd, buffer, BUFFER_SIZE, &pwd_result);
    if (ret == EOK && pwd_result != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "User with UID %"SPRIuid" is a local user\n", uid);
        is_local = true;
    }

    return is_local;
}

bool is_group_local_by_name(const char *name)
{
    struct group grp = { 0 };
    struct group *grp_result;
    char buffer[BUFFER_SIZE];
    bool is_local = false;
    int ret;
    char *shortname = NULL;

    ret = sss_parse_internal_fqname(NULL, name, &shortname, NULL);
    if (ret != EOK) {
        return false;
    }

    ret = getgrnam_r(shortname, &grp, buffer, BUFFER_SIZE, &grp_result);
    talloc_free(shortname);
    if (ret == EOK && grp_result != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Group %s is a local group\n", name);
        is_local = true;
    }

    return is_local;
}

bool is_group_local_by_gid(uid_t gid)
{
    struct group grp = { 0 };
    struct group *grp_result;
    char buffer[BUFFER_SIZE];
    bool is_local = false;
    int ret;

    ret = getgrgid_r(gid, &grp, buffer, BUFFER_SIZE, &grp_result);
    if (ret == EOK && grp_result != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Group with GID %"SPRIgid" is a local group\n", gid);
        is_local = true;
    }

    return is_local;
}
