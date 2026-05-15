/*
    NSS module which calls glibc's user and group lookup functions again

    DO NOT USE THIS IN /etc/nsswitch.conf, it will cause an infinite loop.

    The main use case is to run proxy provider tests with cwrap's nss-wrapper.
    The proxy provider loads the NSS modules directly with dlopen() and is not
    using glibc's NSS mechanism. Since nss-wrapper just wraps the standard
    glibc calls and does not provide an NSS module on its own we have to use
    this workaround to make proxy provider work with nss-wrapper.

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (c) 2023 Red Hat, Inc.

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

#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <stdlib.h>
#include <nss.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>



#define NSSRET(r) return (((r) == 0) ? NSS_STATUS_SUCCESS : NSS_STATUS_NOTFOUND )

enum nss_status _nss_call_getpwnam_r(const char *name, struct passwd *result,
                                     char *buffer, size_t buflen, int *errnop)
{
    struct passwd *res;
    int ret = getpwnam_r(name, result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_getpwuid_r(uid_t uid, struct passwd *result,
                                     char *buffer, size_t buflen, int *errnop)
{
    struct passwd *res;
    int ret = getpwuid_r(uid, result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_setpwent(void)
{
    setpwent();
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_call_getpwent_r(struct passwd *result,
                                    char *buffer, size_t buflen,
                                    int *errnop)
{
    struct passwd *res;
    int ret = getpwent_r(result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_endpwent(void)
{
    endpwent();
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_call_getgrnam_r(const char *name, struct group *result,
                                     char *buffer, size_t buflen, int *errnop)
{
    struct group *res;
    int ret = getgrnam_r(name, result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_getgrgid_r(gid_t gid, struct group *result,
                                     char *buffer, size_t buflen, int *errnop)
{
    struct group *res;
    int ret = getgrgid_r(gid, result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_setgrent(void)
{
    setgrent();
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_call_getgrent_r(struct group *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct group *res;
    int ret = getgrent_r(result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_endgrent(void)
{
    endgrent();
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_call_initgroups_dyn(const char *user, gid_t group,
                                         long int *start, long int *size,
                                         gid_t **groups, long int limit,
                                         int *errnop)
{
    int ngroups = 0;
    gid_t *grps = NULL;
    long int max_ret;
    long int i;
    int ret;

    ret = getgrouplist(user, group, grps, &ngroups);
    if (ret != -1) {
        return NSS_STATUS_UNAVAIL;
     }

    grps = malloc(ngroups * sizeof(gid_t));
    if (grps == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    max_ret = ngroups;
    /* check we have enough space in the buffer */
    if ((*size - *start) < ngroups) {
        long int newsize;
        gid_t *newgroups;

        newsize = *size + ngroups;
        if ((limit > 0) && (newsize > limit)) {
            newsize = limit;
            max_ret = newsize - *start;
        }

        newgroups = (gid_t *)realloc((*groups), newsize * sizeof(**groups));
        if (!newgroups) {
            free(grps);
            return NSS_STATUS_UNAVAIL;
        }
        *groups = newgroups;
        *size = newsize;
    }

    for (i = 0; i < max_ret; i++) {
        (*groups)[*start] = grps[i];
        *start += 1;
    }
    free(grps);

    return NSS_STATUS_SUCCESS;
}
