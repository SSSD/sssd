/*
    Copyright (C) 2019 Red Hat

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

#ifndef __SSSD_NSS_DL_LOAD_H__
#define __SSSD_NSS_DL_LOAD_H__


#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include "util/util_errors.h"
#include "sss_client/nss_compat.h"


struct sss_nss_ops {
    enum nss_status (*getpwnam_r)(const char *name, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getpwuid_r)(uid_t uid, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setpwent)(void);
    enum nss_status (*getpwent_r)(struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endpwent)(void);

    enum nss_status (*getgrnam_r)(const char *name, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getgrgid_r)(gid_t gid, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setgrent)(void);
    enum nss_status (*getgrent_r)(struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endgrent)(void);
    enum nss_status (*initgroups_dyn)(const char *user, gid_t group,
                                      long int *start, long int *size,
                                      gid_t **groups, long int limit,
                                      int *errnop);
    enum nss_status (*setnetgrent)(const char *netgroup,
                                   struct __netgrent *result);
    enum nss_status (*getnetgrent_r)(struct __netgrent *result, char *buffer,
                                     size_t buflen, int *errnop);
    enum nss_status (*endnetgrent)(struct __netgrent *result);

    /* Services */
    enum nss_status (*getservbyname_r)(const char *name,
                                        const char *protocol,
                                        struct servent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop);
    enum nss_status (*getservbyport_r)(int port, const char *protocol,
                                        struct servent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop);
    enum nss_status (*setservent)(void);
    enum nss_status (*getservent_r)(struct servent *result,
                                    char *buffer, size_t buflen,
                                    int *errnop);
    enum nss_status (*endservent)(void);

    void *dl_handle;
};


struct sss_nss_symbols {
    void **fptr;
    bool mandatory;
    const char *fname;
};

errno_t sss_load_nss_symbols(struct sss_nss_ops *ops, const char *libname,
                             struct sss_nss_symbols *syms, size_t nsyms);


#endif /* __SSSD_NSS_DL_LOAD_H__ */
