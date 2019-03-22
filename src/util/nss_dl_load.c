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


#include <dlfcn.h>
#include <talloc.h>
#include <stdbool.h>
#include <errno.h>

#include "util/util_errors.h"
#include "util/debug.h"
#include "nss_dl_load.h"


#define NSS_FN_NAME "_nss_%s_%s"


static void *proxy_dlsym(void *handle,
                         const char *name,
                         const char *libname)
{
    char *funcname;
    void *funcptr;

    funcname = talloc_asprintf(NULL, NSS_FN_NAME, libname, name);
    if (funcname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return NULL;
    }

    funcptr = dlsym(handle, funcname);
    talloc_free(funcname);

    return funcptr;
}


errno_t sss_load_nss_symbols(struct sss_nss_ops *ops, const char *libname)
{
    char *libpath;
    size_t i;
    struct {
        void **dest;
        const char *name;
    } symbols[] = {
        {(void**)&ops->getpwnam_r,      "getpwnam_r"},
        {(void**)&ops->getpwuid_r,      "getpwuid_r"},
        {(void**)&ops->setpwent,        "setpwent"},
        {(void**)&ops->getpwent_r,      "getpwent_r"},
        {(void**)&ops->endpwent,        "endpwent"},
        {(void**)&ops->getgrnam_r,      "getgrnam_r"},
        {(void**)&ops->getgrgid_r,      "getgrgid_r"},
        {(void**)&ops->setgrent,        "setgrent"},
        {(void**)&ops->getgrent_r,      "getgrent_r"},
        {(void**)&ops->endgrent,        "endgrent"},
        {(void**)&ops->initgroups_dyn,  "initgroups_dyn"},
        {(void**)&ops->setnetgrent,     "setnetgrent"},
        {(void**)&ops->getnetgrent_r,   "getnetgrent_r"},
        {(void**)&ops->endnetgrent,     "endnetgrent"},
        {(void**)&ops->getservbyname_r, "getservbyname_r"},
        {(void**)&ops->getservbyport_r, "getservbyport_r"},
        {(void**)&ops->setservent,      "setservent"},
        {(void**)&ops->getservent_r,    "getservent_r"},
        {(void**)&ops->endservent,      "endservent"}
    };

    libpath = talloc_asprintf(NULL, "libnss_%s.so.2", libname);
    if (libpath == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return ENOMEM;
    }

    ops->dl_handle = dlopen(libpath, RTLD_NOW);
    if (ops->dl_handle == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load %s module, "
              "error: %s\n", libpath, dlerror());
        talloc_free(libpath);
        return ELIBACC;
    }
    talloc_free(libpath);

    for (i = 0; i < sizeof(symbols)/sizeof(symbols[0]); ++i) {
        *symbols[i].dest = proxy_dlsym(ops->dl_handle, symbols[i].name,
                                       libname);
        if (*symbols[i].dest == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to load "NSS_FN_NAME", "
                  "error: %s.\n", libname, symbols[i].name, dlerror());
        }
    }

    return EOK;
}
