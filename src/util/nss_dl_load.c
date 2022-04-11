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


errno_t sss_load_nss_symbols(struct sss_nss_ops *ops, const char *libname,
                             struct sss_nss_symbols *syms, size_t nsyms)
{
    errno_t ret;
    char *libpath;
    size_t i;

    libpath = talloc_asprintf(NULL, "libnss_%s.so.2", libname);
    if (libpath == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return ENOMEM;
    }

    ops->dl_handle = dlopen(libpath, RTLD_NOW);
    if (ops->dl_handle == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load %s module, "
              "error: %s\n", libpath, dlerror());
        ret = ELIBACC;
        goto out;
    }

    for (i = 0; i < nsyms; i++) {
        *(syms[i].fptr) = proxy_dlsym(ops->dl_handle, syms[i].fname,
                                     libname);

        if (*(syms[i].fptr) == NULL) {
            if (syms[i].mandatory) {
                DEBUG(SSSDBG_FATAL_FAILURE, "Library '%s' did not provide "
                      "mandatory symbol '%s', error: %s.\n", libpath,
                      syms[i].fname, dlerror());
                ret = ELIBBAD;
                goto out;
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Library '%s' did not provide "
                      "optional symbol '%s', error: %s.\n", libpath,
                      syms[i].fname, dlerror());
            }
        }
    }

    ret = EOK;

out:
    talloc_free(libpath);

    return ret;
}
