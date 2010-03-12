/*
   SSSD

   nscd.c

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2010

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

#include <talloc.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "config.h"
#include "util/util.h"
#include "tools/tools_util.h"

#ifndef NSCD_RELOAD_ARG
#define NSCD_RELOAD_ARG "-i"
#endif

#if defined(NSCD_PATH) && defined(HAVE_NSCD)
int flush_nscd_cache(TALLOC_CTX *mem_ctx, enum nscd_db flush_db)
{
    char *cmd = NULL;
    const char *service;
    int ret;

    switch(flush_db) {
        case NSCD_DB_PASSWD:
            service = "passwd";
            break;

        case NSCD_DB_GROUP:
            service = "group";
            break;

        default:
            DEBUG(1, ("Unknown nscd database\n"));
            ret = EINVAL;
            goto done;
    }

    cmd = talloc_asprintf(mem_ctx, "%s %s %s", NSCD_PATH,
                                               NSCD_RELOAD_ARG,
                                               service);
    if (!cmd) {
        ret = ENOMEM;
        goto done;
    }

    ret = system(cmd);
    if (ret) {
        if (ret == -1) {
            DEBUG(1, ("system(3) failed\n"));
            ret = EFAULT;
            goto done;
        }
        /* The flush fails if nscd is not running, so do not care
         * about the return code */
        DEBUG(8, ("Error flushing cache, perhaps nscd is not running\n"));
    }


    ret = EOK;
done:
    talloc_free(cmd);
    return ret;
}

#else   /* defined(NSCD_PATH) && defined(HAVE_NSCD) */
int flush_nscd_cache(TALLOC_CTX *mem_ctx, enum nscd_db flush_db)
{
    return EOK;
}
#endif
