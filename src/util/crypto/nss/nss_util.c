/*
   SSSD

   NSS crypto wrappers

   Authors:
        Sumit Bose <sbose@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2010

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

#include "config.h"

#include <prinit.h>
#include <prerror.h>
#include <nss.h>
#include <pk11func.h>

#include "util/util.h"
#include "util/crypto/nss/nss_util.h"

static int nspr_nss_init_done = 0;

int nspr_nss_init(void)
{
    SECStatus sret;

    /* nothing to do */
    if (nspr_nss_init_done == 1) return SECSuccess;

    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);

    sret = NSS_NoDB_Init(NULL);
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error initializing connection to NSS [%d]\n",
                  PR_GetError());
        return EIO;
    }

    nspr_nss_init_done = 1;
    return EOK;
}

int nspr_nss_cleanup(void)
{
    SECStatus sret;

    /* nothing to do */
    if (nspr_nss_init_done == 0) return SECSuccess;

    sret = NSS_Shutdown();
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error shutting down connection to NSS [%d]\n",
                  PR_GetError());
        return EIO;
    }

    PR_Cleanup();
    nspr_nss_init_done = 0;
    return EOK;
}
