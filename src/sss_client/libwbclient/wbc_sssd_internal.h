/*
   Unix SMB/CIFS implementation.

   Winbind client API - SSSD version

   Copyright (C) Sumit Bose <sbose@redhat.com> 2014

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _WBC_SSSD_INTERNAL_H
#define _WBC_SSSD_INTERNAL_H

#include <syslog.h>

#include "libwbclient.h"

#if defined(DEVELOPER)
#define WBC_SSSD_DEV_LOG syslog(LOG_DEBUG, "libwbclient_sssd: %s", __FUNCTION__);
#else
#define WBC_SSSD_DEV_LOG
#endif

#define WBC_SSSD_NOT_IMPLEMENTED \
    do { \
        WBC_SSSD_DEV_LOG; \
        return WBC_ERR_NOT_IMPLEMENTED; \
    } while(0)

#endif    /* _WBC_SSSD_INTERNAL_H */
