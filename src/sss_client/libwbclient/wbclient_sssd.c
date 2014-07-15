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
/* Required Headers */

#include "libwbclient.h"
#include "wbc_sssd_internal.h"

wbcErr wbcRequestResponse(int cmd,
              struct winbindd_request *request,
              struct winbindd_response *response)
{
    /* Helper to make API check happy */
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcRequestResponsePriv(int cmd,
                  struct winbindd_request *request,
                  struct winbindd_response *response)
{
    /* Helper to make API check happy */
    WBC_SSSD_NOT_IMPLEMENTED;
}
