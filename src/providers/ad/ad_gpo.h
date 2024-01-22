/*
    SSSD

    Authors:
        Yassir Elley <yelley@redhat.com>

    Copyright (C) 2013 Red Hat

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

#ifndef AD_GPO_H_
#define AD_GPO_H_

#include "providers/ad/ad_access.h"

#define AD_GPO_CHILD_OUT_FILENO 3

#define AD_GPO_ATTRS {AD_AT_DISPLAY_NAME, \
                      AD_AT_NT_SEC_DESC, \
                      AD_AT_CN, AD_AT_FILE_SYS_PATH, \
                      AD_AT_MACHINE_EXT_NAMES, \
                      AD_AT_FUNC_VERSION, \
                      AD_AT_FLAGS, \
                      NULL}

/*
 * This pair of functions provides client-side GPO processing.
 *
 * While a GPO can target both user and computer objects, this
 * implementation only supports targeting of computer objects.
 *
 * A GPO overview is at https://fedorahosted.org/sssd/wiki/GpoOverview
 *
 * In summary, client-side processing involves:
 * - determining the target's DN
 * - extracting the SOM object DNs (i.e. OUs and Domain) from target's DN
 * - including the target's Site as another SOM object
 * - determining which GPOs apply to the target's SOMs
 * - prioritizing GPOs based on SOM, link order, and whether GPO is "enforced"
 * - retrieving the corresponding GPO objects
 * - sending the GPO DNs to the CSE processing engine for policy application
 * - policy application currently consists of HBAC-like functionality
 */
struct tevent_req *
ad_gpo_access_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct sss_domain_info *domain,
                   struct ad_access_ctx *ctx,
                   const char *user,
                   const char *service);

errno_t ad_gpo_access_recv(struct tevent_req *req);

#endif /* AD_GPO_H_ */
