/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#ifndef IFP_GROUPS_H_
#define IFP_GROUPS_H_

#include "responder/ifp/ifp_iface_generated.h"
#include "responder/ifp/ifp_private.h"

#define IFP_PATH_GROUPS "/org/freedesktop/sssd/infopipe/Groups"
#define IFP_PATH_GROUPS_TREE IFP_PATH_GROUPS SBUS_SUBTREE_SUFFIX

/* Utility functions */

char * ifp_groups_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      struct ldb_message *msg);


#endif /* IFP_GROUPS_H_ */
