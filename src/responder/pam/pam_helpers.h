/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2011 Red Hat

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

#ifndef PAM_HELPERS_H_
#define PAM_HELPERS_H_

#include "util/util.h"

#define CERT_AUTH_DEFAULT_MATCHING_RULE "KRB5:<EKU>clientAuth"

errno_t pam_initgr_cache_set(struct tevent_context *ev,
                             hash_table_t *id_table,
                             char *name,
                             long timeout);

/* Returns EOK if the cache is still valid
 * Returns ENOENT if the user is not found or is expired
 * May report other errors if the hash lookup fails.
 */
errno_t pam_initgr_check_timeout(hash_table_t *id_table,
                                 char *name);

#endif /* PAM_HELPERS_H_ */
