/*
    SSSD

    IdP Identity Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

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


#ifndef _IDP_PRIVATE_H_
#define _IDP_PRIVATE_H_

#include "providers/idp/idp_id.h"
#include "providers/idp/idp_auth.h"

/** @brief Evaluate JSON encoded user data and store a POSIX user object in
 * the cache if all required information is available.
 */
errno_t eval_user_buf(struct idp_id_ctx *idp_id_ctx,
                      const char *group_name,
                      const char *del_name,
                      bool noexist_delete,
                      uint8_t *buf, ssize_t buflen);

/** @brief Evaluate JSON encoded group data and store a POSIX group object in
 * the cache if all required information is available.
 */
errno_t eval_group_buf(struct idp_id_ctx *idp_id_ctx,
                       const char *user_name,
                       const char *del_name,
                       bool noexist_delete,
                       uint8_t *buf, ssize_t buflen);

/** Internal data used to identify ongoing OAUTH 2.0 Device Authorization
 * requests.
 */
struct idp_open_req_data {
    char *device_code_data;
};

/** @brief Evaluate Device Authorization reply, if valid create a pam_data
 * reply and track the request internally.
 */
errno_t eval_device_auth_buf(struct idp_auth_ctx *idp_auth_ctx,
                             struct pam_data *pd,
                             uint8_t *buf, ssize_t buflen);

/** @brief Check if the user identifier of the authenticated user matches the
 * user trying to log in.
 */
errno_t eval_access_token_buf(struct idp_auth_ctx *idp_auth_ctx,
                              struct pam_data *pd, struct sss_domain_info *dom,
                              uint8_t *buf, ssize_t buflen);
#endif
