/*
    SSSD

    pamsrv_json authentication selection helper for GDM

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

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

#ifndef __PAMSRV_JSON__H__
#define __PAMSRV_JSON__H__

#include <jansson.h>
#include <talloc.h>

#include "util/sss_pam_data.h"


/**
 * @brief Format authentication mechanisms to JSON
 *
 * @param[in] password_auth Whether password authentication is allowed
 * @param[in] password_prompt Password prompt
 * @param[in] oath2_auth Whether OAUTH2 authentication is allowed
 * @param[in] uri OAUTH2 uri
 * @param[in] code OAUTH2 code
 * @param[out] _list_mech authentication mechanisms JSON object
 *
 * @return 0 if the authentication mechanisms were formatted properly,
 *         error code otherwise.
 */
errno_t
json_format_mechanisms(bool password_auth, const char *password_prompt,
                       bool oauth2_auth, const char *uri, const char *code,
                       json_t **_list_mech);

/**
 * @brief Format priority to JSON
 *
 * @param[in] password_auth Whether password authentication is allowed
 * @param[in] oath2_auth Whether OAUTH2 authentication is allowed
 * @param[out] _priority priority JSON object
 *
 * @return 0 if the priority was formatted properly,
 *         error code otherwise.
 */
errno_t
json_format_priority(bool password_auth, bool oauth2_auth, json_t **_priority);

/**
 * @brief Format data to JSON
 *
 * @param[in] mem_ctx Memory context
 * @param[in] password_auth Whether password authentication is allowed
 * @param[in] password_prompt Password prompt
 * @param[in] oath2_auth Whether OAUTH2 authentication is allowed
 * @param[in] uri OAUTH2 uri
 * @param[in] code OAUTH2 code
 * @param[out] _result JSON message
 *
 * @return 0 if the JSON message was formatted properly,
 *         error code otherwise.
 */
errno_t
json_format_auth_selection(TALLOC_CTX *mem_ctx,
                           bool password_auth, const char *password_prompt,
                           bool oath2_auth, const char *uri, const char *code,
                           char **_result);

/**
 * @brief Check the internal data and generate the JSON message
 *
 * @param[in] cdb The connection object to the confdb
 * @param[out] pd Data structure containing the response_data linked list
 *
 * @return 0 if the data was extracted correctly and JSON message was formatted
 *         properly, error code otherwise.
 */
errno_t
generate_json_auth_message(struct confdb_ctx *cdb, struct pam_data *_pd);


/**
 * @brief Unpack password specific data reply
 *
 * @param[in] jroot jansson structure containing the password specific data
 * @param[out] _password user password
 *
 * @return 0 if the reply was unpacked and the result is ok,
 *         error code otherwise.
 */
errno_t
json_unpack_password(json_t *jroot, char **_password);

/**
 * @brief Unpack GDM reply and check its value
 *
 * @param[in] pd pam_data containing the GDM reply in JSON format
 *
 * @return 0 if the reply was unpacked and the result is ok,
 *         error code otherwise.
 */
errno_t
json_unpack_auth_reply(struct pam_data *pd);

#endif /* __PAMSRV_JSON__H__ */
