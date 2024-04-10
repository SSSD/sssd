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

#define PASSWORD_PROMPT     "Password"
#define OAUTH2_INIT_PROMPT  "Log In"
#define OAUTH2_LINK_PROMPT  "Log in online with another device"
#define SC_INIT_PROMPT      "Insert smartcard"
#define SC_PIN_PROMPT       "PIN"


/**
 * @brief Extract smartcard certificate list from pam_data structure
 *
 * @param[in] mem_ctx Memory context
 * @param[in] pd pam_data containing the certificates
 * @param[out] _cert_list Certificate list
 *
 * @return 0 if the data was extracted successfully,
 *         error code otherwise.
 */
errno_t
get_cert_list(TALLOC_CTX *mem_ctx, struct pam_data *pd,
              struct cert_auth_info **_cert_list);

/**
 * @brief Extract smartcard certificate name list from the certificate list
 *
 * @param[in] mem_ctx Memory context
 * @param[in] cert_list Certificate list
 * @param[out] _names Certificate names list
 *
 * @return 0 if the data was extracted successfully,
 *         error code otherwise.
 */
errno_t
get_cert_names(TALLOC_CTX *mem_ctx, struct cert_auth_info *cert_list,
               char ***_names);

/**
 * @brief Format authentication mechanisms to JSON
 *
 * @param[in] password_auth Whether password authentication is allowed
 * @param[in] password_prompt Password prompt
 * @param[in] oath2_auth Whether OAUTH2 authentication is allowed
 * @param[in] uri OAUTH2 uri
 * @param[in] code OAUTH2 code
 * @param[in] oauth2_init_prompt OAUTH2 initial prompt
 * @param[in] oauth2_link_prompt OAUTH2 link prompt
 * @param[in] sc_auth Whether smartcard authentication is allowed
 * @param[in] sc_names smartcard names
 * @param[in] sc_init_prompt smartcard initial prompt
 * @param[in] sc_pin_prompt smartcard PIN prompt
 * @param[out] _list_mech authentication mechanisms JSON object
 *
 * @return 0 if the authentication mechanisms were formatted properly,
 *         error code otherwise.
 */
errno_t
json_format_mechanisms(bool password_auth, const char *password_prompt,
                       bool oauth2_auth, const char *uri, const char *code,
                       const char *oauth2_init_prompt,
                       const char *oauth2_link_prompt,
                       bool sc_auth, char **sc_names,
                       const char *sc_init_prompt,
                       const char *sc_pin_prompt,
                       json_t **_list_mech);

/**
 * @brief Format priority to JSON
 *
 * @param[in] password_auth Whether password authentication is allowed
 * @param[in] oath2_auth Whether OAUTH2 authentication is allowed
 * @param[in] sc_auth Whether smartcard authentication is allowed
 * @param[in] sc_names Smartcard certificate names
 * @param[out] _priority priority JSON object
 *
 * @return 0 if the priority was formatted properly,
 *         error code otherwise.
 */
errno_t
json_format_priority(bool password_auth, bool oauth2_auth, bool sc_auth,
                     char **sc_names, json_t **_priority);

/**
 * @brief Format data to JSON
 *
 * @param[in] mem_ctx Memory context
 * @param[in] password_auth Whether password authentication is allowed
 * @param[in] password_prompt Password prompt
 * @param[in] oath2_auth Whether OAUTH2 authentication is allowed
 * @param[in] uri OAUTH2 uri
 * @param[in] code OAUTH2 code
 * @param[in] oauth2_init_prompt OAUTH2 initial prompt
 * @param[in] oauth2_link_prompt OAUTH2 link prompt
 * @param[in] sc_auth Whether smartcard authentication is allowed
 * @param[in] sc_names smartcard names
 * @param[in] sc_init_prompt smartcard initial prompt
 * @param[in] sc_pin_prompt smartcard PIN prompt
 * @param[out] _result JSON message
 *
 * @return 0 if the JSON message was formatted properly,
 *         error code otherwise.
 */
errno_t
json_format_auth_selection(TALLOC_CTX *mem_ctx,
                           bool password_auth, const char *password_prompt,
                           bool oath2_auth, const char *uri, const char *code,
                           const char *oauth2_init_prompt,
                           const char *oauth2_link_prompt,
                           bool sc_auth, char **sc_names,
                           const char *sc_init_prompt,
                           const char *sc_pin_prompt,
                           char **_result);

/**
 * @brief Check the internal data and generate the JSON message
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] pc_list List that contains all authentication mechanisms prompts
 * @param[out] pd Data structure containing the response_data linked list
 *
 * @return 0 if the data was extracted correctly and JSON message was formatted
 *         properly, error code otherwise.
 */
errno_t
generate_json_auth_message(struct confdb_ctx *cdb,
                           struct prompt_config **pc_list,
                           struct pam_data *_pd);


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
 * @brief Unpack OAUTH2 code
 *
 * @param[in] mem_ctx Memory context
 * @param[in] json_auth_msg JSON authentication mechanisms message
 * @param[out] _oauth2_code OAUTH2 code
 *
 * @return 0 if the reply was unpacked and the result is ok,
 *         error code otherwise.
 */
errno_t
json_unpack_oauth2_code(TALLOC_CTX *mem_ctx, char *json_auth_msg,
                        char **_oauth2_code);

/**
 * @brief Unpack smartcard specific data reply
 *
 * @param[in] jroot jansson structure containing the smartcard specific data
 * @param[out] _pin user PIN
 */
errno_t
json_unpack_smartcard(json_t *jroot, const char **_pin);

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

/**
 * @brief Check whether the PAM service file in use is enabled for the JSON
 * protocol
 *
 * @param[in] json_services Enabled PAM services for JSON protocol
 * @param[in] service PAM service file in use
 *
 * @return true if the JSON protocol is enabled for the PAM service file,
 *         false otherwise.
 */
bool is_pam_json_enabled(char **json_services,
                         char *service);

#endif /* __PAMSRV_JSON__H__ */
