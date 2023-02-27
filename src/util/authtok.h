/*
   SSSD - auth utils

   Copyright (C) Simo Sorce <simo@redhat.com> 2012

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

#ifndef __AUTHTOK_H__
#define __AUTHTOK_H__

#include "util/util.h"
#include "util/authtok-utils.h"
#include "sss_client/sss_cli.h"

#define IS_SC_AUTHTOK(tok) ( \
    sss_authtok_get_type((tok)) == SSS_AUTHTOK_TYPE_SC_PIN \
        || sss_authtok_get_type((tok)) == SSS_AUTHTOK_TYPE_SC_KEYPAD)


/* Use sss_authtok_* accessor functions instead of struct sss_auth_token
 */
struct sss_auth_token;

/**
 * @brief Converts token type to string for debugging purposes.
 *
 * @param type   Tonen type
 *
 * @return       Token type string representation
 */
const char *sss_authtok_type_to_str(enum sss_authtok_type type);

/**
 * @brief Returns the token type
 *
 * @param tok    A pointer to an sss_auth_token
 *
 * @return       An sss_authtok_type (empty, password, ...)
 */
enum sss_authtok_type sss_authtok_get_type(struct sss_auth_token *tok);

/**
 * @brief Returns the token size
 *
 * @param tok    A pointer to an sss_auth_token
 *
 * @return       The current size of the token payload
 */
size_t sss_authtok_get_size(struct sss_auth_token *tok);

/**
 * @brief Get the data buffer
 *
 * @param tok    A pointer to an sss_auth_token
 *
 * @return       A pointer to the token payload
 */
uint8_t *sss_authtok_get_data(struct sss_auth_token *tok);

/**
 * @brief Returns a const string if the auth token is of type
          SSS_AUTHTOK_TYPE_PASSWORD, otherwise it returns an error
 *
 * @param tok    A pointer to an sss_auth_token
 * @param pwd    A pointer to a const char *, that will point to a null
 *               terminated string
 * @param len    The length of the password string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a password token
 */
errno_t sss_authtok_get_password(struct sss_auth_token *tok,
                                 const char **pwd, size_t *len);

/**
 * @brief Set a password into an auth token, replacing any previous data
 *
 * @param tok        A pointer to an sss_auth_token structure to change, also
 *                   used as a memory context to allocate the internal data.
 * @param password   A string
 * @param len        The length of the string or, if 0 is passed,
 *                   then strlen(password) will be used internally.
 *
 * @return       EOK on success
 *               ENOMEM on error
 */
errno_t sss_authtok_set_password(struct sss_auth_token *tok,
                                 const char *password, size_t len);

/**
 * @brief Returns a const string if the auth token is of type
         SSS_AUTHTOK_TYPE_CCFILE, otherwise it returns an error
 *
 * @param tok    A pointer to an sss_auth_token
 * @param ccfile A pointer to a const char *, that will point to a null
 *               terminated string, also used as a memory context use to allocate the internal data
 * @param len    The length of the string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a password token
 */
errno_t sss_authtok_get_ccfile(struct sss_auth_token *tok,
                               const char **ccfile, size_t *len);

/**
 * @brief Set a cc file name into an auth token, replacing any previous data
 *
 * @param tok        A pointer to an sss_auth_token structure to change, also
 *                   used as a memory context to allocate the internal data.
 * @param ccfile     A null terminated string
 * @param len    The length of the string
 *
 * @return       EOK on success
 *               ENOMEM on error
 */
errno_t sss_authtok_set_ccfile(struct sss_auth_token *tok,
                               const char *ccfile, size_t len);

/**
 * @brief Resets an auth token to the empty status
 *
 * @param tok    A pointer to an sss_auth_token structure to reset
 *
 * NOTE: This function uses sss_erase_mem_securely() on the payload if the type
 * is SSS_AUTHTOK_TYPE_PASSWORD
 */
void sss_authtok_set_empty(struct sss_auth_token *tok);

/**
 * @brief Set an auth token by type, replacing any previous data
 *
 * @param tok        A pointer to an sss_auth_token structure to change, also
 *                   used as a memory context to allocate the internal data.
 * @param type       A valid authtok type
 * @param data       A data pointer
 * @param len        The length of the data
 *
 * @return       EOK on success
 *               ENOMEM or EINVAL on error
 */
errno_t sss_authtok_set(struct sss_auth_token *tok,
                        enum sss_authtok_type type,
                        const uint8_t *data, size_t len);

/**
 * @brief Copy an auth token from source to destination
 *
 * @param src        The source auth token
 * @param dst        The destination auth token, also used as a memory context
 *                   to allocate dst internal data.
 *
 * @return       EOK on success
 *               ENOMEM on error
 */
errno_t sss_authtok_copy(struct sss_auth_token *src,
                         struct sss_auth_token *dst);

/**
 * @brief Uses sss_erase_mem_securely to wipe the password from memory
 *        if the authtoken contains a password, otherwise does nothing.
 *
 * @param tok       A pointer to an sss_auth_token structure to change
 *
 * NOTE: This function should only be used in destructors or similar
 * functions where freeing the actual string is unsafe and where it can
 * be guaranteed that the auth token will not be used anymore.
 * Use sss_authtok_set_empty() in normal circumstances.
 */
void sss_authtok_wipe_password(struct sss_auth_token *tok);

/**
 * @brief Create new empty struct sss_auth_token.
 *
 * @param mem_ctx    A memory context use to allocate the internal data
 * @return           A pointer to new empty struct sss_auth_token
 *                   NULL in case of failure
 *
 * NOTE: This function is the only way, how to create new empty
 * struct sss_auth_token.
 */
struct sss_auth_token *sss_authtok_new(TALLOC_CTX *mem_ctx);

/**
 * @brief Set authtoken with 2FA data
 *
 * @param tok            A pointer to an sss_auth_token structure to change, also
 *                       used as a memory context to allocate the internal data.
 * @param[in]  fa1       First authentication factor, null terminated
 * @param[in]  fa1_len   Length of the first authentication factor, if 0
 *                       strlen() will be called internally
 * @param[in]  fa2       Second authentication factor, null terminated
 * @param[in]  fa2_len   Length of the second authentication factor, if 0
 *                       strlen() will be called internally
 *
 * @return     EOK    on success
 *             ENOMEM if memory allocation failed
 *             EINVAL if input data is not consistent
 */
errno_t sss_authtok_set_2fa(struct sss_auth_token *tok,
                            const char *fa1, size_t fa1_len,
                            const char *fa2, size_t fa2_len);

/**
 * @brief Get 2FA factors from authtoken
 *
 * @param tok            A pointer to an sss_auth_token structure to change, also
 *                       used as a memory context to allocate the internal data.
 * @param[out] fa1       A pointer to a const char *, that will point to a
 *                       null terminated string holding the first
 *                       authentication factor, may not be modified or freed
 * @param[out] fa1_len   Length of the first authentication factor
 * @param[out] fa2       A pointer to a const char *, that will point to a
 *                       null terminated string holding the second
 *                       authentication factor, may not be modified or freed
 * @param[out] fa2_len   Length of the second authentication factor
 *
 * @return     EOK     on success
 *             ENOMEM  if memory allocation failed
 *             EINVAL  if input data is not consistent
 *             ENOENT  if the token is empty
 *             EACCESS if the token is not a 2FA token
 */
errno_t sss_authtok_get_2fa(struct sss_auth_token *tok,
                            const char **fa1, size_t *fa1_len,
                            const char **fa2, size_t *fa2_len);

/**
 * @brief Set a Smart Card PIN into an auth token, replacing any previous data
 *
 * @param tok        A pointer to an sss_auth_token structure to change, also
 *                   used as a memory context to allocate the internal data.
 * @param pin        A string
 * @param len        The length of the string or, if 0 is passed,
 *                   then strlen(password) will be used internally.
 *
 * @return       EOK on success
 *               ENOMEM on error
 */
errno_t sss_authtok_set_sc_pin(struct sss_auth_token *tok, const char *pin,
                               size_t len);

/**
 * @brief Returns a Smart Card PIN as const string if the auth token is of
 *        type SSS_AUTHTOK_TYPE_SC_PIN, otherwise it returns an error
 *
 * @param tok    A pointer to an sss_auth_token
 * @param pin    A pointer to a const char *, that will point to a null
 *               terminated string
 * @param len    The length of the pin string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a Smart Card PIN token
 */
errno_t sss_authtok_get_sc_pin(struct sss_auth_token *tok, const char **pin,
                               size_t *len);

/**
 * @brief Sets an auth token to type SSS_AUTHTOK_TYPE_SC_KEYPAD, replacing any
 *        previous data
 *
 * @param tok        A pointer to an sss_auth_token structure to change, also
 *                   used as a memory context to allocate the internal data.
 */
void sss_authtok_set_sc_keypad(struct sss_auth_token *tok);

/**
 * @brief Set complete Smart Card authentication blob including PKCS#11 token
 *        name, module name and key id.
 *
 * @param tok             A pointer to an sss_auth_token
 * @param type            Authentication token type, may be
 *                        SSS_AUTHTOK_TYPE_SC_PIN or SSS_AUTHTOK_TYPE_SC_KEYPAD
 * @param pin             A pointer to a const char *, that will point to a null
 *                        terminated string containing the PIN
 * @param pin_len         The length of the pin string, if set to 0 it will be
 *                        calculated
 * @param token_name      A pointer to a const char *, that will point to a null
 *                        terminated string containing the PKCS#11 token name
 * @param token_name_len  The length of the token name string, if set to 0 it
 *                        will be calculated
 * @param module_name     A pointer to a const char *, that will point to a null
 *                        terminated string containing the PKCS#11 module name
 * @param module_name_len The length of the module name string, if set to 0 it
 *                        will be calculated
 * @param key_id          A pointer to a const char *, that will point to a null
 *                        terminated string containing the PKCS#11 key id
 * @param key_id_len      The length of the key id string, if set to 0 it will be
 *                        calculated
 * @param label           A pointer to a const char *, that will point to a null
 *                        terminated string containing the PKCS#11 label
 * @param label_len       The length of the label string, if set to 0 it will be
 *                        calculated
 *
 * @return       EOK on success
 *               EINVAL unexpected or inval input
 *               ENOMEM memory allocation error
 */
errno_t sss_authtok_set_sc(struct sss_auth_token *tok,
                           enum sss_authtok_type type,
                           const char *pin, size_t pin_len,
                           const char *token_name, size_t token_name_len,
                           const char *module_name, size_t module_name_len,
                           const char *key_id, size_t key_id_len,
                           const char *label, size_t label_len);
/**
 * @brief Set a Smart Card authentication data, replacing any previous data
 *
 * @param tok    A pointer to an sss_auth_token structure to change, also
 *               used as a memory context to allocate the internal data.
 * @param data   Smart Card authentication data blob
 * @param len    The length of the blob
 *
 * @return       EOK on success
 *               ENOMEM on error
 */
errno_t sss_authtok_set_sc_from_blob(struct sss_auth_token *tok,
                                     const uint8_t *data,
                                     size_t len);

/**
 * @brief Get complete Smart Card authtoken data
 *
 * @param tok                   A pointer to an sss_auth_token structure
 * @param[out] _pin             A pointer to a const char *, that will point to
 *                              a null terminated string holding the PIN,
 *                              may not be modified or freed
 * @param[out] _pin__len        Length of the PIN
 * @param[out] _token_name      A pointer to a const char *, that will point to
 *                              a null terminated string holding the PKCS#11
 *                              token name, may not be modified or freed
 * @param[out] _token_name_len  Length of the PKCS#11 token name
 * @param[out] _module_name     A pointer to a const char *, that will point to
 *                              a null terminated string holding the PKCS#11
 *                              module name, may not be modified or freed
 * @param[out] _module_name_len Length of the PKCS#11 module name
 * @param[out] _key_id          A pointer to a const char *, that will point to
 *                              a null terminated string holding the PKCS#11
 *                              key id, may not be modified or freed
 * @param[out] _key_id_len      Length of the PKCS#11 key id
 * @param[out] _label           A pointer to a const char *, that will point to
 *                              a null terminated string holding the PKCS#11
 *                              label, may not be modified or freed
 * @param[out] _label_len       Length of the PKCS#11 label
 *
 * Any of the output pointers may be NULL if the caller does not need the
 * specific item.
 *
 * @return     EOK     on success
 *             EFAULT  missing token
 *             EINVAL  if input data is not consistent
 *             ENOENT  if the token is empty
 *             EACCESS if the token is not a Smart Card token
 */
errno_t sss_authtok_get_sc(struct sss_auth_token *tok,
                           const char **_pin, size_t *_pin_len,
                           const char **_token_name, size_t *_token_name_len,
                           const char **_module_name, size_t *_module_name_len,
                           const char **_key_id, size_t *_key_id_len,
                           const char **_label, size_t *_label_len);


/**
 * @brief Returns a const string if the auth token is of type
          SSS_AUTHTOK_TYPE_2FA_SINGLE, otherwise it returns an error
 *
 * @param tok    A pointer to an sss_auth_token
 * @param pwd    A pointer to a const char *, that will point to a null
 *               terminated string
 * @param len    The length of the credential string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a password token
 */
errno_t sss_authtok_get_2fa_single(struct sss_auth_token *tok,
                                   const char **str, size_t *len);

/**
 * @brief Set a 2FA credentials in a single strings  into an auth token,
 *        replacing any previous data
 *
 * @param tok        A pointer to an sss_auth_token structure to change, also
 *                   used as a memory context to allocate the internal data.
 * @param str        A string where the two authentication factors are
 *                   concatenated together
 * @param len        The length of the string or, if 0 is passed,
 *                   then strlen(password) will be used internally.
 *
 * @return       EOK on success
 *               ENOMEM on error
 */
errno_t sss_authtok_set_2fa_single(struct sss_auth_token *tok,
                                   const char *str, size_t len);

/**
 * @brief Returns a const string if the auth token is of type
          SSS_AUTHTOK_TYPE_OAUTH2, otherwise it returns an error
 *
 * @param tok    A pointer to an sss_auth_token
 * @param pwd    A pointer to a const char *, that will point to a null
 *               terminated string
 * @param len    The length of the credential string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a password token
 */
errno_t sss_authtok_get_oauth2(struct sss_auth_token *tok,
                               const char **str, size_t *len);

/**
 * @brief Set one-time password into an auth token, replacing any previous data.
 *
 * @param tok        A pointer to an sss_auth_token structure to change, also
 *                   used as a memory context to allocate the internal data.
 * @param str   A string that holds the one-time password.
 * @param len        The length of the string or, if 0 is passed,
 *                   then strlen(password) will be used internally.
 *
 * @return       EOK on success
 *               ENOMEM on error
 */
errno_t sss_authtok_set_oauth2(struct sss_auth_token *tok,
                               const char *str, size_t len);
/**
 * @brief Returns a const string if the auth token is of type
          SSS_AUTHTOK_TYPE_PASSKEY_REPLY, otherwise it returns an error
 *
 * @param tok    A pointer to an sss_auth_token
 * @param str    A string that holds the passkey assertion data
 * @param len    The length of the credential string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a passkey token
 */
errno_t sss_authtok_set_passkey_reply(struct sss_auth_token *tok,
                                      const char *str, size_t len);
/**
 * @brief Returns a const string if the auth token is of type
          SSS_AUTHTOK_TYPE_PASSKEY_REPLY, otherwise it returns an error
 *
 * @param tok    A pointer to an sss_auth_token
 * @param str    A pointer to a const char *, that will point to a null
 *               terminated string
 * @param len    The length of the credential string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a password token
 */
errno_t sss_authtok_get_passkey_reply(struct sss_auth_token *tok,
                                      const char **str, size_t *len);

/**
 * @brief Returns a const string if the auth token is of type
          SSS_AUTHTOK_TYPE_PASSKEY, otherwise it returns an error
 *
 * @param mem_ctx    Parent talloc context to attach to
 * @param tok    A pointer to an sss_auth_token
 * @param prompt A pointer to a const char *, that will point to a null
 *               terminated string
 * @param key    A pointer to a const char *, that will point to a null
 *               terminated string
 * @param pin    A pointer to a const char *, that will point to a null
 *               terminated string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a password token
 */
errno_t sss_authtok_get_passkey(TALLOC_CTX *mem_ctx,
                                struct sss_auth_token *tok,
                                const char **_prompt, const char **_key,
                                const char **_pin, size_t *_pin_len);
/**
 * @brief Returns a const string if the auth token is of type
          SSS_AUTHTOK_TYPE_PASSKEY, otherwise it returns the error code
 *
 * @param tok    A pointer to an sss_auth_token
 * @param pwd    A pointer to a const char *, that will point to a null
 *               terminated string
 * @param len    The length of the credential string
 *
 * @return       EOK on success
 *               ENOENT if the token is empty
 *               EACCESS if the token is not a password token
 */
errno_t sss_authtok_get_passkey_pin(struct sss_auth_token *tok,
                                    const char **pin, size_t *len);

/**
 * @brief Set passkey kerberos preauth credentials into an auth token,
 *        replacing any previous data.
 *
 * @param tok        A pointer to an sss_auth_token structure to change, also
 *                   used as a memory context to allocate the internal data.
 * @param pin        A string that holds the passkey PIN.
 * @param len        The length of the string or, if 0 is passed,
 *                   then strlen(password) will be used internally.
 *
 * @return       EOK on success
 *               ENOMEM on error
 */
errno_t sss_authtok_set_passkey_krb(struct sss_auth_token *tok,
                                    const char *prompt, const char *key,
                                    const char *pin);
#endif /*  __AUTHTOK_H__ */
