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
#include "sss_client/sss_cli.h"

/* Use sss_authtok_* accesor functions instead of struct sss_auth_token
 */
struct sss_auth_token;

/**
 * @brief Returns the token type
 *
 * @param tok    A pointer to an sss_auth_token
 *
 * @return       A sss_authtok_type (empty, password, ...)
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
 * @brief Set a password into a an auth token, replacing any previous data
 *
 * @param tok        A pointer to a sss_auth_token structure to change, also
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
 * @brief Set a cc file name into a an auth token, replacing any previous data
 *
 * @param tok        A pointer to a sss_auth_token structure to change, also
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
 * @param tok    A pointer to a sss_auth_token structure to reset
 *
 * NOTE: This function uses safezero() on the payload if the type
 * is SSS_AUTHTOK_TYPE_PASSWORD
 */
void sss_authtok_set_empty(struct sss_auth_token *tok);

/**
 * @brief Set an auth token by type, replacing any previous data
 *
 * @param tok        A pointer to a sss_auth_token structure to change, also
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
 * @brief Uses safezero to wipe the password from memory if the
 *        authtoken contains a password, otherwise does nothing.
 *
 * @param tok       A pointer to a sss_auth_token structure to change
 *
 * NOTE: This function should only be used in destructors or similar
 * functions where freing the actual string is unsafe and where it can
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

#endif /*  __AUTHTOK_H__ */
