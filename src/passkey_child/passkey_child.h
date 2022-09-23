/*
    SSSD

    Helper child to commmunicate with passkey devices

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2022 Red Hat

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

#ifndef __PASSKEY_CHILD_H__
#define __PASSKEY_CHILD_H__

#include <fido.h>

#define DEFAULT_PROMPT "Insert your passkey device, then press ENTER."
#define DEFAULT_CUE "Please touch the device."

#define DEVLIST_SIZE    64
#define TIMEOUT         15
#define FREQUENCY       1

enum action_opt {
    ACTION_NONE,
    ACTION_REGISTER,
    ACTION_AUTHENTICATE
};

struct passkey_data {
    enum action_opt action;
    const char *shortname;
    const char *domain;
    char *public_key;
    char *key_handle;
    int type;
    fido_opt_t user_verification;
    bool debug_libfido2;
};

/**
 * @brief Parse arguments
 *
 * @param[in] argc Number of arguments
 * @param[in] argv Argument list
 * @param[out] data passkey data
 *
 * @return 0 if the arguments were parsed properly,
 *         another value on error.
 */
errno_t
parse_arguments(int argc, const char *argv[], struct passkey_data *data);

/**
 * @brief Check that all the arguments have been set
 *
 * @param[in] data passkey data
 *
 * @return 0 if the arguments were set properly,
 *         another value on error.
 */
errno_t
check_arguments(const struct passkey_data *data);

/**
 * @brief Register a key for a user
 *
 * @param[in] data passkey data
 *
 * @return 0 if the key was registered properly,
 *         another value on error.
 */
errno_t
register_key(struct passkey_data *data);

/**
 * @brief Translate COSE type from string to int
 *
 * @param[in] type string COSE type
 * @param[out] out int COSE type
 *
 * @return 0 if the COSE type has been translated,
 *         another value if the COSE type doesn't exist.
 */
errno_t
cose_str_to_int(const char *type, int *out);

/**
 * @brief Prepare user credentials
 *
 * @param[in] data passkey data
 * @param[in] dev Device information
 * @param[out] cred Credentials
 *
 * @return 0 if the credentials were prepared properly,
 *         another value on error.
 */
errno_t
prepare_credentials(struct passkey_data *data, fido_dev_t *dev,
                    fido_cred_t *cred);

/**
 * @brief List connected passkey devices
 *
 * @param[out] dev_list passkey device list
 * @param[out] dev_number Number of passkey devices
 *
 * @return 0 if the list was retrieved properly, another value on error.
 */
errno_t
list_devices(fido_dev_info_t *dev_list, size_t *dev_number);

/**
 * @brief Select passkey device
 *
 * @param[in] dev_list passkey device list
 * @param[in] dev_index passkey device index
 * @param[out] dev Device information
 *
 * @return 0 if the device was opened properly, another value on error.
 */
errno_t
select_device(fido_dev_info_t *dev_list, size_t dev_index, fido_dev_t *dev);

/**
 * @brief Disable echoing and read PIN from stdin
 *
 * @param[out] line_ptr PIN
 *
 * @return Number of bytes read, or -1 on error.
 */
ssize_t
read_pin(char **line_ptr);

/**
 * @brief Generate passkey credentials
 *
 * @param[in] data passkey data
 * @param[in] dev Device information
 * @param[out] cred Credentials
 *
 * @return 0 if the credentials were generated properly,
 *         another value on error.
 */
errno_t
generate_credentials(struct passkey_data *data, fido_dev_t *dev,
                     fido_cred_t *cred);

/**
 * @brief Verify passkey credentials
 *
 * @param[in] cred Credentials
 *
 * @return 0 if the credentials were verified properly,
 *         another value on error.
 */
errno_t
verify_credentials(const fido_cred_t *const cred);

/**
 * @brief Print passkey credentials
 *
 * @param[in] data passkey data
 * @param[out] cred Credentials
 *
 * @return 0 if the credentials were printed properly,
 *         another value on error.
 */
errno_t
print_credentials(const struct passkey_data *data,
                  const fido_cred_t *const cred);

/**
 * @brief Format libfido2's es256 data structure to EVP_PKEY
 *
 * @param[in] mem_ctx Memory context
 * @param[in] es256_key Public key pointer
 * @param[in] es256_key_len Public key length
 * @param[out] _evp_pkey Pointer to public key structure
 *
 * @return 0 if the key was formatted properly, error code otherwise.
 */
int
es256_pubkey_to_evp_pkey(TALLOC_CTX *mem_ctx, const void *es256_key,
                         size_t es256_key_len, EVP_PKEY **_evp_pkey);

/**
 * @brief Format libfido2's rs256 data structure to EVP_PKEY
 *
 * @param[in] mem_ctx Memory context
 * @param[in] rs256_key Public key pointer
 * @param[in] rs256_key_len Public key length
 * @param[out] _evp_pkey Pointer to public key structure
 *
 * @return 0 if the key was formatted properly, error code otherwise.
 */
int
rs256_pubkey_to_evp_pkey(TALLOC_CTX *mem_ctx, const void *rs256_key,
                         size_t rs256_key_len, EVP_PKEY **_evp_pkey);

/**
 * @brief Format libfido2's eddsa data structure to EVP_PKEY
 *
 * @param[in] mem_ctx Memory context
 * @param[in] eddsa_key Public key pointer
 * @param[in] eddsa_key_len Public key length
 * @param[out] _evp_pkey Pointer to public key structure
 *
 * @return 0 if the key was formatted properly, error code otherwise.
 */
int
eddsa_pubkey_to_evp_pkey(TALLOC_CTX *mem_ctx, const void *eddsa_key,
                         size_t eddsa_key_len, EVP_PKEY **_evp_pkey);

/**
 * @brief Format the public key to base64
 *
 * @param[in] mem_ctx Memory context
 * @param[in] data passkey data
 * @param[in] public_key Public key
 * @param[in] pk_len Public key length
 * @param[out] _pem_key Public key in PEM format
 *
 * @return 0 if the key was formatted properly, error code otherwise.
 */
errno_t
public_key_to_base64(TALLOC_CTX *mem_ctx, const struct passkey_data *data,
                     const unsigned char *public_key, size_t pk_len,
                     char **_pem_key);

#endif /* __PASSKEY_CHILD_H__ */
