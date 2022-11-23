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
#define USER_ID_SIZE    32
#define TIMEOUT         15
#define FREQUENCY       1

enum action_opt {
    ACTION_NONE,
    ACTION_REGISTER,
    ACTION_AUTHENTICATE
};

enum credential_type {
    CRED_SERVER_SIDE,
    CRED_DISCOVERABLE
};

struct passkey_data {
    enum action_opt action;
    const char *shortname;
    const char *domain;
    char **public_key_list;
    char **key_handle_list;
    int keys_size;
    int type;
    fido_opt_t user_verification;
    enum credential_type cred_type;
    unsigned char *user_id;
    bool quiet;
    bool debug_libfido2;
};

struct pk_data_t {
    void *public_key;
    int type;
};

/**
 * @brief Parse arguments
 *
 * @param[in] mem_ctx Memory context
 * @param[in] argc Number of arguments
 * @param[in] argv Argument list
 * @param[out] data passkey data
 *
 * @return 0 if the arguments were parsed properly,
 *         another value on error.
 */
errno_t
parse_arguments(TALLOC_CTX *mem_ctx, int argc, const char *argv[],
                struct passkey_data *data);

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
 * @param[in] action Action to perform with the key
 * @param[in] dev_list passkey device list
 * @param[in] dev_index passkey device index
 * @param[in] assert Assert
 * @param[out] dev Device information
 *
 * @return 0 if the device was opened properly, another value on error.
 */
errno_t
select_device(enum action_opt action, fido_dev_info_t *dev_list,
              size_t dev_list_len, fido_assert_t *assert,
              fido_dev_t **_dev);

/**
 * @brief Get authenticator data from assert
 *
 * @param[in] dev_list passkey device list
 * @param[in] dev_list_len passkey device list length
 * @param[in] assert Assert
 * @param[out] dev Authenticator data
 *
 * @return 0 if the authenticator data was retrieved properly,
 *         another value on error.
 */
errno_t
select_from_multiple_devices(fido_dev_info_t *dev_list,
                             size_t dev_list_len,
                             fido_assert_t *assert,
                             fido_dev_t **_dev);

/**
 * @brief Receive PIN via stdin
 *
 * @param[in] mem_ctx Memory context
 * @param[in] fd File descriptor
 * @param[out] pin Pin
 *
 * @return 0 if the authenticator data was received properly,
 *         error code otherwise.
 */
errno_t
passkey_recv_pin(TALLOC_CTX *mem_ctx, int fd, char **_pin);

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

/*
 * @brief Authenticate a user
 *
 * Prepare the assertion request data, select the device to use, get the device
 * options and compare them with the organization policy, decode the public
 * key, request the assert and verify it.
 *
 * @param[in] data passkey data
 *
 * @return 0 if the user was authenticated properly,
 *         error code otherwise.
 */
errno_t
authenticate(struct passkey_data *data);

/**
 * @brief Get user id from assert
 *
 * @param[in] mem_ctx Memory context
 * @param[in] assert Assert
 * @param[out] _user_id User id
 *
 * @return 0 if the user id was obtained properly, error code otherwise.
 */
errno_t
get_assert_user_id(TALLOC_CTX *mem_ctx, fido_assert_t *assert,
                   unsigned char **_user_id);

/**
 * @brief Set client data hash in the assert
 *
 * @param[out] assert Assert
 *
 * @return 0 if the data was set properly,
 *         error code otherwise.
 */
errno_t
set_assert_client_data_hash(fido_assert_t *_assert);

/**
 * @brief Set options in the assert
 *
 * @param[in] up User presence check
 * @param[in] uv User verification check
 * @param[out] assert Assert
 *
 * @return 0 if the data was set properly,
 *         error code otherwise.
 */
errno_t
set_assert_options(fido_opt_t up, fido_opt_t uv, fido_assert_t *_assert);

/**
 * @brief Prepare assert
 *
 * @param[in] data passkey data
 * @param[in] count Index for key handle list
 * @param[out] assert Assert
 *
 * @return 0 if the assert was prepared properly,
 *         error code otherwise.
 */
errno_t
prepare_assert(const struct passkey_data *data, int index,
               fido_assert_t *_assert);

/**
 * @brief Reset and free public key
 *
 * @param[out] _pk_data Public key data
 *
 * @return 0 if the public key was reset properly,
 *         error code otherwise.
 */
errno_t
reset_public_key(struct pk_data_t *_pk_data);

/**
 * @brief Format EVP_PKEY to libfido2's es256 data structure
 *
 * @param[in] evp_pkey EVP_PKEY public key
 * @param[out] _pk_data Public key data
 *
 * @return 0 if the public key was formatted properly,
 *         error code otherwise.
 */
errno_t
evp_pkey_to_es256_pubkey(const EVP_PKEY *evp_pkey, struct pk_data_t *_pk_data);

/**
 * @brief Format EVP_PKEY to libfido2's rs256 data structure
 *
 * @param[in] evp_pkey EVP_PKEY public key
 * @param[out] _pk_data Public key data
 *
 * @return 0 if the public key was formatted properly,
 *         error code otherwise.
 */
errno_t
evp_pkey_to_rs256_pubkey(const EVP_PKEY *evp_pkey, struct pk_data_t *_pk_data);

/**
 * @brief Format EVP_PKEY to libfido2's eddsa data structure
 *
 * @param[in] evp_pkey EVP_PKEY public key
 * @param[out] _pk_data Public key data
 *
 * @return 0 if the public key was formatted properly,
 *         error code otherwise.
 */
errno_t
evp_pkey_to_eddsa_pubkey(const EVP_PKEY *evp_pkey, struct pk_data_t *_pk_data);

/**
 * @brief Format the public key to the libfido2 data structure
 *
 * @param[in] pem_public_key PEM formatter public key
 * @param[out] _pk_data Public key data
 *
 * @return 0 if the public key was formatted properly,
 *         error code otherwise.
 */
errno_t
public_key_to_libfido2(const char *pem_public_key, struct pk_data_t *_pk_data);

/**
 * @brief Get device options and compare with the policy options expectations
 *
 * @param[in] dev Device information
 * @param[out] data passkey data
 *
 * @return 0 if the device data was retrieved and the options match properly,
 *         error code otherwise.
 */
errno_t
get_device_options(fido_dev_t *dev, struct passkey_data *_data);

/**
 * @brief Get assertion data
 *
 * @param[in] data passkey data
 * @param[in] dev Device information
 * @param[out] assert Assert
 *
 * @return 0 if the assertion was verified properly,
 *         error code otherwise.
 */
errno_t
request_assert(struct passkey_data *data, fido_dev_t *dev,
               fido_assert_t *_assert);

/**
 * @brief Verify assertion
 *
 * @param[in] pk_data Public key data
 * @param[in] assert Assert
 *
 * @return 0 if the assertion was verified properly,
 *         error code otherwise.
 */
errno_t
verify_assert(struct pk_data_t *data, fido_assert_t *assert);

#endif /* __PASSKEY_CHILD_H__ */
