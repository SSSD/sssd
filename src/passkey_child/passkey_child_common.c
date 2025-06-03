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

#include <popt.h>
#include <fido/param.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "util/crypto/sss_crypto.h"
#include "util/debug.h"
#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_prctl.h"

#include "passkey_child.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000
#define get_id(x)   EVP_PKEY_get_base_id((x))
#else
#define get_id(x)   EVP_PKEY_base_id((x))
#endif /* OPENSSL_VERSION_NUMBER */

errno_t
cose_str_to_int(const char *type, int *out)
{
    if (strcasecmp(type, "es256") == 0) {
        *out = COSE_ES256;
    } else if (strcasecmp(type, "rs256") == 0) {
        *out = COSE_RS256;
    } else if (strcasecmp(type, "eddsa") == 0) {
        *out = COSE_EDDSA;
    } else {
        *out = 0;
        return ERR_INVALID_CRED_TYPE;
    }

    return EOK;
}

static errno_t
cred_type_str_to_enum(const char *type, enum credential_type *out)
{
    if (strcasecmp(type, "server-side") == 0) {
        *out = CRED_SERVER_SIDE;
    } else if (strcasecmp(type, "discoverable") == 0) {
        *out = CRED_DISCOVERABLE;
    } else {
        *out = 0;
        return ERR_INVALID_CRED_TYPE;
    }

    return EOK;
}

static errno_t
parse_public_keys_and_handlers(TALLOC_CTX *mem_ctx,
                               const char *public_keys,
                               const char *key_handles,
                               struct passkey_data *_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **pk_list = NULL;
    char **kh_list = NULL;
    int pk_num = 0;
    int kh_num = 0;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ERROR("talloc_new() failed\n");
        return ENOMEM;
    }

    ret = split_on_separator(tmp_ctx, public_keys, ',', true, true, &pk_list, &pk_num);
    if (ret != EOK && _data->action == ACTION_AUTHENTICATE) {
        ERROR("Incorrectly formatted public keys.\n");
        goto done;
    }

    ret = split_on_separator(tmp_ctx, key_handles, ',', true, true, &kh_list, &kh_num);
    if (ret != EOK) {
        ERROR("Incorrectly formatted public keys.\n");
        goto done;
    }

    if (_data->action == ACTION_AUTHENTICATE && pk_num != kh_num) {
        ERROR("The number of public keys and key handles don't match.\n");
        goto done;
    }

    _data->public_key_list = talloc_steal(mem_ctx, pk_list);
    _data->key_handle_list = talloc_steal(mem_ctx, kh_list);
    _data->public_key_size = pk_num;
    _data->key_handle_size = kh_num;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
parse_arguments(TALLOC_CTX *mem_ctx, int argc, const char *argv[],
                struct passkey_data *data)
{
    int opt;
    int dumpable = 1;
    int backtrace = 1;
    int debug_fd = -1;
    char *user_verification = NULL;
    char *public_keys = NULL;
    char *key_handles = NULL;
    const char *opt_logger = NULL;
    const char *type = NULL;
    const char *cred_type = NULL;
    poptContext pc;
    errno_t ret;

    /* Set defaults */
    data->action = ACTION_NONE;
    data->shortname = NULL;
    data->domain = NULL;
    data->public_key_list = NULL;
    data->key_handle_list = NULL;
    data->public_key_size = 0;
    data->key_handle_size = 0;
    data->crypto_challenge = NULL;
    data->auth_data = NULL;
    data->signature = NULL;
    data->type = COSE_ES256;
    data->user_verification = FIDO_OPT_OMIT;
    data->cred_type = CRED_SERVER_SIDE;
    data->user_id = NULL;
    data->mapping_file = NULL;
    data->quiet = false;
    data->debug_libfido2 = false;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"dumpable", 0, POPT_ARG_INT, &dumpable, 0,
         _("Allow core dumps"), NULL },
        {"backtrace", 0, POPT_ARG_INT, &backtrace, 0,
         _("Enable debug backtrace"), NULL },
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        SSSD_LOGGER_OPTS
        {"register", 0, POPT_ARG_NONE, NULL, 'r',
         _("Register a passkey for a user"), NULL },
        {"authenticate", 0, POPT_ARG_NONE, NULL, 'a',
         _("Authenticate a user with a passkey"), NULL },
        {"get-assert", 0, POPT_ARG_NONE, NULL, 'g',
         _("Obtain assertion data"), NULL },
        {"verify-assert", 0, POPT_ARG_NONE, NULL, 'v',
         _("Verify assertion data"), NULL },
        {"preflight", 0, POPT_ARG_NONE, NULL, 'p',
         _("Obtain authentication data prior to processing"), NULL },
        {"username", 0, POPT_ARG_STRING, &data->shortname, 0,
         _("Shortname"), NULL },
        {"domain", 0, POPT_ARG_STRING, &data->domain, 0,
         _("Domain"), NULL},
        {"public-key", 0, POPT_ARG_STRING, &public_keys, 0,
         _("Public key"), NULL },
        {"key-handle", 0, POPT_ARG_STRING, &key_handles, 0,
         _("Key handle"), NULL},
        {"cryptographic-challenge", 0, POPT_ARG_STRING,
         &data->crypto_challenge, 0,
         _("Cryptographic challenge"), NULL},
        {"auth-data", 0, POPT_ARG_STRING, &data->auth_data, 0,
         _("Authenticator data"), NULL},
        {"signature", 0, POPT_ARG_STRING, &data->signature, 0,
         _("Signature"), NULL},
        {"type", 0, POPT_ARG_STRING, &type, 0,
         _("COSE type to use"), "es256|rs256|eddsa"},
        {"user-verification", 0, POPT_ARG_STRING, &user_verification, 0,
         _("Require user-verification"), "true|false"},
        {"cred-type", 0, POPT_ARG_STRING, &cred_type, 0,
         _("Credential type"), "server-side|discoverable"},
        {"output-file", 0, POPT_ARG_STRING, &data->mapping_file, 0,
         _("Write key mapping data to file"), NULL},
        {"quiet", 0, POPT_ARG_NONE, NULL, 'q',
         _("Supress prompts"), NULL},
        {"debug-libfido2", 0, POPT_ARG_NONE, NULL, 'd',
         _("Enable debug in libfido2 library"), NULL},
        SSSD_LOGGER_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);

    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        case 'r':
            if (data->action != ACTION_NONE
                && data->action != ACTION_REGISTER) {
                fprintf(stderr, "\nActions are mutually exclusive and should" \
                                " be used only once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                ret = EINVAL;
                goto done;
            }
            data->action = ACTION_REGISTER;
            break;
        case 'a':
            if (data->action != ACTION_NONE
                && data->action != ACTION_AUTHENTICATE) {
                fprintf(stderr, "\nActions are mutually exclusive and should" \
                                " be used only once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                ret = EINVAL;
                goto done;
            }
            data->action = ACTION_AUTHENTICATE;
            break;
        case 'g':
            if (data->action != ACTION_NONE
                && data->action != ACTION_GET_ASSERT) {
                fprintf(stderr, "\nActions are mutually exclusive and should" \
                                " be used only once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                ret = EINVAL;
                goto done;
            }
            data->action = ACTION_GET_ASSERT;
            break;
        case 'v':
            if (data->action != ACTION_NONE
                && data->action != ACTION_VERIFY_ASSERT) {
                fprintf(stderr, "\nActions are mutually exclusive and should" \
                                " be used only once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                ret = EINVAL;
                goto done;
            }
            data->action = ACTION_VERIFY_ASSERT;
            break;
        case 'p':
            if (data->action != ACTION_NONE) {
                fprintf(stderr, "\nActions are mutually exclusive and should" \
                                " be used only once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                ret = EINVAL;
                goto done;
            }
            data->action = ACTION_PREFLIGHT;
            break;
        case 'q':
            data->quiet = true;
            break;
        case 'd':
            data->debug_libfido2 = true;
            break;
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            ret = EINVAL;
            goto done;
        }
    }

    poptFreeContext(pc);

    sss_prctl_set_dumpable((dumpable == 0) ? 0 : 1);

    if (user_verification != NULL) {
        if (strcmp(user_verification, "true") == 0) {
            data->user_verification = FIDO_OPT_TRUE;
        } else if (strcmp(user_verification, "false") == 0) {
            data->user_verification = FIDO_OPT_FALSE;
        } else if (user_verification != NULL) {
            ERROR("[%s] is not a valid user-verification value.\n",
                  user_verification);
            ret = EINVAL;
            goto done;
        }
    }

    if (type != NULL) {
        ret = cose_str_to_int(type, &data->type);
        if (ret != EOK) {
            ERROR("[%s] is not a valid COSE type (es256, rs256 or eddsa).\n",
                  type);
            goto done;
        }
    }

    if (public_keys != NULL || key_handles != NULL) {
        ret = parse_public_keys_and_handlers(mem_ctx, public_keys, key_handles,
                                             data);
        if (ret != EOK) {
            goto done;
        }
    }

    if (cred_type != NULL) {
        ret = cred_type_str_to_enum(cred_type, &data->cred_type);
        if (ret != EOK) {
            ERROR("[%s] is not a valid credential type (server-side or"
                  " discoverable).\n",
                  cred_type);
            goto done;
        }
    }

    debug_prg_name = talloc_asprintf(NULL, "passkey_child[%d]", getpid());
    if (debug_prg_name == NULL) {
        ERROR("talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (debug_fd != -1) {
        opt_logger = sss_logger_str[FILES_LOGGER];
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            opt_logger = sss_logger_str[STDERR_LOGGER];
            ERROR("set_debug_file_from_fd failed.\n");
        }
    }

    DEBUG_INIT(debug_level, opt_logger);
    sss_set_debug_backtrace_enable((backtrace == 0) ? false : true);

    ret = EOK;

done:
    return ret;
}

errno_t
check_arguments(const struct passkey_data *data)
{
    errno_t ret = EOK;

    DEBUG(SSSDBG_TRACE_FUNC, "Argument values after parsing\n");
    DEBUG(SSSDBG_TRACE_FUNC, "action: %d\n", data->action);
    DEBUG(SSSDBG_TRACE_FUNC, "shortname: %s, domain: %s\n",
          data->shortname, data->domain);
    DEBUG(SSSDBG_TRACE_FUNC, "Number of key handles %d\n",
          data->key_handle_size);
    for (int i = 0; i < data->key_handle_size; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, "key %d, key_handle: %s\n",
              i + 1, data->key_handle_list[i]);
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Number of public keys %d\n",
          data->public_key_size);
    for (int i = 0; i < data->public_key_size; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, "key %d, public_key: %s\n",
              i + 1, data->public_key_list[i]);
    }
    DEBUG(SSSDBG_TRACE_FUNC, "cryptographic-challenge: %s\n",
          data->crypto_challenge);
    DEBUG(SSSDBG_TRACE_FUNC, "auth-data: %s\n",
          data->auth_data);
    DEBUG(SSSDBG_TRACE_FUNC, "signature: %s\n",
          data->signature);
    DEBUG(SSSDBG_TRACE_FUNC, "type: %d\n", data->type);
    DEBUG(SSSDBG_TRACE_FUNC, "user_verification: %d\n",
          data->user_verification);
    DEBUG(SSSDBG_TRACE_FUNC, "cred_type: %d\n",
          data->cred_type);
    DEBUG(SSSDBG_TRACE_FUNC, "Mapping file: %s\n", data->mapping_file);
    DEBUG(SSSDBG_TRACE_FUNC, "debug_libfido2: %d\n", data->debug_libfido2);

    if (data->action == ACTION_NONE) {
        DEBUG(SSSDBG_OP_FAILURE, "No action set.\n");
        ret = ERR_INPUT_PARSE;
        goto done;
    }

    if (data->action == ACTION_REGISTER
        && (data->shortname == NULL || data->domain == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE, "Too few arguments for register action.\n");
        ret = ERR_INPUT_PARSE;
        goto done;
    }

    if (data->action == ACTION_AUTHENTICATE
        && (data->domain == NULL || data->public_key_list == NULL
        || data->key_handle_list == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Too few arguments for authenticate action.\n");
        ret = ERR_INPUT_PARSE;
        goto done;
    }

    if (data->action == ACTION_GET_ASSERT
        && (data->domain == NULL || data->key_handle_list == NULL
        || data->crypto_challenge == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Too few arguments for get-assert action.\n");
        ret = ERR_INPUT_PARSE;
        goto done;
    }

    if (data->action == ACTION_VERIFY_ASSERT
        && (data->domain == NULL || data->public_key_list == NULL
        || data->key_handle_list == NULL || data->crypto_challenge == NULL
        || data->auth_data == NULL || data->signature == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Too few arguments for verify-assert action.\n");
        ret = ERR_INPUT_PARSE;
        goto done;
    }

    if (data->action == ACTION_PREFLIGHT
        && (data->domain == NULL || data->key_handle_list == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Too few arguments for preflight action.\n");
        ret = ERR_INPUT_PARSE;
        goto done;
    }

done:
    return ret;
}

errno_t
register_key(struct passkey_data *data, int timeout)
{
    TALLOC_CTX *tmp_ctx = NULL;
    fido_cred_t *cred = NULL;
    fido_dev_t *dev = NULL;
    fido_dev_info_t *dev_list = NULL;
    size_t dev_number = 0;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    data->user_id = talloc_array(tmp_ctx, unsigned char, USER_ID_SIZE);
    if (data->user_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    cred = fido_cred_new();
    if (cred == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    dev_list = fido_dev_info_new(DEVLIST_SIZE);
    if (dev_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_info_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = list_devices(timeout, dev_list, &dev_number);
    if (ret != EOK) {
        goto done;
    }

    ret = select_device(data->action, dev_list, dev_number, NULL, &dev);
    if (ret != EOK) {
        goto done;
    }

    ret = prepare_credentials(data, dev, cred);
    if (ret != EOK) {
        goto done;
    }

    ret = generate_credentials(data, dev, cred);
    if (ret != EOK) {
        ERROR("A problem occurred while generating the credentials.\n");
        goto done;
    }

    ret = verify_credentials(cred);
    if (ret != EOK) {
        goto done;
    }

    ret = print_credentials(data, cred);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    fido_cred_free(&cred);
    fido_dev_info_free(&dev_list, dev_number);
    if (dev != NULL) {
        fido_dev_close(dev);
    }
    fido_dev_free(&dev);
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
public_key_to_base64(TALLOC_CTX *mem_ctx, const struct passkey_data *data,
                     const unsigned char *public_key, size_t pk_len,
                     char **_pem_key)
{
    EVP_PKEY *evp_pkey = NULL;
    unsigned char *pub = NULL;
    char *pem_key = NULL;
    unsigned long err;
    errno_t ret;

    if (_pem_key == NULL) {
        ret = EINVAL;
        goto done;
    }

    switch (data->type) {
    case COSE_ES256:
        ret = es256_pubkey_to_evp_pkey(mem_ctx, public_key, pk_len, &evp_pkey);
        break;
    case COSE_RS256:
        ret = rs256_pubkey_to_evp_pkey(mem_ctx, public_key, pk_len, &evp_pkey);
        break;
    case COSE_EDDSA:
        ret = eddsa_pubkey_to_evp_pkey(mem_ctx, public_key, pk_len, &evp_pkey);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Invalid key type.\n");
        ret = EINVAL;
        break;
    }

    if (ret != EOK) {
        goto done;
    }

    ret = i2d_PUBKEY(evp_pkey, &pub);
    if (ret < 1) {
        err = ERR_get_error();
        DEBUG(SSSDBG_OP_FAILURE, "i2d_PUBKEY failed [%lu][%s].\n",
              err, ERR_error_string(err, NULL));
        ret = EIO;
        goto done;
    }

    pem_key = sss_base64_encode(mem_ctx, pub, ret);
    if (pem_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_encode failed.\n");
        ret = ENOMEM;
        goto done;
    }

    *_pem_key = pem_key;
    ret = EOK;

done:
    free(pub);

    if (evp_pkey != NULL) {
        EVP_PKEY_free(evp_pkey);
    }

    return ret;
}

errno_t
select_authenticator(struct passkey_data *data, int timeout, fido_dev_t **_dev,
                     fido_assert_t **_assert, int *_index)
{
    fido_dev_info_t *dev_list = NULL;
    fido_dev_t *dev = NULL;
    size_t dev_list_len = 0;
    fido_assert_t *assert = NULL;
    int index = 0;
    errno_t ret;

    dev_list = fido_dev_info_new(DEVLIST_SIZE);
    if (dev_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_info_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Checking for devices.\n");
    ret = list_devices(timeout, dev_list, &dev_list_len);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "%d key handles provided.\n",
          data->key_handle_size);

    while (index < data->key_handle_size) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Preparing assert request data with key handle %d.\n", index + 1);

        assert = fido_assert_new();
        if (assert == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_assert_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Preparing assert request data.\n");
        ret = prepare_assert(data, index, assert);
        if (ret != FIDO_OK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Selecting device.\n");
        ret = select_device(data->action, dev_list, dev_list_len, assert, &dev);
        if (ret == EOK) {
            /* Key handle found in device */
            break;
        }

        if (dev != NULL) {
            fido_dev_close(dev);
        }
        fido_dev_free(&dev);
        fido_assert_free(&assert);
        index++;
    }

    *_dev = dev;
    *_assert = assert;
    *_index = index;

done:
    if (ret != EOK) {
        fido_assert_free(&assert);
    }
    fido_dev_info_free(&dev_list, dev_list_len);

    return ret;
}

errno_t
public_key_to_libfido2(const char *pem_public_key, struct pk_data_t *_pk_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const unsigned char *public_key = NULL;
    size_t pk_len;
    const EVP_PKEY *evp_pkey = NULL;
    int base_id;
    unsigned long err;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    public_key = sss_base64_decode(tmp_ctx, pem_public_key, &pk_len);
    if (public_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to decode public key.\n");
        ret = ENOMEM;
        goto done;
    }

    evp_pkey = d2i_PUBKEY(NULL, &public_key, pk_len);
    if (evp_pkey == NULL) {
        err = ERR_get_error();
        DEBUG(SSSDBG_OP_FAILURE, "d2i_pubkey failed [%lu][%s].\n",
              err, ERR_error_string(err, NULL));
        ret = EIO;
        goto done;
    }

    base_id = get_id(evp_pkey);
    if (base_id == EVP_PKEY_EC) {
        _pk_data->type = COSE_ES256;
        ret = evp_pkey_to_es256_pubkey(evp_pkey, _pk_data);
    } else if (base_id == EVP_PKEY_RSA) {
        _pk_data->type = COSE_RS256;
        ret = evp_pkey_to_rs256_pubkey(evp_pkey, _pk_data);
    } else if (base_id == EVP_PKEY_ED25519) {
        _pk_data->type = COSE_EDDSA;
        ret = evp_pkey_to_eddsa_pubkey(evp_pkey, _pk_data);
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unrecognized key type.\n");
        ret = EINVAL;
    }
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    if (evp_pkey != NULL) {
        EVP_PKEY_free(discard_const(evp_pkey));
    }
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
authenticate(struct passkey_data *data, int timeout)
{
    TALLOC_CTX *tmp_ctx = NULL;
    fido_assert_t *assert = NULL;
    fido_dev_t *dev = NULL;
    struct pk_data_t pk_data = { 0 };
    int index;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ERROR("talloc_new() failed\n");
        return ENOMEM;
    }

    ret = select_authenticator(data, timeout, &dev, &assert, &index);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Comparing the device and policy options.\n");
    ret = get_device_options(dev, data);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Resetting assert options.\n");
    ret = set_assert_options(FIDO_OPT_TRUE, data->user_verification, assert);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to reset assert options.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Resetting assert client data.\n");
    ret = set_assert_client_data_hash(data, assert);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to reset client data hash.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Decoding public key.\n");
    ret = public_key_to_libfido2(data->public_key_list[index], &pk_data);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Getting assert.\n");
    ret = request_assert(data, dev, assert);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Verifying assert.\n");
    ret = verify_assert(&pk_data, assert);
    if (ret != FIDO_OK) {
        goto done;
    }

    ret = FIDO_OK;

done:
    reset_public_key(&pk_data);
    if (dev != NULL) {
        fido_dev_close(dev);
    }
    fido_dev_free(&dev);
    fido_assert_free(&assert);
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
get_assert_data(struct passkey_data *data, int timeout)
{
    TALLOC_CTX *tmp_ctx = NULL;
    fido_dev_t *dev = NULL;
    fido_assert_t *assert = NULL;
    const char *auth_data = NULL;
    const char *signature = NULL;
    int index;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    ret = select_authenticator(data, timeout, &dev, &assert, &index);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Comparing the device and policy options.\n");
    ret = get_device_options(dev, data);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Resetting assert options.\n");
    ret = set_assert_options(FIDO_OPT_TRUE, data->user_verification, assert);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to reset assert options.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Getting assert.\n");
    ret = request_assert(data, dev, assert);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Getting authentication data and signature.\n");
    ret = get_assert_auth_data_signature(tmp_ctx, assert, &auth_data,
                                         &signature);
    if (ret != EOK) {
        goto done;
    }

    print_assert_data(data->key_handle_list[index], data->crypto_challenge,
                      auth_data, signature);

done:
    if (dev != NULL) {
        fido_dev_close(dev);
    }
    fido_dev_free(&dev);
    fido_assert_free(&assert);
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
verify_assert_data(struct passkey_data *data)
{
    fido_assert_t *assert = NULL;
    struct pk_data_t pk_data = { 0 };
    errno_t ret;

    assert = fido_assert_new();
    if (assert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_assert_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Preparing assert data.\n");
    ret = prepare_assert(data, 0, assert);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Preparing assert authenticator data and signature.\n");
    ret = set_assert_auth_data_signature(data, assert);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Decoding public key.\n");
    ret = public_key_to_libfido2(data->public_key_list[0], &pk_data);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Verifying assert.\n");
    ret = verify_assert(&pk_data, assert);
    if (ret != FIDO_OK) {
        goto done;
    }

    ret = FIDO_OK;

done:
    reset_public_key(&pk_data);
    fido_assert_free(&assert);

    return ret;
}

errno_t
preflight(struct passkey_data *data, int timeout)
{
    fido_assert_t *assert = NULL;
    fido_dev_t *dev = NULL;
    int index = 0;
    int pin_retries = 0;
    errno_t ret;

    ret = select_authenticator(data, timeout, &dev, &assert, &index);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Comparing the device and policy options.\n");
    ret = get_device_options(dev, data);
    if (ret != FIDO_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Checking the number of remaining PIN retries.\n");
    ret = get_device_pin_retries(dev, data, &pin_retries);
    if (ret != FIDO_OK) {
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        data->user_verification = FIDO_OPT_TRUE;
        pin_retries = MAX_PIN_RETRIES;
    }
    print_preflight(data, pin_retries);

    if (dev != NULL) {
        fido_dev_close(dev);
    }
    fido_dev_free(&dev);
    fido_assert_free(&assert);

    return EOK;
}
