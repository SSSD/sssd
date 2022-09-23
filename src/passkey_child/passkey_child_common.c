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
#include <sys/prctl.h>
#include <fido/param.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "util/debug.h"
#include "util/util.h"
#include "util/crypto/sss_crypto.h"

#include "passkey_child.h"

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

errno_t
parse_arguments(int argc, const char *argv[], struct passkey_data *data)
{
    int opt;
    int dumpable = 1;
    int debug_fd = -1;
    char *user_verification = NULL;
    const char *opt_logger = NULL;
    const char *type = NULL;
    poptContext pc;
    errno_t ret;

    /* Set defaults */
    data->action = ACTION_NONE;
    data->shortname = NULL;
    data->domain = NULL;
    data->public_key = NULL;
    data->key_handle = NULL;
    data->type = COSE_ES256;
    data->user_verification = FIDO_OPT_OMIT;
    data->debug_libfido2 = false;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"dumpable", 0, POPT_ARG_INT, &dumpable, 0,
         _("Allow core dumps"), NULL },
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        SSSD_LOGGER_OPTS
        {"register", 0, POPT_ARG_NONE, NULL, 'r',
         _("Register a passkey for a user"), NULL },
        {"authenticate", 0, POPT_ARG_NONE, NULL, 'a',
         _("Authenticate a user with a passkey"), NULL },
        {"username", 0, POPT_ARG_STRING, &data->shortname, 0,
         _("Shortname"), NULL },
        {"domain", 0, POPT_ARG_STRING, &data->domain, 0,
         _("Domain"), NULL},
        {"public-key", 0, POPT_ARG_STRING, &data->public_key, 0,
         _("Public key"), NULL },
        {"key-handle", 0, POPT_ARG_STRING, &data->key_handle, 0,
         _("Key handle"), NULL},
        {"type", 0, POPT_ARG_STRING, &type, 0,
         _("COSE type to use"), "es256|rs256|eddsa"},
        {"user-verification", 0, POPT_ARG_STRING, &user_verification, 0,
         _("Require user-verification"), "true|false"},
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

    prctl(PR_SET_DUMPABLE, (dumpable == 0) ? 0 : 1);

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
    DEBUG(SSSDBG_TRACE_FUNC, "public_key: %s, key_handle: %s\n",
          data->public_key, data->key_handle);
    DEBUG(SSSDBG_TRACE_FUNC, "type: %d\n", data->type);
    DEBUG(SSSDBG_TRACE_FUNC, "user_verification: %d\n",
          data->user_verification);
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
        && (data->shortname == NULL || data->domain == NULL
        || data->public_key == NULL || data->key_handle == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Too few arguments for authenticate action.\n");
        ret = ERR_INPUT_PARSE;
        goto done;
    }

done:
    return ret;
}

errno_t
register_key(struct passkey_data *data)
{
    fido_cred_t *cred = NULL;
    fido_dev_t *dev = NULL;
    fido_dev_info_t *dev_list = NULL;
    size_t dev_number = 0;
    errno_t ret;

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

    ret = list_devices(dev_list, &dev_number);
    if (ret != EOK) {
        goto done;
    }

    if (dev_number == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "No device found. Aborting.\n");
        fprintf(stderr, "No device found. Aborting.\n");
        ret = ENOENT;
        goto done;
    } else if (dev_number > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Only one device is supported at a time. Aborting.\n");
        fprintf(stderr, "Only one device is supported at a time. Aborting.\n");
        ret = EPERM;
        goto done;
    }

    dev = fido_dev_new();
    if (dev == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = select_device(dev_list, 0, dev);
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
