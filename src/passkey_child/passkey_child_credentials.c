/*
    SSSD

    Helper child to communicate with passkey devices

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

#include <fcntl.h>
#include <termios.h>
#include <stdio.h>

#include <fido/es256.h>
#include <fido/rs256.h>
#include <fido/eddsa.h>

#include "util/crypto/sss_crypto.h"
#include "util/debug.h"
#include "util/util.h"

#include "passkey_child.h"

errno_t
prepare_credentials(struct passkey_data *data, fido_dev_t *dev,
                    fido_cred_t *cred)
{
    unsigned char cdh[32];
    fido_opt_t rk = FIDO_OPT_OMIT;
    bool has_pin;
    bool has_uv;
    errno_t ret = EOK;

    ret = fido_cred_set_type(cred, data->type);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_type failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    ret = sss_generate_csprng_buffer(cdh, sizeof(cdh));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_generate_csprng_buffer failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    ret = fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh));
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "fido_cred_set_clientdata_hash failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Setting Relying Party ID and name to %s.\n",
          data->domain);

    ret = fido_cred_set_rp(cred, data->domain, data->domain);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_rp failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    if (data->user_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "user_id must be allocated before using it.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_generate_csprng_buffer(data->user_id, USER_ID_SIZE);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_generate_csprng_buffer failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Setting user: %s.\n", data->shortname);

    ret = fido_cred_set_user(cred, data->user_id, USER_ID_SIZE,
                             data->shortname, NULL, NULL);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_user failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    if (data->cred_type == CRED_DISCOVERABLE) {
        rk = FIDO_OPT_TRUE;
    }

    /* Set to FIDO_OPT_OMIT instead of FIDO_OPT_FALSE for compatibility reasons
     */
    ret = fido_cred_set_rk(cred, rk);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_rk failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    has_uv = fido_dev_has_uv(dev);
    has_pin = fido_dev_has_pin(dev);
    if (data->user_verification == FIDO_OPT_TRUE && has_uv == false
        && has_pin == false) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Policy enabled user-verification but there isn't any "
              "verification method set.\n");
        ret = EINVAL;
        goto done;
    }

    if (data->user_verification == FIDO_OPT_FALSE
        && (has_uv == true || has_pin == true)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Policy disabled user-verification but the key settings are "
              "enforcing it. Thus, enabling user-verification.\n");
        data->user_verification = FIDO_OPT_TRUE;
    }

    if (has_uv == true) {
        ret = fido_cred_set_uv(cred, FIDO_OPT_TRUE);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_uv failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    }

done:
    return ret;
}

errno_t
passkey_recv_pin(TALLOC_CTX *mem_ctx, int fd, char **_pin)
{
    static const size_t IN_BUF_SIZE = 1024;
    uint8_t buf[IN_BUF_SIZE];
    ssize_t len;
    errno_t ret;
    char *str;

    errno = 0;
    len = sss_atomic_read_s(fd, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        ret = (ret == 0) ? EINVAL: ret;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "read failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    if (len == 0 || *buf == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing PIN.\n");
        return EINVAL;
    }

    str = talloc_strndup(mem_ctx, (char *) buf, len);
    if (str == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
        return ENOMEM;
    }

    if (strlen(str) != len) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Input contains additional data, only PIN expected.\n");
        talloc_free(str);
        return EINVAL;
    }

    *_pin = str;

    return EOK;
}

ssize_t
read_pin(char **pin)
{
    char *line_ptr = NULL;
    struct termios old, new;
    size_t line_len = 0;
    ssize_t bytes_read;
    ssize_t ret;

    ret = tcgetattr(STDIN_FILENO, &old);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get the parameters associated with stdin [%d]: %s.\n",
              errno, sss_strerror(errno));
        goto done;
    }
    new = old;
    new.c_lflag &= ~ECHO;
    ret = tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to turn echoing off [%d]: %s.\n",
              errno, sss_strerror(errno));
        goto done;
    }

    PRINT("Enter PIN:\n");
    fflush(stdout);
    bytes_read = getline(&line_ptr, &line_len, stdin);
    if (bytes_read == -1) {
        DEBUG(SSSDBG_OP_FAILURE, "getline failed [%d]: %s.\n",
              errno, sss_strerror(errno));
    } else {
        /* Remove the end of line '\n' character */
        line_ptr[--bytes_read] = '\0';
    }
    PRINT("\n");

    ret = tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to restore parameters associated with stdin [%d]: %s.\n",
              errno, sss_strerror(errno));
        goto done;
    }

    ret = bytes_read;
    *pin = line_ptr;

done:
    return ret;
}

errno_t
generate_credentials(struct passkey_data *data, fido_dev_t *dev,
                     fido_cred_t *cred)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *pin = NULL;
    char *tmp_pin = NULL;
    bool has_pin;
    ssize_t pin_len = 0;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    has_pin = fido_dev_has_pin(dev);
    if (has_pin == true) {
        if (data->quiet == true) {
            ret = passkey_recv_pin(tmp_ctx, STDIN_FILENO, &pin);
            if (ret != EOK) {
                goto done;
            }
        } else {
            pin_len = read_pin(&tmp_pin);
            if (pin_len == -1) {
                ret = ERR_INPUT_PARSE;
                goto done;
            }
            pin = talloc_strdup(tmp_ctx, tmp_pin);
            sss_erase_mem_securely(tmp_pin, pin_len);
            free(tmp_pin);
        }
    }

    if (data->quiet == false) {
        PRINT("Please touch the device.\n");
        fflush(stdout);
    }
    ret = fido_dev_make_cred(dev, cred, pin);
    sss_erase_mem_securely(pin, pin_len);

    if (ret != FIDO_OK) {
        if (ret == FIDO_ERR_PIN_INVALID) {
            ERROR("Invalid PIN.\n");
        }
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_make_cred failed [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    if (has_pin == true) {
        ret = fido_cred_set_uv(cred, FIDO_OPT_TRUE);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_cred_set_uv failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
verify_credentials(const fido_cred_t *const cred)
{
    errno_t ret;

    if (fido_cred_x5c_ptr(cred) != NULL) {
        ret = fido_cred_verify(cred);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_cred_verify failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Attestation certificate missing. "
              "Falling back to self attestation.\n");
        ret = fido_cred_verify_self(cred);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "fido_cred_verify_self failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }
    }

done:
    return ret;
}

errno_t
print_credentials(const struct passkey_data *data,
                  const fido_cred_t *const cred)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const unsigned char *cred_id = NULL;
    const unsigned char *public_key = NULL;
    const char *b64_cred_id = NULL;
    char *pem_key = NULL;
    size_t cred_id_len;
    size_t user_key_len;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cred_id = fido_cred_id_ptr(cred);
    if (cred_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_id_ptr failed.\n");
        ret = ERR_CREDS_INVALID;
        goto done;
    }

    cred_id_len = fido_cred_id_len(cred);
    if (cred_id_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_id_len returned 0.\n");
        ret = ERR_CREDS_INVALID;
        goto done;
    }

    b64_cred_id = sss_base64_encode(tmp_ctx, cred_id, cred_id_len);
    if (b64_cred_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to encode key handle.\n");
        ret = ENOMEM;
        goto done;
    }

    public_key = fido_cred_pubkey_ptr(cred);
    if (public_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_pubkey_ptr failed.\n");
        ret = ERR_CREDS_INVALID;
        goto done;
    }

    user_key_len = fido_cred_pubkey_len(cred);
    if (user_key_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_cred_pubkey_len returned 0.\n");
        ret = ERR_CREDS_INVALID;
        goto done;
    }

    ret = public_key_to_base64(tmp_ctx, data, public_key, user_key_len,
                               &pem_key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "failed to format public key to b64 [%d]: %s.\n",
              ret, fido_strerr(ret));
        goto done;
    }

    PRINT("passkey:%s,%s\n", b64_cred_id, pem_key);
    if (data->mapping_file != NULL) {
        print_credentials_to_file(data, b64_cred_id, pem_key);
    }
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
print_credentials_to_file(const struct passkey_data *data,
                          const char *b64_cred_id,
                          const char *pem_key)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *mapping_data = NULL;
    int mapping_data_len = 0;
    int fd = -1;
    ssize_t written = 0;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    mapping_data = talloc_asprintf(tmp_ctx, "passkey:%s,%s",
                                   b64_cred_id, pem_key);
    if (mapping_data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    mapping_data_len = strlen(mapping_data);

    fd = open(data->mapping_file, O_WRONLY|O_CREAT, 0640);
    if (fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "open() failed [%d][%s]\n", ret, strerror(ret));
        ret = EIO;
        goto done;
    }

    errno = 0;
    written = sss_atomic_write_s(fd, mapping_data, mapping_data_len);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Write failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    if (written != mapping_data_len) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Write error, wrote [%zd] bytes, expected [%d]\n",
               written, mapping_data_len);
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (fd != -1) {
        if (close(fd) == -1) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Close failed [%s].\n", strerror(errno));
        }
    }
    talloc_free(tmp_ctx);

    return ret;
}

/* Operations on libfido2's public key data structure of a COSE type. libfido2
 * provides the same set of functions for each type, differing only in the
 * structure type; the wrappers below give them a common signature. */
struct cose_pk_ops {
    int type;
    /* Name used by the --type option */
    const char *name;
    /* OpenSSL key type and size (0 for any) to match EVP_PKEY keys */
    const char *evp_type;
    int evp_bits;
    void *(*pk_new)(void);
    void (*pk_free)(void **pk);
    int (*pk_from_ptr)(void *pk, const void *ptr, size_t len);
    int (*pk_from_evp)(void *pk, const EVP_PKEY *evp_pkey);
    EVP_PKEY *(*pk_to_evp)(const void *pk);
};

#define COSE_PK_WRAPPERS(alg) \
    static void *alg##_pk_new_op(void) \
    { \
        return alg##_pk_new(); \
    } \
    static void alg##_pk_free_op(void **pk) \
    { \
        alg##_pk_free((alg##_pk_t **) pk); \
    } \
    static int alg##_pk_from_ptr_op(void *pk, const void *ptr, size_t len) \
    { \
        return alg##_pk_from_ptr(pk, ptr, len); \
    } \
    static int alg##_pk_from_evp_op(void *pk, const EVP_PKEY *evp_pkey) \
    { \
        return alg##_pk_from_EVP_PKEY(pk, evp_pkey); \
    } \
    static EVP_PKEY *alg##_pk_to_evp_op(const void *pk) \
    { \
        return alg##_pk_to_EVP_PKEY(pk); \
    }

#define COSE_PK_OPS(alg, cose_type, evp_type, evp_bits) \
    { cose_type, #alg, evp_type, evp_bits, \
      alg##_pk_new_op, alg##_pk_free_op, alg##_pk_from_ptr_op, \
      alg##_pk_from_evp_op, alg##_pk_to_evp_op }

COSE_PK_WRAPPERS(es256)
COSE_PK_WRAPPERS(rs256)
COSE_PK_WRAPPERS(eddsa)

static const struct cose_pk_ops cose_pk_ops_list[] = {
    COSE_PK_OPS(es256, COSE_ES256, "EC", 256),
    COSE_PK_OPS(rs256, COSE_RS256, "RSA", 0),
    COSE_PK_OPS(eddsa, COSE_EDDSA, "ED25519", 0),
};

static const struct cose_pk_ops *
cose_pk_ops_by_type(int type)
{
    for (size_t i = 0; i < N_ELEMENTS(cose_pk_ops_list); i++) {
        if (cose_pk_ops_list[i].type == type) {
            return &cose_pk_ops_list[i];
        }
    }

    return NULL;
}

static const struct cose_pk_ops *
cose_pk_ops_by_evp_pkey(const EVP_PKEY *evp_pkey)
{
    const struct cose_pk_ops *ops;

    for (size_t i = 0; i < N_ELEMENTS(cose_pk_ops_list); i++) {
        ops = &cose_pk_ops_list[i];
        if (EVP_PKEY_is_a(evp_pkey, ops->evp_type) == 1
            && (ops->evp_bits == 0
                || EVP_PKEY_get_bits(evp_pkey) == ops->evp_bits)) {
            return ops;
        }
    }

    return NULL;
}

errno_t
cose_str_to_int(const char *type, int *out)
{
    for (size_t i = 0; i < N_ELEMENTS(cose_pk_ops_list); i++) {
        if (strcasecmp(type, cose_pk_ops_list[i].name) == 0) {
            *out = cose_pk_ops_list[i].type;
            return EOK;
        }
    }

    *out = 0;
    return ERR_INVALID_CRED_TYPE;
}

int
cose_pubkey_to_evp_pkey(int type, const void *key, size_t key_len,
                        EVP_PKEY **_evp_pkey)
{
    const struct cose_pk_ops *ops;
    EVP_PKEY *evp_pkey = NULL;
    void *public_key = NULL;
    errno_t ret;

    ops = cose_pk_ops_by_type(type);
    if (ops == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Invalid key type [%d].\n", type);
        return EINVAL;
    }

    public_key = ops->pk_new();
    if (public_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "%s_pk_new failed.\n", ops->name);
        ret = ENOMEM;
        goto done;
    }

    ret = ops->pk_from_ptr(public_key, key, key_len);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "%s_pk_from_ptr failed [%d]: %s.\n",
              ops->name, ret, fido_strerr(ret));
        goto done;
    }

    evp_pkey = ops->pk_to_evp(public_key);
    if (evp_pkey == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "%s_pk_to_EVP_PKEY failed.\n", ops->name);
        ret = ENOMEM;
        goto done;
    }

    *_evp_pkey = evp_pkey;
    ret = EOK;

done:
    ops->pk_free(&public_key);

    return ret;
}

errno_t
evp_pkey_to_cose_pubkey(const EVP_PKEY *evp_pkey, struct pk_data_t *_pk_data)
{
    const struct cose_pk_ops *ops;
    void *public_key = NULL;
    errno_t ret;

    ops = cose_pk_ops_by_evp_pkey(evp_pkey);
    if (ops == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unrecognized key type [%s].\n",
              EVP_PKEY_get0_type_name(evp_pkey));
        return EINVAL;
    }

    public_key = ops->pk_new();
    if (public_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "%s_pk_new failed.\n", ops->name);
        ret = ENOMEM;
        goto done;
    }

    ret = ops->pk_from_evp(public_key, evp_pkey);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "%s_pk_from_EVP_PKEY failed [%d]: %s.\n",
              ops->name, ret, fido_strerr(ret));
        goto done;
    }

    _pk_data->type = ops->type;
    _pk_data->public_key = public_key;
    public_key = NULL;
    ret = EOK;

done:
    if (public_key != NULL) {
        ops->pk_free(&public_key);
    }

    return ret;
}

void
cose_pubkey_free(int type, void **_public_key)
{
    const struct cose_pk_ops *ops;

    ops = cose_pk_ops_by_type(type);
    if (ops != NULL) {
        ops->pk_free(_public_key);
    }
}
