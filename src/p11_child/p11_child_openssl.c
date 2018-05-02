/*
    SSSD

    Helper child to commmunicate with SmartCard via OpenSSL

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2018 Red Hat

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

#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <p11-kit/p11-kit.h>

#include <popt.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/child_common.h"
#include "p11_child/p11_child.h"

struct p11_ctx {
    X509_STORE *x509_store;
    const char *ca_db;
};

static int talloc_cleanup_openssl(struct p11_ctx *p11_ctx)
{
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
errno_t init_p11_ctx(TALLOC_CTX *mem_ctx, const char *ca_db,
                     struct p11_ctx **p11_ctx)
{
    int ret;
    struct p11_ctx *ctx;

    /* See https://wiki.openssl.org/index.php/Library_Initialization for
     * details. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ret = OPENSSL_init_ssl(0, NULL);
#else
    ret = SSL_library_init();
#endif
    if (ret != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize OpenSSL.\n");
        return EIO;
    }

    ctx = talloc_zero(mem_ctx, struct p11_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ctx->ca_db = ca_db;
    talloc_set_destructor(ctx, talloc_cleanup_openssl);

    *p11_ctx = ctx;

    return EOK;
}

static int talloc_free_x509_store(struct p11_ctx *p11_ctx)
{
    X509_STORE_free(p11_ctx->x509_store);

    return 0;
}

errno_t init_verification(struct p11_ctx *p11_ctx,
                          struct cert_verify_opts *cert_verify_opts)
{
    int ret;
    X509_STORE *store = NULL;
    unsigned long err;
    X509_LOOKUP *lookup = NULL;

    store = X509_STORE_new();
    if (store == NULL) {
        err = ERR_get_error();
        DEBUG(SSSDBG_OP_FAILURE, "X509_STORE_new failed [%lu][%s].\n",
                                 err, ERR_error_string(err, NULL));
        return ENOMEM;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL) {
        err = ERR_get_error();
        DEBUG(SSSDBG_OP_FAILURE, "X509_LOOKUP_file failed [%lu][%s].\n",
                                 err, ERR_error_string(err, NULL));
        ret = EIO;
        goto done;
    }

    if (!X509_LOOKUP_load_file(lookup, p11_ctx->ca_db, X509_FILETYPE_PEM)) {
        err = ERR_get_error();
        DEBUG(SSSDBG_OP_FAILURE, "X509_LOOKUP_load_file failed [%lu][%s].\n",
                                 err, ERR_error_string(err, NULL));
        ret = EIO;
        goto done;
    }

    p11_ctx->x509_store = store;
    talloc_set_destructor(p11_ctx, talloc_free_x509_store);

    ret = EOK;

done:
    if (ret != EOK) {
        X509_STORE_free(store);
        X509_LOOKUP_free(lookup);
    }

    return ret;
}

static int b64_to_cert(const char *b64, X509 **cert)
{
    X509 *x509;
    unsigned char *der = NULL;
    const unsigned char *d;
    size_t der_size;

    der = sss_base64_decode(NULL, b64, &der_size);
    if (der == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
        return ENOMEM;
    }

    d = (const unsigned char *) der;
    x509 = d2i_X509(NULL, &d, (int) der_size);
    talloc_free(der);
    if (x509 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "d2i_X509 failed.\n");
        return EINVAL;
    }

    *cert = x509;

    return 0;
}

bool do_verification(struct p11_ctx *p11_ctx, X509 *cert)
{
    bool res = false;
    int ret;
    X509_STORE_CTX *ctx = NULL;
    unsigned long err;

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        err = ERR_get_error();
        DEBUG(SSSDBG_OP_FAILURE, "X509_STORE_CTX_new failed [%lu][%s].\n",
                                 err, ERR_error_string(err, NULL));
        return false;
    }

    if (!X509_STORE_CTX_init(ctx, p11_ctx->x509_store, cert, NULL)) {
        err = ERR_get_error();
        DEBUG(SSSDBG_OP_FAILURE, "X509_STORE_CTX_init failed [%lu][%s].\n",
                                 err, ERR_error_string(err, NULL));
        goto done;
    }

    ret = X509_verify_cert(ctx);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "X509_verify_cert failed [%d].\n", ret);
        ret = X509_STORE_CTX_get_error(ctx);
        DEBUG(SSSDBG_OP_FAILURE, "X509_verify_cert failed [%d][%s].\n",
                                 ret, X509_verify_cert_error_string(ret));
        ret = EINVAL;
        goto done;
    }

    res = true;

done:
    X509_STORE_CTX_free(ctx);

    return res;
}

bool do_verification_b64(struct p11_ctx *p11_ctx, const char *cert_b64)
{
    int ret;
    X509 *cert;
    bool res;

    ret = b64_to_cert(cert_b64, &cert);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to convert certificate.\n");
        return EINVAL;
    }

    res = do_verification(p11_ctx, cert);
    X509_free(cert);

    return res;
}

#define ATTR_ID 0
#define ATTR_LABEL 1
#define ATTR_CERT 2

struct cert_list {
    struct cert_list *prev;
    struct cert_list *next;
    CK_ATTRIBUTE attributes[3];
    char *id;
    char *label;
    X509 *cert;
    char *subject_dn;
    char *cert_b64;
    CK_KEY_TYPE key_type;
    CK_OBJECT_HANDLE private_key;
};

static int free_x509_cert(struct cert_list *item)
{
    X509_free(item->cert);
    return 0;
}

static int read_certs(TALLOC_CTX *mem_ctx, CK_FUNCTION_LIST *module,
                      CK_SESSION_HANDLE session, struct p11_ctx *p11_ctx,
                      struct cert_list **cert_list)
{
    int ret;
    size_t c;
    CK_RV rv;
    struct cert_list *list = NULL;
    struct cert_list *item;
    X509_NAME *tmp_name;
    char *tmp_name_str;

    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_ATTRIBUTE cert_find_template[] = {
        {CKA_CLASS, &cert_class, sizeof(CK_OBJECT_CLASS)} ,
        {CKA_CERTIFICATE_TYPE, &cert_type, sizeof(CK_CERTIFICATE_TYPE)}
    };

    CK_ULONG obj_count;
    CK_OBJECT_HANDLE obj;

    rv = module->C_FindObjectsInit(session, cert_find_template, 2);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE ,"C_FindObjectsInit failed [%lu][%s].\n",
                                 rv, p11_kit_strerror(rv));
        return EIO;
    }

    do {
        rv = module->C_FindObjects(session, &obj, 1, &obj_count);
        if (rv != CKR_OK) {
            DEBUG(SSSDBG_OP_FAILURE ,"C_FindObject failed [%lu][%s].\n",
                                     rv, p11_kit_strerror(rv));
            ret = EIO;
            goto done;
        }

        if (obj_count != 0) {
            item = talloc_zero(mem_ctx, struct cert_list);
            if (item == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
                ret = ENOMEM;
                goto done;
            }
            item->attributes[0].type = CKA_ID;
            item->attributes[1].type = CKA_LABEL;
            item->attributes[2].type = CKA_VALUE;

            rv = module->C_GetAttributeValue(session, obj, item->attributes, 3);
            if (rv != CKR_OK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "C_GetAttributeValue failed [%lu][%s].\n",
                      rv, p11_kit_strerror(rv));
                ret = EIO;
                goto done;
            }

            if (item->attributes[0].ulValueLen == -1
                    || item->attributes[1].ulValueLen == -1
                    || item->attributes[2].ulValueLen == -1) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "One of the needed attributes cannot be read.\n");
                ret = EIO;
                goto done;
            }

            item->attributes[0].pValue = talloc_size(item,
                                              item->attributes[0].ulValueLen);
            item->attributes[1].pValue = talloc_size(item,
                                              item->attributes[1].ulValueLen);
            item->attributes[2].pValue = talloc_size(item,
                                              item->attributes[2].ulValueLen);
            if (item->attributes[0].pValue == NULL
                    || item->attributes[1].pValue == NULL
                    || item->attributes[2].pValue == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
                ret = ENOMEM;
                goto done;
            }

            rv = module->C_GetAttributeValue(session, obj, item->attributes, 3);
            if (rv != CKR_OK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "C_GetAttributeValue failed [%lu][%s].\n",
                      rv, p11_kit_strerror(rv));
                ret = EIO;
                goto done;
            }

            item->label = talloc_strndup(item, item->attributes[1].pValue,
                                         item->attributes[1].ulValueLen);
            if (item->label == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
                ret = ENOMEM;
                goto done;
            }

            item->id = talloc_zero_size(item, 2 * item->attributes[0].ulValueLen + 1);
            if (item->id == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
                ret = ENOMEM;
                goto done;
            }

            for (c = 0; c < item->attributes[0].ulValueLen; c++) {
                ret = snprintf(item->id + 2*c, 3, "%02X",
                               ((uint8_t *)item->attributes[0].pValue)[c]);
                if (ret != 2) {
                    DEBUG(SSSDBG_OP_FAILURE, "snprintf failed.\n");
                    ret = EIO;
                    goto done;
                }
            }

            item->cert_b64 = sss_base64_encode(item,
                                            item->attributes[2].pValue,
                                            item->attributes[2].ulValueLen);
            if (item->cert_b64 == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_base64_encode failed.\n");
                ret = ENOMEM;
                goto done;
            }

            /* It looks like d2i_X509 modifies the given binary data, so do
             * not use item->attributes[2].pValue after this call. */
            item->cert = d2i_X509(NULL,
                            (const unsigned char **)&item->attributes[2].pValue,
                            item->attributes[2].ulValueLen);
            if (item->cert == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "d2i_X509 failed.\n");
                ret = EINVAL;
                goto done;
            }
            talloc_set_destructor(item, free_x509_cert);

            tmp_name = X509_get_subject_name(item->cert);
            tmp_name_str = X509_NAME_oneline(tmp_name, NULL, 0);

            item->subject_dn = talloc_strdup(item, tmp_name_str);
            OPENSSL_free(tmp_name_str);
            if (item->subject_dn == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }

            DEBUG(SSSDBG_TRACE_ALL, "found cert[%s][%s]\n",
                                    item->label, item->subject_dn);

            if (p11_ctx->x509_store == NULL
                    || do_verification(p11_ctx, item->cert)) {
                DLIST_ADD(list, item);
            } else {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Certificate [%s][%s] not valid, skipping.\n",
                          item->label,
                          item->subject_dn);
                    talloc_free(item);
            }
        }
    } while (obj_count != 0);

    *cert_list = list;

    ret = EOK;

done:
    rv = module->C_FindObjectsFinal(session);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE ,"C_FindObject failed [%lu][%s].\n",
                                 rv, p11_kit_strerror(rv));
        ret = EIO;
    }

    return ret;
}

static int sign_data(CK_FUNCTION_LIST *module, CK_SESSION_HANDLE session,
                     struct cert_list *cert)
{
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_BBOOL key_sign = CK_TRUE;
    CK_ATTRIBUTE key_template[] = {
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_SIGN, &key_sign, sizeof(key_sign)},
      {CKA_ID, NULL, 0}
    };
    CK_MECHANISM mechanism = { CKM_SHA1_RSA_PKCS, NULL, 0 };
    CK_OBJECT_HANDLE priv_key_object;
    CK_ULONG object_count;
    CK_BYTE random_value[128];
    CK_BYTE *signature = NULL;
    CK_ULONG signature_size = 0;
    CK_RV rv;
    CK_RV rv_f;
    EVP_PKEY *cert_pub_key = NULL;
    EVP_MD_CTX *md_ctx;
    int ret;

    key_template[2].pValue = cert->attributes[ATTR_ID].pValue;
    key_template[2].ulValueLen = cert->attributes[ATTR_ID].ulValueLen;

    rv = module->C_FindObjectsInit(session, key_template, 3);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE ,"C_FindObjectsInit failed [%lu][%s].\n",
                                 rv, p11_kit_strerror(rv));
        return EIO;
    }

    rv = module->C_FindObjects(session, &priv_key_object, 1, &object_count);
    rv_f = module->C_FindObjectsFinal(session);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE ,"C_FindObject failed [%lu][%s].\n",
                                 rv, p11_kit_strerror(rv));
        return EIO;
    }
    if (rv_f != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE ,"C_FindObjectsFinal failed [%lu][%s].\n",
                                 rv_f, p11_kit_strerror(rv_f));
        return EIO;
    }

    if (object_count == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No private key found.\n");
        return EINVAL;
    }

    rv = module->C_SignInit(session, &mechanism, priv_key_object);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "C_SignInit failed [%lu][%s].",
                                 rv, p11_kit_strerror(rv));
        return EIO;
    }

    ret = RAND_bytes(random_value, sizeof(random_value));
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "RAND_bytes failed.\n");
        return EINVAL;
    }

    rv = module->C_Sign(session, random_value, sizeof(random_value), NULL,
                        &signature_size);
    if (rv != CKR_OK || signature_size == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "C_Sign failed [%lu][%s].\n",
                                 rv, p11_kit_strerror(rv));
        return EIO;
    }

    signature = talloc_size(cert, signature_size);
    if (signature == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    rv = module->C_Sign(session, random_value, sizeof(random_value), signature,
                        &signature_size);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "C_Sign failed [%lu][%s].\n",
                                 rv, p11_kit_strerror(rv));
        return EIO;
    }

    cert_pub_key = X509_get_pubkey(cert->cert);
    if (cert_pub_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "X509_get_pubkey failed.\n");
        ret = EIO;
        goto done;
    }

    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "EVP_MD_CTX_create failed.\n");
        ret = ENOMEM;
        goto done;
    }
    ret = EVP_VerifyInit(md_ctx, EVP_sha1());
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "EVP_VerifyInit failed.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EVP_VerifyUpdate(md_ctx, random_value, sizeof(random_value));
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "EVP_VerifyUpdate failed.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EVP_VerifyFinal(md_ctx, signature, signature_size, cert_pub_key);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "EVP_VerifyFinal failed.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(signature);
    EVP_PKEY_free(cert_pub_key);

    return ret;
}

#define MAX_SLOTS 64

errno_t do_card(TALLOC_CTX *mem_ctx, struct p11_ctx *p11_ctx,
                enum op_mode mode, const char *pin,
                const char *module_name_in, const char *token_name_in,
                const char *key_id_in, char **_multi)
{
    int ret;
    size_t c;
    size_t s;
    CK_FUNCTION_LIST **modules;
    CK_FUNCTION_LIST *module = NULL;
    char *mod_name;
    char *mod_file_name;
    CK_ULONG num_slots;
    CK_SLOT_ID slots[MAX_SLOTS];
    CK_SLOT_ID slot_id;
    CK_SLOT_INFO info;
    CK_TOKEN_INFO token_info;
    CK_RV rv;
    size_t module_id;
    char *module_file_name = NULL;
    char *slot_name = NULL;
    char *token_name = NULL;
    CK_SESSION_HANDLE session = 0;
    struct cert_list *cert_list = NULL;
    struct cert_list *item = NULL;
    char *multi = NULL;
    bool pkcs11_session = false;
    bool pkcs11_login = false;

    /* Maybe use P11_KIT_MODULE_TRUSTED ? */
    modules = p11_kit_modules_load_and_initialize(0);
    if (modules == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "p11_kit_modules_load_and_initialize failed.\n");
        return EIO;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Module List:\n");
    for (c = 0; modules[c] != NULL; c++) {
        mod_name = p11_kit_module_get_name(modules[c]);
        mod_file_name = p11_kit_module_get_filename(modules[c]);
        DEBUG(SSSDBG_TRACE_ALL, "common name: [%s].\n", mod_name);
        DEBUG(SSSDBG_TRACE_ALL, "dll name: [%s].\n", mod_file_name);
        free(mod_name);
        free(mod_file_name);

        num_slots = MAX_SLOTS;
        rv = modules[c]->C_GetSlotList(CK_TRUE, slots, &num_slots);
        if (rv != CKR_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "C_GetSlotList failed.\n");
            ret = EIO;
            goto done;
        }

        for (s = 0; s < num_slots; s++) {
            rv = modules[c]->C_GetSlotInfo(slots[s], &info);
            if (rv != CKR_OK) {
                DEBUG(SSSDBG_OP_FAILURE, "C_GetSlotInfo failed\n");
                ret = EIO;
                goto done;
            }
            DEBUG(SSSDBG_TRACE_ALL,
                  "Description [%s] Manufacturer [%s] flags [%lu] removable [%s].\n",
                  info.slotDescription, info.manufacturerID, info.flags,
                  (info.flags & CKF_REMOVABLE_DEVICE) ? "true": "false");
            if ((info.flags & CKF_REMOVABLE_DEVICE)) {
                break;
            }
        }
        if (s != num_slots) {
            break;
        }
    }

    if (modules[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No removable slots found.\n");
        ret = EIO;
        goto done;
    }

    rv = modules[c]->C_GetTokenInfo(slots[s], &token_info);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "C_GetTokenInfo failed.\n");
        ret = EIO;
        goto done;
    }

    slot_id = slots[s];
    module_id = c;
    slot_name = p11_kit_space_strdup(info.slotDescription,
                                     sizeof(info.slotDescription));
    if (slot_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_kit_space_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    token_name = p11_kit_space_strdup(token_info.label,
                                      sizeof(token_info.label));
    if (token_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_kit_space_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }
    module = modules[c];
    module_file_name = p11_kit_module_get_filename(module);

    DEBUG(SSSDBG_TRACE_ALL, "Found [%s] in slot [%s][%d] of module [%d][%s].\n",
          token_name, slot_name, (int) slot_id, (int) module_id,
          module_file_name);

    rv = module->C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL,
                               &session);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "C_OpenSession failed [%lu][%s].\n",
                                 rv, p11_kit_strerror(rv));
        ret = EIO;
        goto done;
    }
    pkcs11_session = true;

    /* login: do we need to check for Login Required? */
    if (mode == OP_AUTH) {
        DEBUG(SSSDBG_TRACE_ALL, "Login required.\n");
        if (pin != NULL) {
            rv = module->C_Login(session, CKU_USER, discard_const(pin),
                                 strlen(pin));
            if (rv != CKR_OK) {
                DEBUG(SSSDBG_OP_FAILURE, "C_Login failed [%lu][%s].\n",
                                 rv, p11_kit_strerror(rv));
                ret = EIO;
                goto done;
            }
            pkcs11_login = true;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Login required but no PIN available, continue.\n");
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "Login NOT required.\n");
    }

    ret = read_certs(mem_ctx, module, session, p11_ctx, &cert_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "read_certs failed.\n");
        goto done;
    }

    /* TODO: check module_name_in, token_name_in, key_id_in */

    if (cert_list == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "No certificate found.\n");
        *_multi = NULL;
        ret = EOK;
        goto done;
    }

    if (mode == OP_AUTH) {
        if (cert_list->next != NULL || cert_list->prev != NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "More than one certificate found for authentication, "
                  "aborting!\n");
            ret = EINVAL;
            goto done;
        }

        ret = sign_data(module, session, cert_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sign_data failed.\n");
            ret = EACCES;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL,
              "Certificate verified and validated.\n");
    }

    multi = talloc_strdup(mem_ctx, "");
    if (multi == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create output string.\n");
        ret = ENOMEM;
        goto done;
    }

    DLIST_FOR_EACH(item, cert_list) {
        DEBUG(SSSDBG_TRACE_ALL, "Found certificate has key id [%s].\n",
              item->id);

        multi = talloc_asprintf_append(multi, "%s\n%s\n%s\n%s\n%s\n",
                                       token_name, module_file_name, item->id,
                                       item->label, item->cert_b64);
    }

    *_multi = multi;

    ret = EOK;
done:
    if (module != NULL) {
        if (pkcs11_login) {
            rv = module->C_Logout(session);
            if (rv != CKR_OK) {
                DEBUG(SSSDBG_OP_FAILURE, "C_Logout failed [%lu][%s].\n",
                                         rv, p11_kit_strerror(rv));
            }
        }
        if (pkcs11_session) {
            rv = module->C_CloseSession(session);
            if (rv != CKR_OK) {
                DEBUG(SSSDBG_OP_FAILURE, "C_CloseSession failed [%lu][%s].\n",
                                         rv, p11_kit_strerror(rv));
            }
        }
    }
    free(slot_name);
    free(token_name);
    free(module_file_name);
    p11_kit_modules_finalize_and_release(modules);

    return ret;
}
