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
#include <openssl/ocsp.h>
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include <popt.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/child_common.h"
#include "p11_child/p11_child.h"

struct p11_ctx {
    X509_STORE *x509_store;
    const char *ca_db;
    bool wait_for_card;
    struct cert_verify_opts *cert_verify_opts;
};

static OCSP_RESPONSE *query_responder(BIO *cbio, const char *host,
                                      const char *path,
                                      OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    int rv;
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;

    if (req_timeout != -1) {
        BIO_set_nbio(cbio, 1);
    }

    rv = BIO_do_connect(cbio);

    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
        DEBUG(SSSDBG_OP_FAILURE, "Error connecting BIO\n");
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) < 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't get connection fd\n");
        goto err;
    }

    if (req_timeout != -1 && rv <= 0) {
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        if (rv == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Timeout on connect\n");
            return NULL;
        }
    }

    ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
    if (ctx == NULL) {
        return NULL;
    }

    if (OCSP_REQ_CTX_add1_header(ctx, "Host", host) == 0) {
        goto err;
    }

    if (!OCSP_REQ_CTX_set1_req(ctx, req)) {
        goto err;
    }

    for (;;) {
        rv = OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;
        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio)) {
            rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
        } else if (BIO_should_write(cbio)) {
            rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected retry condition\n");
            goto err;
        }
        if (rv == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Timeout on request\n");
            break;
        }
        if (rv == -1) {
            DEBUG(SSSDBG_OP_FAILURE, "Select error\n");
            break;
        }

    }
 err:
    OCSP_REQ_CTX_free(ctx);

    return rsp;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define TLS_client_method SSLv23_client_method
#define X509_STORE_get0_objects(store) (store->objs)
#define X509_OBJECT_get_type(object) (object->type)
#define X509_OBJECT_get0_X509(object) (object->data.x509)
#endif

OCSP_RESPONSE *process_responder(OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 char *port, int use_ssl,
                                 int req_timeout)
{
    BIO *cbio = NULL;
    SSL_CTX *ctx = NULL;
    OCSP_RESPONSE *resp = NULL;

    cbio = BIO_new_connect(host);
    if (cbio == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Error creating connect BIO\n");
        goto end;
    }
    if (port != NULL)
        BIO_set_conn_port(cbio, port);
    if (use_ssl == 1) {
        BIO *sbio;
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Error creating SSL context.\n");
            goto end;
        }
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        sbio = BIO_new_ssl(ctx, 1);
        cbio = BIO_push(sbio, cbio);
    }

    resp = query_responder(cbio, host, path, req, req_timeout);
    if (resp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Error querying OCSP responder\n");
    }

 end:
    BIO_free_all(cbio);
    SSL_CTX_free(ctx);
    return resp;
}

static errno_t do_ocsp(struct p11_ctx *p11_ctx, X509 *cert)
{
    OCSP_REQUEST *ocsp_req = NULL;
    OCSP_RESPONSE *ocsp_resp = NULL;
    OCSP_BASICRESP *ocsp_basic = NULL;
    OCSP_CERTID *cid = NULL;
    STACK_OF(OPENSSL_STRING) *ocsp_urls = NULL;
    char *url_str;
    X509 *issuer = NULL;
    int req_timeout = -1;
    int status;
    int ret = EIO;
    int reason;
    ASN1_GENERALIZEDTIME *revtime;
    ASN1_GENERALIZEDTIME *thisupd;
    ASN1_GENERALIZEDTIME *nextupd;
    long grace_time = (5 * 60); /* Allow 5 minutes time difference when
                                 * checking the validity of the OCSP response */
    char *host = NULL;
    char *path = NULL;
    char *port = NULL;
    int use_ssl;
    X509_NAME *issuer_name = NULL;
    X509_OBJECT *x509_obj;
    STACK_OF(X509_OBJECT) *store_objects;

    ocsp_urls = X509_get1_ocsp(cert);
    if (ocsp_urls == NULL
            && p11_ctx->cert_verify_opts->ocsp_default_responder == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No OCSP URL in certificate and no default responder defined, "
              "skipping OCSP check.\n");
        return EOK;
    }

    if (p11_ctx->cert_verify_opts->ocsp_default_responder != NULL) {
        url_str = p11_ctx->cert_verify_opts->ocsp_default_responder;
    } else {
        if (sk_OPENSSL_STRING_num(ocsp_urls) > 1) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Found more than 1 OCSP URLs, just using the first.\n");
        }

        url_str = sk_OPENSSL_STRING_value(ocsp_urls, 0);
    }

    DEBUG(SSSDBG_TRACE_ALL, "Using OCSP URL [%s].\n", url_str);

    ret = OCSP_parse_url(url_str, &host, &port, &path, &use_ssl);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "OCSP_parse_url failed to parse [%s].\n",
                                 url_str);
        ret = EIO;
        goto done;
    }

    issuer_name = X509_get_issuer_name(cert);
    if (issuer_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Certificate has no issuer, "
                                   "cannot run OCSP check.\n");
        ret = EINVAL;
        goto done;
    }

    store_objects = X509_STORE_get0_objects(p11_ctx->x509_store);
    if (store_objects == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No objects found in certificate store, OCSP failed.\n");
        ret = EINVAL;
        goto done;
    }

    x509_obj = X509_OBJECT_retrieve_by_subject(store_objects, X509_LU_X509,
                                               issuer_name);
    if (x509_obj == NULL || X509_OBJECT_get_type(x509_obj) != X509_LU_X509) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Issuer not found.\n");
        ret = EIO;
        goto done;
    }

    issuer = X509_OBJECT_get0_X509(x509_obj);

    ocsp_req = OCSP_REQUEST_new();
    if (ocsp_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "OCSP_REQUEST_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    cid = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    if (cid == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "OCSP_cert_to_id failed.\n");
        ret = EIO;
        goto done;
    }

    if (OCSP_request_add0_id(ocsp_req, cid) == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "OCSP_request_add0_id failed.\n");
        ret = EIO;
        goto done;
    }

    OCSP_request_add1_nonce(ocsp_req, NULL, -1);

    ocsp_resp = process_responder(ocsp_req, host, path, port, use_ssl,
                                  req_timeout);
    if (ocsp_resp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "process_responder failed.\n");
        ret = EIO;
        goto done;
    }

    status = OCSP_response_status(ocsp_resp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "OCSP response error: [%d][%s].\n",
                                   status, OCSP_response_status_str(status));
        ret = EIO;
        goto done;
    }

    ocsp_basic = OCSP_response_get1_basic(ocsp_resp);
    if (ocsp_resp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "OCSP_response_get1_basic failed.\n");
        ret = EIO;
        goto done;
    }

    switch (OCSP_check_nonce(ocsp_req, ocsp_basic)) {
    case -1:
        DEBUG(SSSDBG_CRIT_FAILURE, "No nonce in OCSP response. This might "
              "indicate a replay attack or an OCSP responder which does not "
              "support nonces.  Accepting response.\n");
        break;
    case 0:
        DEBUG(SSSDBG_CRIT_FAILURE, "Nonce in OCSP response does not match the "
                                   "one used in the request.\n");
        ret = EIO;
        goto done;
        break;
    case 1:
        DEBUG(SSSDBG_TRACE_ALL, "Nonce in OCSP response is the same as the one "
                                "used in the request.\n");
        break;
    case 2:
    case 3:
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing nonce in OCSP request, this should"
                                   "never happen.\n");
        ret = EIO;
        goto done;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected result of OCSP_check_nonce.\n");
    }

    status = OCSP_basic_verify(ocsp_basic, NULL, p11_ctx->x509_store, 0);
    if (status != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "OCSP_base_verify failed to verify OCSP "
                                   "response.\n");
        ret = EIO;
        goto done;
    }

    ret = OCSP_resp_find_status(ocsp_basic, cid, &status, &reason,
                                &revtime, &thisupd, &nextupd);
    if (ret != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "OCSP response does not contain status of "
                                   "our certificate.\n");
        ret = EIO;
        goto done;
    }

    if (status != V_OCSP_CERTSTATUS_GOOD) {
        DEBUG(SSSDBG_CRIT_FAILURE, "OCSP check failed with [%d][%s].\n",
                                   status, OCSP_cert_status_str(status));
        if (status == V_OCSP_CERTSTATUS_REVOKED) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Certificate is revoked [%d][%s].\n",
                                       reason, OCSP_crl_reason_str(reason));
        }
        ret = EIO;
        goto done;
    }

    if (OCSP_check_validity(thisupd, nextupd, grace_time, -1) != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "OCSP response is not valid anymore.\n");
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "OCSP check was successful.\n");
    ret = EOK;

done:
    OCSP_BASICRESP_free(ocsp_basic);
    OCSP_RESPONSE_free(ocsp_resp);
    OCSP_REQUEST_free(ocsp_req);

    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    X509_email_free(ocsp_urls);

    return ret;
}

static char *get_pkcs11_uri(TALLOC_CTX *mem_ctx, CK_INFO *module_info,
                            CK_SLOT_INFO *slot_info, CK_SLOT_ID slot_id,
                            CK_TOKEN_INFO *token_info, CK_ATTRIBUTE *label,
                            CK_ATTRIBUTE *id)
{
    P11KitUri *uri;
    char *uri_str = NULL;
    char *tmp_str = NULL;
    int ret;
    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_ATTRIBUTE class_attr = {CKA_CLASS, &cert_class, sizeof(CK_OBJECT_CLASS)};

    uri = p11_kit_uri_new();
    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_kit_uri_new failed.\n");
        return NULL;
    }

    ret = p11_kit_uri_set_attribute(uri, label);
    if (ret != P11_KIT_URI_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_kit_uri_set_attribute failed.\n");
        goto done;
    }

    ret = p11_kit_uri_set_attribute(uri, id);
    if (ret != P11_KIT_URI_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_kit_uri_set_attribute failed.\n");
        goto done;
    }

    ret = p11_kit_uri_set_attribute(uri, &class_attr);
    if (ret != P11_KIT_URI_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_kit_uri_set_attribute failed.\n");
        goto done;
    }


    memcpy(p11_kit_uri_get_token_info(uri), token_info, sizeof(CK_TOKEN_INFO));

    memcpy(p11_kit_uri_get_slot_info(uri), slot_info, sizeof(CK_SLOT_INFO));
    p11_kit_uri_set_slot_id(uri, slot_id);

    memcpy(p11_kit_uri_get_module_info(uri), module_info, sizeof(CK_INFO));

    ret = p11_kit_uri_format(uri, P11_KIT_URI_FOR_ANY, &tmp_str);
    if (ret != P11_KIT_URI_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_kit_uri_format failed [%s].\n",
                                 p11_kit_uri_message(ret));
        goto done;
    }

    if (tmp_str != NULL) {
        uri_str = talloc_strdup(mem_ctx, tmp_str);
        free(tmp_str);
        if (uri_str == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        }
    }

done:
    p11_kit_uri_free(uri);

    return uri_str;
}

static int talloc_cleanup_openssl(struct p11_ctx *p11_ctx)
{
    CRYPTO_cleanup_all_ex_data();

    return 0;
}

errno_t init_p11_ctx(TALLOC_CTX *mem_ctx, const char *ca_db,
                     bool wait_for_card, struct p11_ctx **p11_ctx)
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
    ctx->wait_for_card = wait_for_card;
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
    X509_VERIFY_PARAM *verify_param = NULL;

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

    if (cert_verify_opts->crl_file != NULL) {
        verify_param = X509_VERIFY_PARAM_new();
        if (verify_param == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "X509_VERIFY_PARAM_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        X509_VERIFY_PARAM_set_flags(verify_param, (X509_V_FLAG_CRL_CHECK
                                                  | X509_V_FLAG_CRL_CHECK_ALL));

        X509_STORE_set1_param(store, verify_param);

        ret = X509_load_crl_file(lookup, cert_verify_opts->crl_file,
                                 X509_FILETYPE_PEM);
        if (ret == 0) {
            err = ERR_get_error();
            DEBUG(SSSDBG_OP_FAILURE, "X509_load_crl_file failed [%lu][%s].\n",
                                     err, ERR_error_string(err, NULL));
            ret = EIO;
            goto done;
        }
    }

    p11_ctx->x509_store = store;
    p11_ctx->cert_verify_opts = cert_verify_opts;
    talloc_set_destructor(p11_ctx, talloc_free_x509_store);

    ret = EOK;

done:
    if (ret != EOK) {
        X509_STORE_free(store);
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

    if (p11_ctx->cert_verify_opts->do_ocsp) {
        ret = do_ocsp(p11_ctx, cert);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "do_ocsp failed.\n");
            goto done;
        }
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
        return false;
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
    char *uri;
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

static errno_t wait_for_card(CK_FUNCTION_LIST *module, CK_SLOT_ID *slot_id)
{
    CK_FLAGS wait_flags = 0;
    CK_RV rv;
    CK_SLOT_INFO info;

    rv = module->C_WaitForSlotEvent(wait_flags, slot_id, NULL);
    if (rv != CKR_OK) {
        if (rv != CKR_FUNCTION_NOT_SUPPORTED) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "C_WaitForSlotEvent failed [%lu][%s].\n",
                  rv, p11_kit_strerror(rv));
            return EIO;
        }

        /* Poor man's wait */
        do {
            sleep(10);
            rv = module->C_GetSlotInfo(*slot_id, &info);
            if (rv != CKR_OK) {
                DEBUG(SSSDBG_OP_FAILURE, "C_GetSlotInfo failed\n");
                return EIO;
            }
            DEBUG(SSSDBG_TRACE_ALL,
                  "Description [%s] Manufacturer [%s] flags [%lu] "
                  "removable [%s] token present [%s].\n",
                  info.slotDescription, info.manufacturerID, info.flags,
                  (info.flags & CKF_REMOVABLE_DEVICE) ? "true": "false",
                  (info.flags & CKF_TOKEN_PRESENT) ? "true": "false");
            if ((info.flags & CKF_REMOVABLE_DEVICE)
                    && (info.flags & CKF_TOKEN_PRESENT)) {
                break;
            }
        } while (true);
    }

    return EOK;
}

#define MAX_SLOTS 64

errno_t do_card(TALLOC_CTX *mem_ctx, struct p11_ctx *p11_ctx,
                enum op_mode mode, const char *pin,
                const char *module_name_in, const char *token_name_in,
                const char *key_id_in, const char *uri_str, char **_multi)
{
    int ret;
    size_t c;
    size_t s = 0;
    CK_FUNCTION_LIST **modules = NULL;
    CK_FUNCTION_LIST *module = NULL;
    char *mod_name;
    char *mod_file_name;
    CK_ULONG num_slots;
    CK_SLOT_ID slots[MAX_SLOTS];
    CK_SLOT_ID slot_id;
    CK_SLOT_ID uri_slot_id;
    CK_SLOT_INFO info;
    CK_TOKEN_INFO token_info;
    CK_INFO module_info;
    CK_RV rv;
    size_t module_id;
    char *module_file_name = NULL;
    char *slot_name = NULL;
    char *token_name = NULL;
    CK_SESSION_HANDLE session = 0;
    struct cert_list *all_cert_list = NULL;
    struct cert_list *cert_list = NULL;
    struct cert_list *item = NULL;
    struct cert_list *tmp_cert = NULL;
    char *multi = NULL;
    bool pkcs11_session = false;
    bool pkcs11_login = false;
    P11KitUri *uri = NULL;

    if (uri_str != NULL) {
        uri = p11_kit_uri_new();
        ret = p11_kit_uri_parse(uri_str, P11_KIT_URI_FOR_ANY, uri);
        if (ret != P11_KIT_URI_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "p11_kit_uri_parse failed [%d][%s].\n",
                                     ret, p11_kit_uri_message(ret));
            ret = EINVAL;
            goto done;
        }
    }


    /* Maybe use P11_KIT_MODULE_TRUSTED ? */
    modules = p11_kit_modules_load_and_initialize(0);
    if (modules == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "p11_kit_modules_load_and_initialize failed.\n");
        return EIO;
    }

    for (;;) {
        DEBUG(SSSDBG_TRACE_ALL, "Module List:\n");
        for (c = 0; modules[c] != NULL; c++) {
            mod_name = p11_kit_module_get_name(modules[c]);
            mod_file_name = p11_kit_module_get_filename(modules[c]);
            DEBUG(SSSDBG_TRACE_ALL, "common name: [%s].\n", mod_name);
            DEBUG(SSSDBG_TRACE_ALL, "dll name: [%s].\n", mod_file_name);
            free(mod_name);
            free(mod_file_name);

            if (uri != NULL) {
                memset(&module_info, 0, sizeof(CK_INFO));
                rv = modules[c]->C_GetInfo(&module_info);
                if (rv != CKR_OK) {
                    DEBUG(SSSDBG_OP_FAILURE, "C_GetInfo failed.\n");
                    ret = EIO;
                    goto done;
                }

                /* Skip modules which do not match the PKCS#11 URI */
                if (p11_kit_uri_match_module_info(uri, &module_info) != 1) {
                    DEBUG(SSSDBG_TRACE_ALL,
                          "Not matching URI [%s], skipping.\n", uri_str);
                    continue;
                }
            }

            num_slots = MAX_SLOTS;
            rv = modules[c]->C_GetSlotList(CK_FALSE, slots, &num_slots);
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
                      "Description [%s] Manufacturer [%s] flags [%lu] "
                      "removable [%s] token present [%s].\n",
                      info.slotDescription, info.manufacturerID, info.flags,
                      (info.flags & CKF_REMOVABLE_DEVICE) ? "true": "false",
                      (info.flags & CKF_TOKEN_PRESENT) ? "true": "false");

                /* Skip slots which do not match the PKCS#11 URI */
                if (uri != NULL) {
                    uri_slot_id = p11_kit_uri_get_slot_id(uri);
                    if ((uri_slot_id != (CK_SLOT_ID)-1
                                && uri_slot_id != slots[s])
                            || p11_kit_uri_match_slot_info(uri, &info) != 1) {
                        DEBUG(SSSDBG_TRACE_ALL,
                              "Not matching URI [%s], skipping.\n", uri_str);
                        continue;
                    }
                }

                if ((info.flags & CKF_TOKEN_PRESENT) && uri != NULL) {
                    rv = modules[c]->C_GetTokenInfo(slots[s], &token_info);
                    if (rv != CKR_OK) {
                        DEBUG(SSSDBG_OP_FAILURE, "C_GetTokenInfo failed.\n");
                        ret = EIO;
                        goto done;
                    }
                    DEBUG(SSSDBG_TRACE_ALL, "Token label [%s].\n",
                          token_info.label);

                    if (p11_kit_uri_match_token_info(uri, &token_info) != 1) {
                        DEBUG(SSSDBG_CONF_SETTINGS,
                              "No matching uri [%s], skipping.\n", uri_str);
                        continue;
                    }

                }

                if ((info.flags & CKF_REMOVABLE_DEVICE)) {
                    break;
                }
            }
            if (s != num_slots) {
                break;
            }
        }

        /* When e.g. using Yubikeys the slot isn't present until the device is
         * inserted, so we should wait for a slot as well. */
        if (p11_ctx->wait_for_card && modules[c] == NULL) {
            p11_kit_modules_finalize_and_release(modules);

            sleep(PKCS11_FINIALIZE_INITIALIZE_WAIT_TIME);

            modules = p11_kit_modules_load_and_initialize(0);
            if (modules == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "p11_kit_modules_load_and_initialize failed.\n");
                ret = EIO;
                goto done;
            }

        } else {
            break;
        }
    }

    if (modules[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No removable slots found.\n");
        ret = EIO;
        goto done;
    }

    slot_id = slots[s];

    if (!(info.flags & CKF_TOKEN_PRESENT)) {
        DEBUG(SSSDBG_TRACE_ALL, "Token not present.\n");
        if (p11_ctx->wait_for_card) {
            ret = wait_for_card(modules[c], &slot_id);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "wait_for_card failed.\n");
                goto done;
            }
        } else {
            ret = EIO;
            goto done;
        }
    }

    rv = modules[c]->C_GetTokenInfo(slot_id, &token_info);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "C_GetTokenInfo failed.\n");
        ret = EIO;
        goto done;
    }

    if (uri != NULL && p11_kit_uri_match_token_info(uri, &token_info) != 1) {
        DEBUG(SSSDBG_CONF_SETTINGS, "No token matching uri [%s] found.",
                                    uri_str);
        ret = ENOENT;
        goto done;
    }

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

    ret = read_certs(mem_ctx, module, session, p11_ctx, &all_cert_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "read_certs failed.\n");
        goto done;
    }

    DLIST_FOR_EACH(item, all_cert_list) {
        /* Check if we found the certificates we needed for authentication or
         * the requested ones for pre-auth. For authentication all attributes
         * must be given and match, for pre-auth only the given ones must
         * match. */
        DEBUG(SSSDBG_TRACE_ALL, "%s %s %s %s %s %s.\n",
              module_name_in, module_file_name, token_name_in, token_name,
              key_id_in, item->id);

        if ((mode == OP_AUTH
                && module_name_in != NULL
                && token_name_in != NULL
                && key_id_in != NULL
                && item->id != NULL
                && strcmp(key_id_in, item->id) == 0
                && strcmp(token_name_in, token_name) == 0
                && strcmp(module_name_in, module_file_name) == 0)
            || (mode == OP_PREAUTH
                && (module_name_in == NULL
                    || (module_name_in != NULL
                        && strcmp(module_name_in, module_file_name) == 0))
                && (token_name_in == NULL
                    || (token_name_in != NULL
                        && strcmp(token_name_in, token_name) == 0))
                && (key_id_in == NULL
                    || (key_id_in != NULL && item->id != NULL
                        && strcmp(key_id_in, item->id) == 0)))) {

            tmp_cert = talloc_memdup(mem_ctx, item, sizeof(struct cert_list));
            if (tmp_cert == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_memdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            tmp_cert->prev = NULL;
            tmp_cert->next = NULL;

            DLIST_ADD(cert_list, tmp_cert);

        }
    }

    memset(&module_info, 0, sizeof(CK_INFO));
    rv = module->C_GetInfo(&module_info);
    if (rv != CKR_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "C_GetInfo failed.\n");
        ret = EIO;
        goto done;
    }

    DLIST_FOR_EACH(item, cert_list) {
        item->uri = get_pkcs11_uri(mem_ctx, &module_info, &info, slot_id,
                                   &token_info,
                                   &item->attributes[1] /* label */,
                                   &item->attributes[0] /* id */);
        DEBUG(SSSDBG_TRACE_ALL, "uri: %s.\n", item->uri);
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
    p11_kit_uri_free(uri);

    return ret;
}
