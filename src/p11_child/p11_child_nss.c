/*
    SSSD

    Helper child to commmunicate with SmartCard via NSS

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <popt.h>

#include "util/util.h"

#include <nss.h>
#include <base64.h>
#include <cryptohi.h>
#include <secmod.h>
#include <cert.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>
#include <ocsp.h>

#include "util/child_common.h"
#include "providers/backend.h"
#include "util/crypto/sss_crypto.h"
#include "util/cert.h"
#include "p11_child/p11_child.h"

struct p11_ctx {
    NSSInitContext *nss_ctx;
    CERTCertDBHandle *handle;
    struct cert_verify_opts *cert_verify_opts;
    const char *nss_db;
};

#define EXP_USAGES (  certificateUsageSSLClient \
                    | certificateUsageSSLServer \
                    | certificateUsageSSLServerWithStepUp \
                    | certificateUsageEmailSigner \
                    | certificateUsageEmailRecipient \
                    | certificateUsageObjectSigner \
                    | certificateUsageStatusResponder \
                    | certificateUsageSSLCA )

static char *password_passthrough(PK11SlotInfo *slot, PRBool retry, void *arg)
{
  /* give up if 1) no password was supplied, or 2) the password has already
   * been rejected once by this token. */
  if (retry || (arg == NULL)) {
    return NULL;
  }
  return PL_strdup((char *)arg);
}

static char *get_key_id_str(PK11SlotInfo *slot, CERTCertificate *cert)
{
    SECItem *key_id = NULL;
    char *key_id_str = NULL;

    key_id = PK11_GetLowLevelKeyIDForCert(slot, cert, NULL);
    if (key_id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "PK11_GetLowLevelKeyIDForCert failed [%d][%s].\n",
              PR_GetError(), PORT_ErrorToString(PR_GetError()));
        return NULL;
    }

    key_id_str = CERT_Hexify(key_id, PR_FALSE);
    SECITEM_FreeItem(key_id, PR_TRUE);
    if (key_id_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_Hexify failed [%d][%s].\n",
              PR_GetError(), PORT_ErrorToString(PR_GetError()));
        return NULL;
    }

    return key_id_str;
}

static int b64_to_cert(struct p11_ctx *p11_ctx, const char *b64,
                       CERTCertificate **cert)
{
    CERTCertificate *c = NULL;
    SECItem der_item = { 0 };

    der_item.data = ATOB_AsciiToData(b64, &der_item.len);
    if (der_item.data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ATOB_AsciiToData failed.\n");
        return EIO;
    }

    c = CERT_NewTempCertificate(p11_ctx->handle, &der_item, NULL, PR_FALSE,
                                PR_TRUE);
    PORT_Free(der_item.data);
    if (c == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_NewTempCertificate failed.\n");
        return EINVAL;
    }

    *cert = c;

    return EOK;
}

static int talloc_free_handle(struct p11_ctx *p11_ctx)
{
    SECStatus rv;

    /* Disable OCSP default responder so that NSS can shutdown properly */
    if (p11_ctx->cert_verify_opts->do_ocsp
            && p11_ctx->cert_verify_opts->ocsp_default_responder != NULL
            && p11_ctx->cert_verify_opts->ocsp_default_responder_signing_cert
                                                                      != NULL) {
        rv = CERT_DisableOCSPDefaultResponder(p11_ctx->handle);
        if (rv != SECSuccess) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "CERT_DisableOCSPDefaultResponder failed: [%d][%s].\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
        }
    }

    return 0;
}

errno_t init_verification(struct p11_ctx *p11_ctx,
                          struct cert_verify_opts *cert_verify_opts)
{
    SECStatus rv;
    CERTCertDBHandle *handle;

    handle = CERT_GetDefaultCertDB();
    if (handle == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_GetDefaultCertDB failed: [%d][%s].\n",
              PR_GetError(), PORT_ErrorToString(PR_GetError()));
        return EIO;
    }

    if (cert_verify_opts->do_ocsp) {
        rv = CERT_EnableOCSPChecking(handle);
        if (rv != SECSuccess) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "CERT_EnableOCSPChecking failed: [%d][%s].\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
            return EIO;
        }

        if (cert_verify_opts->ocsp_default_responder != NULL
            && cert_verify_opts->ocsp_default_responder_signing_cert != NULL) {
            rv = CERT_SetOCSPDefaultResponder(handle,
                         cert_verify_opts->ocsp_default_responder,
                         cert_verify_opts->ocsp_default_responder_signing_cert);
            if (rv != SECSuccess) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "CERT_SetOCSPDefaultResponder failed: [%d][%s].\n",
                      PR_GetError(), PORT_ErrorToString(PR_GetError()));
                return EIO;
            }

            rv = CERT_EnableOCSPDefaultResponder(handle);
            if (rv != SECSuccess) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "CERT_EnableOCSPDefaultResponder failed: [%d][%s].\n",
                      PR_GetError(), PORT_ErrorToString(PR_GetError()));
                return EIO;
            }
        }
    }

    p11_ctx->handle = handle;
    p11_ctx->cert_verify_opts = cert_verify_opts;
    talloc_set_destructor(p11_ctx, talloc_free_handle);

    return EOK;
}

bool do_verification(struct p11_ctx *p11_ctx, CERTCertificate *cert)
{
    SECStatus rv;
    SECCertificateUsage returned_usage = 0;

    rv = CERT_VerifyCertificateNow(p11_ctx->handle, cert, PR_TRUE,
                                   certificateUsageCheckAllUsages,
                                   NULL, &returned_usage);
    if (rv != SECSuccess || ((returned_usage & EXP_USAGES) == 0)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Certificate [%s][%s] not valid [%d][%s].\n",
              cert->nickname, cert->subjectName,
              PR_GetError(), PORT_ErrorToString(PR_GetError()));
        return false;
    }

    return true;
}

bool do_verification_b64(struct p11_ctx *p11_ctx, const char *cert_b64)
{
    int ret;
    CERTCertificate *cert;
    bool res;

    ret = b64_to_cert(p11_ctx, cert_b64, &cert);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to convert certificate.\n");
        return EINVAL;
    }

    res = do_verification(p11_ctx, cert);
    CERT_DestroyCertificate(cert);

    return res;
}

errno_t do_card(TALLOC_CTX *mem_ctx, struct p11_ctx *p11_ctx,
                enum op_mode mode, const char *pin,
                const char *module_name_in, const char *token_name_in,
                const char *key_id_in, char **_multi)
{
    int ret;
    SECStatus rv;
    SECMODModuleList *mod_list;
    SECMODModuleList *mod_list_item;
    SECMODModule *module;
    const char *slot_name;
    const char *token_name;
    PK11SlotInfo *slot = NULL;
    CK_SLOT_ID slot_id;
    SECMODModuleID module_id;
    const char *module_name;
    CERTCertList *cert_list = NULL;
    CERTCertListNode *cert_list_node;
    const PK11DefaultArrayEntry friendly_attr = { "Publicly-readable certs",
                                                  SECMOD_FRIENDLY_FLAG,
                                                  CKM_INVALID_MECHANISM };
    unsigned char random_value[128];
    SECKEYPrivateKey *priv_key;
    SECOidTag algtag;
    SECItem signed_random_value = {0};
    SECKEYPublicKey *pub_key;
    CERTCertificate *found_cert = NULL;
    PK11SlotList *list = NULL;
    PK11SlotListElement *le;
    const char *label;
    char *key_id_str = NULL;
    CERTCertList *valid_certs = NULL;
    char *cert_b64 = NULL;
    char *multi = NULL;
    PRCList *node;

    PK11_SetPasswordFunc(password_passthrough);

    DEBUG(SSSDBG_TRACE_ALL, "Default Module List:\n");
    mod_list = SECMOD_GetDefaultModuleList();
    for (mod_list_item = mod_list; mod_list_item != NULL;
                                   mod_list_item = mod_list_item->next) {
        DEBUG(SSSDBG_TRACE_ALL, "common name: [%s].\n",
                                mod_list_item->module->commonName);
        DEBUG(SSSDBG_TRACE_ALL, "dll name: [%s].\n",
                                mod_list_item->module->dllName);
    }

    DEBUG(SSSDBG_TRACE_ALL, "Dead Module List:\n");
    mod_list = SECMOD_GetDeadModuleList();
    for (mod_list_item = mod_list; mod_list_item != NULL;
                                   mod_list_item = mod_list_item->next) {
        DEBUG(SSSDBG_TRACE_ALL, "common name: [%s].\n",
                                mod_list_item->module->commonName);
        DEBUG(SSSDBG_TRACE_ALL, "dll name: [%s].\n",
                                mod_list_item->module->dllName);
    }

    DEBUG(SSSDBG_TRACE_ALL, "DB Module List:\n");
    mod_list = SECMOD_GetDBModuleList();
    for (mod_list_item = mod_list; mod_list_item != NULL;
                                   mod_list_item = mod_list_item->next) {
        DEBUG(SSSDBG_TRACE_ALL, "common name: [%s].\n",
                                mod_list_item->module->commonName);
        DEBUG(SSSDBG_TRACE_ALL, "dll name: [%s].\n",
                                mod_list_item->module->dllName);
    }

    list = PK11_GetAllTokens(CKM_INVALID_MECHANISM, PR_FALSE, PR_TRUE,
                             NULL);
    if (list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "PK11_GetAllTokens failed.\n");
        ret = EIO;
        goto done;
    }

    for (le = list->head; le; le = le->next) {
        CK_SLOT_INFO slInfo;

        slInfo.flags = 0;
        rv = PK11_GetSlotInfo(le->slot, &slInfo);
        DEBUG(SSSDBG_TRACE_ALL,
              "Description [%s] Manufacturer [%s] flags [%lu].\n",
              slInfo.slotDescription, slInfo.manufacturerID, slInfo.flags);
        if (rv == SECSuccess && (slInfo.flags & CKF_REMOVABLE_DEVICE)) {
            slot = PK11_ReferenceSlot(le->slot);
            break;
        }
    }
    PK11_FreeSlotList(list);
    if (slot == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No removable slots found.\n");
        ret = EIO;
        goto done;
    }

    slot_id = PK11_GetSlotID(slot);
    module_id = PK11_GetModuleID(slot);
    slot_name = PK11_GetSlotName(slot);
    token_name = PK11_GetTokenName(slot);
    module = PK11_GetModule(slot);
    module_name = module->dllName == NULL ? "NSS-Internal" : module->dllName;

    DEBUG(SSSDBG_TRACE_ALL, "Found [%s] in slot [%s][%d] of module [%d][%s].\n",
          token_name, slot_name, (int) slot_id, (int) module_id, module_name);

    if (PK11_IsFriendly(slot)) {
        DEBUG(SSSDBG_TRACE_ALL, "Token is friendly.\n");
    } else {
        DEBUG(SSSDBG_TRACE_ALL,
              "Token is NOT friendly.\n");
        if (mode == OP_PREAUTH) {
            DEBUG(SSSDBG_TRACE_ALL, "Trying to switch to friendly to read certificate.\n");
            rv = PK11_UpdateSlotAttribute(slot, &friendly_attr, PR_TRUE);
            if (rv != SECSuccess) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "PK11_UpdateSlotAttribute failed, continue.\n");
            }
        }
    }

    /* TODO: check  PK11_ProtectedAuthenticationPath() and return the result */
    if (mode == OP_AUTH || PK11_NeedLogin(slot)) {
        DEBUG(SSSDBG_TRACE_ALL, "Login required.\n");
        if (pin != NULL) {
            rv = PK11_Authenticate(slot, PR_FALSE, discard_const(pin));
            if (rv !=  SECSuccess) {
                DEBUG(SSSDBG_OP_FAILURE, "PK11_Authenticate failed: [%d][%s].\n",
                      PR_GetError(), PORT_ErrorToString(PR_GetError()));
                ret = EIO;
                goto done;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Login required but no PIN available, continue.\n");
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "Login NOT required.\n");
    }

    cert_list = PK11_ListCertsInSlot(slot);
    if (cert_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "PK11_ListCertsInSlot failed: [%d][%s].\n",
              PR_GetError(), PORT_ErrorToString(PR_GetError()));
        ret = EIO;
        goto done;
    }

    for (cert_list_node = CERT_LIST_HEAD(cert_list);
                !CERT_LIST_END(cert_list_node, cert_list);
                cert_list_node = CERT_LIST_NEXT(cert_list_node)) {
        if (cert_list_node->cert) {
            DEBUG(SSSDBG_TRACE_ALL, "found cert[%s][%s]\n",
                             cert_list_node->cert->nickname,
                             cert_list_node->cert->subjectName);
        } else {
            DEBUG(SSSDBG_TRACE_ALL, "--- empty cert list node ---\n");
        }
    }

    found_cert = NULL;
    valid_certs = CERT_NewCertList();
    if (valid_certs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_NewCertList failed [%d][%s].\n",
              PR_GetError(), PORT_ErrorToString(PR_GetError()));
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Filtered certificates:\n");
    for (cert_list_node = CERT_LIST_HEAD(cert_list);
                !CERT_LIST_END(cert_list_node, cert_list);
                cert_list_node = CERT_LIST_NEXT(cert_list_node)) {
        if (cert_list_node->cert == NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "--- empty cert list node ---\n");
            continue;
        }

        DEBUG(SSSDBG_TRACE_ALL,
              "found cert[%s][%s]\n",
              cert_list_node->cert->nickname,
              cert_list_node->cert->subjectName);

        if (p11_ctx->handle != NULL) {
            if (!do_verification(p11_ctx, cert_list_node->cert)) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Certificate [%s][%s] not valid, skipping.\n",
                      cert_list_node->cert->nickname,
                      cert_list_node->cert->subjectName);
                continue;
            }
        }

        if (key_id_in != NULL) {
            PORT_Free(key_id_str);
            key_id_str = NULL;
            key_id_str = get_key_id_str(slot, cert_list_node->cert);
        }
        /* Check if we found the certificates we needed for authentication or
         * the requested ones for pre-auth. For authentication all attributes
         * must be given and match, for pre-auth only the given ones must
         * match. */
        DEBUG(SSSDBG_TRACE_ALL, "%s %s %s %s %s %s.\n",
              module_name_in, module_name, token_name_in, token_name,
              key_id_in, key_id_str);
        if ((mode == OP_AUTH
                && module_name_in != NULL
                && token_name_in != NULL
                && key_id_in != NULL
                && key_id_str != NULL
                && strcmp(key_id_in, key_id_str) == 0
                && strcmp(token_name_in, token_name) == 0
                && strcmp(module_name_in, module_name) == 0)
            || (mode == OP_PREAUTH
                && (module_name_in == NULL
                    || (module_name_in != NULL
                        && strcmp(module_name_in, module_name) == 0))
                && (token_name_in == NULL
                    || (token_name_in != NULL
                        && strcmp(token_name_in, token_name) == 0))
                && (key_id_in == NULL
                    || (key_id_in != NULL && key_id_str != NULL
                        && strcmp(key_id_in, key_id_str) == 0)))) {

            rv = CERT_AddCertToListTail(valid_certs, cert_list_node->cert);
            if (rv != SECSuccess) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "CERT_AddCertToListTail failed [%d][%s].\n",
                      PR_GetError(), PORT_ErrorToString(PR_GetError()));
                ret = EIO;
                goto done;
            }
        }
    }

    if (CERT_LIST_EMPTY(valid_certs)) {
        DEBUG(SSSDBG_TRACE_ALL, "No certificate found.\n");
        *_multi = NULL;
        ret = EOK;
        goto done;
    }

    if (mode == OP_AUTH) {
        cert_list_node = CERT_LIST_HEAD(valid_certs);
        if (!CERT_LIST_END(CERT_LIST_NEXT(cert_list_node), valid_certs)) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "More than one certificate found for authentication, "
                  "aborting!\n");
            ret = EINVAL;
            goto done;
        }

        found_cert = cert_list_node->cert;
        if (found_cert == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "No certificate found for authentication, aborting!\n");
            ret = EINVAL;
            goto done;
        }

        rv = PK11_GenerateRandom(random_value, sizeof(random_value));
        if (rv != SECSuccess) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "PK11_GenerateRandom failed [%d][%s].\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
            ret = EIO;
            goto done;
        }

        priv_key = PK11_FindPrivateKeyFromCert(slot, found_cert, NULL);
        if (priv_key == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "PK11_FindPrivateKeyFromCert failed [%d][%s]."
                  "Maybe PIN is missing.\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
            ret = EIO;
            goto done;
        }

        algtag = SEC_GetSignatureAlgorithmOidTag(priv_key->keyType,
                                                  SEC_OID_SHA1);
        if (algtag == SEC_OID_UNKNOWN) {
            SECKEY_DestroyPrivateKey(priv_key);
            DEBUG(SSSDBG_OP_FAILURE,
                  "SEC_GetSignatureAlgorithmOidTag failed [%d][%s].\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
            ret = EIO;
            goto done;
        }

        rv = SEC_SignData(&signed_random_value,
                          random_value, sizeof(random_value),
                          priv_key, algtag);
        SECKEY_DestroyPrivateKey(priv_key);
        if (rv != SECSuccess) {
            DEBUG(SSSDBG_OP_FAILURE, "SEC_SignData failed [%d][%s].\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
            ret = EIO;
            goto done;
        }

        pub_key = CERT_ExtractPublicKey(found_cert);
        if (pub_key == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "CERT_ExtractPublicKey failed [%d][%s].\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
            ret = EIO;
            goto done;
        }

        rv = VFY_VerifyData(random_value, sizeof(random_value),
                            pub_key, &signed_random_value, algtag,
                            NULL);
        SECKEY_DestroyPublicKey(pub_key);
        if (rv != SECSuccess) {
            DEBUG(SSSDBG_OP_FAILURE, "VFY_VerifyData failed [%d][%s].\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
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

    for (cert_list_node = CERT_LIST_HEAD(valid_certs);
                !CERT_LIST_END(cert_list_node, valid_certs);
                cert_list_node = CERT_LIST_NEXT(cert_list_node)) {

        found_cert = cert_list_node->cert;

        PORT_Free(key_id_str);
        key_id_str = get_key_id_str(slot, found_cert);
        if (key_id_str == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "get_key_id_str [%d][%s].\n",
                  PR_GetError(), PORT_ErrorToString(PR_GetError()));
            ret = ENOMEM;
            goto done;
        }

        /* The NSS nickname is typically token_name:label, so the label starts
         * after the ':'. */
        if (found_cert->nickname != NULL) {
            if ((label = strchr(found_cert->nickname, ':')) == NULL) {
                label = found_cert->nickname;
            } else {
                label++;
            }
        } else {
            label = "- no label found -";
        }
        talloc_free(cert_b64);
        cert_b64 = sss_base64_encode(mem_ctx, found_cert->derCert.data,
                                     found_cert->derCert.len);
        if (cert_b64 == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_base64_encode failed.\n");
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL, "Found certificate has key id [%s].\n",
              key_id_str);

        multi = talloc_asprintf_append(multi, "%s\n%s\n%s\n%s\n%s\n",
                                       token_name, module_name, key_id_str,
                                       label, cert_b64);
    }
    *_multi = multi;

    ret = EOK;

done:
    if (slot != NULL) {
        PK11_FreeSlot(slot);
    }

    if (valid_certs != NULL) {
        /* The certificates can be found in valid_certs and cert_list and
         * CERT_DestroyCertList() will free the certificates as well. To avoid
         * a double free the nodes from valid_certs are removed first because
         * valid_certs will only have a sub-set of the certificates. */
        while (!PR_CLIST_IS_EMPTY(&valid_certs->list)) {
            node = PR_LIST_HEAD(&valid_certs->list);
            PR_REMOVE_LINK(node);
        }
        CERT_DestroyCertList(valid_certs);
    }

    if (cert_list != NULL) {
        CERT_DestroyCertList(cert_list);
    }

    PORT_Free(key_id_str);

    PORT_Free(signed_random_value.data);

    talloc_free(cert_b64);

    return ret;
}

static int talloc_nss_shutdown(struct p11_ctx *p11_ctx)
{
    SECStatus rv;

    rv = NSS_ShutdownContext(p11_ctx->nss_ctx);
    if (rv != SECSuccess) {
        DEBUG(SSSDBG_OP_FAILURE, "NSS_ShutdownContext failed [%d][%s].\n",
              PR_GetError(), PORT_ErrorToString(PR_GetError()));
    }

    return 0;
}

errno_t init_p11_ctx(TALLOC_CTX *mem_ctx, const char *nss_db,
                     struct p11_ctx **p11_ctx)
{
    struct p11_ctx *ctx;
    uint32_t flags = NSS_INIT_READONLY
                                   | NSS_INIT_FORCEOPEN
                                   | NSS_INIT_NOROOTINIT
                                   | NSS_INIT_OPTIMIZESPACE
                                   | NSS_INIT_PK11RELOAD;
    NSSInitParameters parameters = { 0 };
    parameters.length =  sizeof (parameters);

    ctx = talloc_zero(mem_ctx, struct p11_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }
    ctx->nss_db = nss_db;

    ctx->nss_ctx = NSS_InitContext(nss_db, "", "", SECMOD_DB, &parameters,
                                    flags);
    if (ctx->nss_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "NSS_InitContext failed [%d][%s].\n",
              PR_GetError(), PORT_ErrorToString(PR_GetError()));
        talloc_free(p11_ctx);
        return EIO;
    }

    talloc_set_destructor(ctx, talloc_nss_shutdown);

    *p11_ctx = ctx;

    return EOK;
}
