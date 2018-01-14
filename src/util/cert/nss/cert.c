
/*
   SSSD - certificate handling utils - NSS version

   Copyright (C) Sumit Bose <sbose@redhat.com> 2015

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

#include "config.h"

#include <nss.h>
#include <cert.h>
#include <base64.h>
#include <key.h>
#include <prerror.h>
#include <ocsp.h>
#include <talloc.h>

#include "util/crypto/sss_crypto.h"
#include "util/crypto/nss/nss_util.h"
#include "util/cert.h"
#include "util/sss_endian.h"

#define NS_CERT_HEADER "-----BEGIN CERTIFICATE-----"
#define NS_CERT_TRAILER "-----END CERTIFICATE-----"
#define NS_CERT_HEADER_LEN  ((sizeof NS_CERT_HEADER) - 1)
#define NS_CERT_TRAILER_LEN ((sizeof NS_CERT_TRAILER) - 1)

errno_t sss_cert_der_to_pem(TALLOC_CTX *mem_ctx, const uint8_t *der_blob,
                            size_t der_size, char **pem, size_t *pem_size)
{

    CERTCertDBHandle *handle;
    CERTCertificate *cert = NULL;
    SECItem der_item;
    char *ascii_crlf = NULL;
    size_t ascii_crlf_len;
    char *ascii_lf = NULL;
    char *pem_cert_str = NULL;
    int ret;
    size_t c;
    size_t d;

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "nspr_nss_init failed.\n");
        return ret;
    }

    handle = CERT_GetDefaultCertDB();

    der_item.len = der_size;
    der_item.data = discard_const(der_blob);

    cert = CERT_NewTempCertificate(handle, &der_item, NULL, PR_FALSE, PR_TRUE);
    if (cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_NewTempCertificate failed.\n");
        return EINVAL;
    }

    ascii_crlf = BTOA_DataToAscii(cert->derCert.data, cert->derCert.len);
    if (ascii_crlf == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "BTOA_DataToAscii failed.\n");
        ret = EIO;
        goto done;
    }

    ascii_crlf_len = strlen(ascii_crlf) + 1;
    ascii_lf = talloc_size(mem_ctx, ascii_crlf_len * sizeof(char));
    if (ascii_lf == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "malloc failed.\n");
        ret = ENOMEM;
        goto done;
    }

    d = 0;
    for (c = 0; c < ascii_crlf_len; c++) {
        if (ascii_crlf[c] != '\r') {
            ascii_lf[d++] = ascii_crlf[c];
        }
    }

    pem_cert_str = talloc_asprintf(mem_ctx, "%s\n%s\n%s\n", NS_CERT_HEADER,
                                                            ascii_lf,
                                                            NS_CERT_TRAILER);
    if (pem_cert_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (pem_size != NULL) {
        *pem_size = strlen(pem_cert_str);
    }

    if (pem != NULL) {
        *pem = pem_cert_str;
        pem_cert_str = NULL;
    }

    ret = EOK;
done:
    talloc_free(pem_cert_str);
    talloc_free(ascii_lf);
    PORT_Free(ascii_crlf);
    CERT_DestroyCertificate(cert);

    return ret;
}

errno_t sss_cert_pem_to_der(TALLOC_CTX *mem_ctx, const char *pem,
                            uint8_t **_der_blob, size_t *_der_size)
{
    const char *ps;
    const char *pe;
    size_t pem_len;
    uint8_t *der_blob = NULL;
    unsigned int der_size; /* unsigned int to match 2nd parameter of
                              ATOB_AsciiToData */
    CERTCertDBHandle *handle;
    CERTCertificate *cert = NULL;
    SECItem der_item;
    int ret;
    char *b64 = NULL;

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "nspr_nss_init failed.\n");
        return ret;
    }

    if (pem == NULL || *pem == '\0') {
        return EINVAL;
    }

    if ((pem = strstr(pem, NS_CERT_HEADER)) == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing PEM header.");
        return EINVAL;
    }

    pem_len = strlen(pem);
    if (pem_len <= NS_CERT_HEADER_LEN + NS_CERT_TRAILER_LEN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "PEM data too short.\n");
        return EINVAL;
    }

    if (pem[NS_CERT_HEADER_LEN] != '\n') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing newline in PEM data.\n");
        return EINVAL;
    }

    pe = pem + pem_len - NS_CERT_TRAILER_LEN;
    if (pem[pem_len - 1] == '\n') {
        pe--;
    }
    if (strncmp(pe, NS_CERT_TRAILER, NS_CERT_TRAILER_LEN) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Wrong PEM trailer.\n");
        return EINVAL;
    }

    ps = pem + NS_CERT_HEADER_LEN + 1;

    b64 = talloc_strndup(mem_ctx, ps, pe - ps);
    if(b64 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    der_blob = ATOB_AsciiToData(b64, &der_size);
    if (der_blob == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ATOB_AsciiToData failed.\n");
        return EIO;
    }

    handle = CERT_GetDefaultCertDB();

    der_item.len = der_size;
    der_item.data = der_blob;

    cert = CERT_NewTempCertificate(handle, &der_item, NULL, PR_FALSE, PR_TRUE);
    if (cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_NewTempCertificate failed.\n");
        ret = EINVAL;
        goto done;
    }

    if (_der_blob != NULL) {
        *_der_blob = talloc_memdup(mem_ctx, cert->derCert.data,
                                   cert->derCert.len);
        if (*_der_blob == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_memdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (_der_size != NULL) {
        *_der_size = cert->derCert.len;
    }
done:
    PORT_Free(der_blob);
    talloc_free(b64);
    CERT_DestroyCertificate(cert);

    return ret;
}

#define SSH_RSA_HEADER "ssh-rsa"
#define SSH_RSA_HEADER_LEN (sizeof(SSH_RSA_HEADER) - 1)

errno_t cert_to_ssh_key(TALLOC_CTX *mem_ctx, const char *ca_db,
                        const uint8_t *der_blob, size_t der_size,
                        struct cert_verify_opts *cert_verify_opts,
                        uint8_t **key, size_t *key_size)
{
    CERTCertDBHandle *handle;
    CERTCertificate *cert = NULL;
    SECItem der_item;
    SECKEYPublicKey *cert_pub_key = NULL;
    int ret;
    size_t size;
    uint8_t *buf = NULL;
    size_t c;
    NSSInitContext *nss_ctx;
    NSSInitParameters parameters = { 0 };
    parameters.length =  sizeof (parameters);
    SECStatus rv;
    SECStatus rv_verify;
    size_t exponent_prefix_len;
    size_t modulus_prefix_len;

    if (der_blob == NULL || der_size == 0) {
        return EINVAL;
    }

    /* initialize NSS with context, we might have already called
     * NSS_NoDB_Init() but for validation we need to have access to a DB with
     * the trusted issuer cert. Only NSS_InitContext will really open the DB
     * in this case. I'm not sure about how long validation might need e.g. if
     * CRLs or OSCP is enabled, maybe it would be better to run validation in
     * p11_child? */
    nss_ctx = NSS_InitContext(ca_db, "", "", SECMOD_DB, &parameters,
                              NSS_INIT_READONLY);
    if (nss_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "NSS_InitContext failed [%d].\n",
                                 PR_GetError());
        return EIO;
    }

    handle = CERT_GetDefaultCertDB();

    if (cert_verify_opts->do_ocsp) {
        rv = CERT_EnableOCSPChecking(handle);
        if (rv != SECSuccess) {
            DEBUG(SSSDBG_OP_FAILURE, "CERT_EnableOCSPChecking failed: [%d].\n",
                                     PR_GetError());
            return EIO;
        }

        if (cert_verify_opts->ocsp_default_responder != NULL
            && cert_verify_opts->ocsp_default_responder_signing_cert != NULL) {
            rv = CERT_SetOCSPDefaultResponder(handle,
                         cert_verify_opts->ocsp_default_responder,
                         cert_verify_opts->ocsp_default_responder_signing_cert);
            if (rv != SECSuccess) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "CERT_SetOCSPDefaultResponder failed: [%d].\n",
                      PR_GetError());
                return EIO;
            }

            rv = CERT_EnableOCSPDefaultResponder(handle);
            if (rv != SECSuccess) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "CERT_EnableOCSPDefaultResponder failed: [%d].\n",
                      PR_GetError());
                return EIO;
            }
        }
    }

    der_item.len = der_size;
    der_item.data = discard_const(der_blob);

    cert = CERT_NewTempCertificate(handle, &der_item, NULL, PR_FALSE, PR_TRUE);
    if (cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_NewTempCertificate failed.\n");
        ret = EINVAL;
        goto done;
    }

    if (cert_verify_opts->do_verification) {
        rv_verify = CERT_VerifyCertificateNow(handle, cert, PR_TRUE,
                                              certificateUsageSSLClient,
                                              NULL, NULL);

        /* Disable OCSP default responder so that NSS can shutdown properly */
        if (cert_verify_opts->do_ocsp
                && cert_verify_opts->ocsp_default_responder != NULL
                && cert_verify_opts->ocsp_default_responder_signing_cert
                                                                      != NULL) {
            rv = CERT_DisableOCSPDefaultResponder(handle);
            if (rv != SECSuccess) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "CERT_DisableOCSPDefaultResponder failed: [%d].\n",
                      PR_GetError());
            }
        }

        if (rv_verify != SECSuccess) {
            DEBUG(SSSDBG_CRIT_FAILURE, "CERT_VerifyCertificateNow failed [%d].\n",
                                       PR_GetError());
            ret = EACCES;
            goto done;
        }
    }

    cert_pub_key = CERT_ExtractPublicKey(cert);
    if (cert_pub_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_ExtractPublicKey failed.\n");
        ret = EIO;
        goto done;
    }

    if (cert_pub_key->keyType != rsaKey) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected RSA public key, found unsupported [%d].\n",
              cert_pub_key->keyType);
        ret = EINVAL;
        goto done;
    }

    /* Looks like nss drops the leading 00 which AFAIK is added to make sure
     * the bigint is handled as positive number if the leading bit is set. */
    exponent_prefix_len = 0;
    if (cert_pub_key->u.rsa.publicExponent.data[0] & 0x80) {
        exponent_prefix_len = 1;
    }

    modulus_prefix_len = 0;
    if (cert_pub_key->u.rsa.modulus.data[0] & 0x80) {
        modulus_prefix_len = 1;
    }
    size = SSH_RSA_HEADER_LEN + 3 * sizeof(uint32_t)
                + cert_pub_key->u.rsa.modulus.len
                + cert_pub_key->u.rsa.publicExponent.len
                + exponent_prefix_len + modulus_prefix_len;

    buf = talloc_size(mem_ctx, size);
    if (buf == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        ret = ENOMEM;
        goto done;
    }

    c = 0;

    SAFEALIGN_SET_UINT32(buf, htobe32(SSH_RSA_HEADER_LEN), &c);
    safealign_memcpy(&buf[c], SSH_RSA_HEADER, SSH_RSA_HEADER_LEN, &c);
    SAFEALIGN_SET_UINT32(&buf[c],
                         htobe32(cert_pub_key->u.rsa.publicExponent.len
                                    + exponent_prefix_len), &c);
    if (exponent_prefix_len == 1) {
        SAFEALIGN_SETMEM_VALUE(&buf[c], '\0', unsigned char, &c);
    }
    safealign_memcpy(&buf[c], cert_pub_key->u.rsa.publicExponent.data,
                     cert_pub_key->u.rsa.publicExponent.len, &c);

    SAFEALIGN_SET_UINT32(&buf[c],
                         htobe32(cert_pub_key->u.rsa.modulus.len
                                    + modulus_prefix_len ), &c);
    if (modulus_prefix_len == 1) {
        SAFEALIGN_SETMEM_VALUE(&buf[c], '\0', unsigned char, &c);
    }
    safealign_memcpy(&buf[c], cert_pub_key->u.rsa.modulus.data,
                     cert_pub_key->u.rsa.modulus.len, &c);

    *key = buf;
    *key_size = size;

    ret = EOK;

done:
    if (ret != EOK)  {
        talloc_free(buf);
    }
    SECKEY_DestroyPublicKey(cert_pub_key);
    CERT_DestroyCertificate(cert);

    rv = NSS_ShutdownContext(nss_ctx);
    if (rv != SECSuccess) {
        DEBUG(SSSDBG_OP_FAILURE, "NSS_ShutdownContext failed [%d].\n",
                                 PR_GetError());
    }

    return ret;
}
