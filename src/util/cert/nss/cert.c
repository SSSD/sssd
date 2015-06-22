
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

#include "util/util.h"

#include <cert.h>
#include <base64.h>

#include "util/crypto/nss/nss_util.h"

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

    pem_len = strlen(pem);
    if (pem_len <= NS_CERT_HEADER_LEN + NS_CERT_TRAILER_LEN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "PEM data too short.\n");
        return EINVAL;
    }

    if (strncmp(pem, NS_CERT_HEADER, NS_CERT_HEADER_LEN) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Wrong PEM header.\n");
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
