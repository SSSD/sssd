
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

/* taken from NSS's lib/cryptohi/seckey.c */
static SECOidTag
sss_SECKEY_GetECCOid(const SECKEYECParams *params)
{
    SECItem oid = { siBuffer, NULL, 0 };
    SECOidData *oidData = NULL;

    /*
     * params->data needs to contain the ASN encoding of an object ID (OID)
     * representing a named curve. Here, we strip away everything
     * before the actual OID and use the OID to look up a named curve.
     */
    if (params->data[0] != SEC_ASN1_OBJECT_ID)
        return 0;
    oid.len = params->len - 2;
    oid.data = params->data + 2;
    if ((oidData = SECOID_FindOID(&oid)) == NULL)
        return 0;

    return oidData->offset;
}

/* SSH EC keys are defined in https://tools.ietf.org/html/rfc5656 */
#define ECDSA_SHA2_HEADER "ecdsa-sha2-"
/* Looks like OpenSSH currently only supports the following 3 required
 * curves. */
#define IDENTIFIER_NISTP256 "nistp256"
#define IDENTIFIER_NISTP384 "nistp384"
#define IDENTIFIER_NISTP521 "nistp521"

static errno_t ec_pub_key_to_ssh(TALLOC_CTX *mem_ctx,
                                 SECKEYPublicKey *cert_pub_key,
                                 uint8_t **key_blob, size_t *key_size)
{
    int ret;
    size_t c;
    uint8_t *buf = NULL;
    size_t buf_len;
    SECOidTag curve_tag;
    int key_len;
    const char *identifier = NULL;
    int identifier_len;
    const char *header = NULL;
    int header_len;
    SECItem *ec_public_key;

    curve_tag = sss_SECKEY_GetECCOid(&cert_pub_key->u.ec.DEREncodedParams);
    switch(curve_tag) {
    case SEC_OID_ANSIX962_EC_PRIME256V1:
        identifier = IDENTIFIER_NISTP256;
        header = ECDSA_SHA2_HEADER IDENTIFIER_NISTP256;
        break;
    case SEC_OID_SECG_EC_SECP384R1:
        identifier = IDENTIFIER_NISTP384;
        header = ECDSA_SHA2_HEADER IDENTIFIER_NISTP384;
        break;
    case SEC_OID_SECG_EC_SECP521R1:
        identifier = IDENTIFIER_NISTP521;
        header = ECDSA_SHA2_HEADER IDENTIFIER_NISTP521;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported curve [%s]\n",
              SECOID_FindOIDTagDescription(curve_tag));
        ret = EINVAL;
        goto done;
    }

    header_len = strlen(header);
    identifier_len = strlen(identifier);

    ec_public_key = &cert_pub_key->u.ec.publicValue;

    key_len = ec_public_key->len;
    if (key_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "EC_POINT_point2oct failed.\n");
        ret = EINVAL;
        goto done;
    }

    buf_len = header_len + identifier_len + key_len + 3 * sizeof(uint32_t);
    buf = talloc_size(mem_ctx, buf_len * sizeof(uint8_t));
    if (buf == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        ret = ENOMEM;
        goto done;
    }

    c = 0;

    SAFEALIGN_SET_UINT32(buf, htobe32(header_len), &c);
    safealign_memcpy(&buf[c], header, header_len, &c);

    SAFEALIGN_SET_UINT32(&buf[c], htobe32(identifier_len), &c);
    safealign_memcpy(&buf[c], identifier , identifier_len, &c);

    SAFEALIGN_SET_UINT32(&buf[c], htobe32(key_len), &c);

    safealign_memcpy(&buf[c], ec_public_key->data, key_len, &c);

    *key_size = buf_len;
    *key_blob = buf;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(buf);
    }

    return ret;
}

#define SSH_RSA_HEADER "ssh-rsa"
#define SSH_RSA_HEADER_LEN (sizeof(SSH_RSA_HEADER) - 1)

static errno_t rsa_pub_key_to_ssh(TALLOC_CTX *mem_ctx,
                                  SECKEYPublicKey *cert_pub_key,
                                  uint8_t **key_blob, size_t *key_size)
{
    int ret;
    size_t size;
    uint8_t *buf = NULL;
    size_t c;
    size_t exponent_prefix_len;
    size_t modulus_prefix_len;

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

    *key_blob = buf;
    *key_size = size;

    ret = EOK;

done:
    if (ret != EOK)  {
        talloc_free(buf);
    }

    return ret;
}

errno_t get_ssh_key_from_cert(TALLOC_CTX *mem_ctx,
                              uint8_t *der_blob, size_t der_size,
                              uint8_t **key_blob, size_t *key_size)
{
    CERTCertDBHandle *handle;
    CERTCertificate *cert = NULL;
    SECItem der_item;
    SECKEYPublicKey *cert_pub_key = NULL;
    int ret;

    if (der_blob == NULL || der_size == 0) {
        return EINVAL;
    }

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        ret = EIO;
        goto done;
    }

    handle = CERT_GetDefaultCertDB();

    der_item.len = der_size;
    der_item.data = discard_const(der_blob);

    cert = CERT_NewTempCertificate(handle, &der_item, NULL, PR_FALSE, PR_TRUE);
    if (cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_NewTempCertificate failed.\n");
        ret = EINVAL;
        goto done;
    }

    cert_pub_key = CERT_ExtractPublicKey(cert);
    if (cert_pub_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "CERT_ExtractPublicKey failed.\n");
        ret = EIO;
        goto done;
    }

    switch (cert_pub_key->keyType) {
    case rsaKey:
        ret = rsa_pub_key_to_ssh(mem_ctx, cert_pub_key, key_blob, key_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "rsa_pub_key_to_ssh failed.\n");
            goto done;
        }
        break;
    case ecKey:
        ret = ec_pub_key_to_ssh(mem_ctx, cert_pub_key, key_blob, key_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "rsa_pub_key_to_ssh failed.\n");
            goto done;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected RSA or EC public key, found unsupported [%d].\n",
              cert_pub_key->keyType);
        ret = EINVAL;
        goto done;
    }

done:

    SECKEY_DestroyPublicKey(cert_pub_key);
    CERT_DestroyCertificate(cert);

    return ret;
}
