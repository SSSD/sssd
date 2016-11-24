/*
   SSSD - certificate handling utils - openssl version

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

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "util/util.h"
#include "util/sss_endian.h"

errno_t sss_cert_der_to_pem(TALLOC_CTX *mem_ctx, const uint8_t *der_blob,
                            size_t der_size, char **pem, size_t *pem_size)
{
    X509 *x509 = NULL;
    BIO *bio_mem = NULL;
    const unsigned char *d;
    int ret;
    long p_size;
    char *p;

    if (der_blob == NULL || der_size == 0) {
        return EINVAL;
    }

    d = (const unsigned char *) der_blob;

    x509 = d2i_X509(NULL, &d, (int) der_size);
    if (x509 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "d2i_X509 failed.\n");
        return EINVAL;
    }

    bio_mem = BIO_new(BIO_s_mem());
    if (bio_mem == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "BIO_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = PEM_write_bio_X509(bio_mem, x509);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "PEM_write_bio_X509 failed.\n");
        ret = EIO;
        goto done;
    }

    p_size = BIO_get_mem_data(bio_mem, &p);
    if (p_size == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected PEM size [%ld].\n", p_size);
        ret = EINVAL;
        goto done;
    }

    if (pem != NULL) {
        *pem = talloc_strndup(mem_ctx, p, p_size);
        if (*pem == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_memdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (pem_size != NULL) {
        *pem_size = p_size;
    }

    ret = EOK;

done:
    X509_free(x509);
    BIO_free_all(bio_mem);

    return ret;
}

errno_t sss_cert_pem_to_der(TALLOC_CTX *mem_ctx, const char *pem,
                            uint8_t **_der_blob, size_t *_der_size)
{
    X509 *x509 = NULL;
    BIO *bio_mem = NULL;
    int ret;
    unsigned char *buf;
    int buf_size;
    uint8_t *der_blob;
    size_t der_size;

    if (pem == NULL) {
        return EINVAL;
    }

    bio_mem = BIO_new(BIO_s_mem());
    if (bio_mem == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "BIO_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = BIO_puts(bio_mem, pem);
    if (ret <= 0) {
        DEBUG(SSSDBG_OP_FAILURE, "BIO_puts failed.\n");
        ret = EIO;
        goto done;
    }

    x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    if (x509 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "PEM_read_bio_X509 failed.\n");
        ret = EIO;
        goto done;
    }

    buf_size = i2d_X509(x509, NULL);
    if (buf_size <= 0) {
        DEBUG(SSSDBG_OP_FAILURE, "i2d_X509 failed.\n");
        ret = EIO;
        goto done;
    }

    if (_der_blob != NULL) {
        buf = talloc_size(mem_ctx, buf_size);
        if (buf == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
            ret = ENOMEM;
            goto done;
        }

        der_blob = buf;

        der_size = i2d_X509(x509, &buf);
        if (der_size != buf_size) {
            talloc_free(der_blob);
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "i2d_X509 size mismatch between two calls.\n");
            ret = EIO;
            goto done;
        }

        *_der_blob = der_blob;
    }

    if (_der_size != NULL) {
        *_der_size = buf_size;
    }

    ret = EOK;

done:
    X509_free(x509);
    BIO_free_all(bio_mem);

    return ret;

}

#define SSH_RSA_HEADER "ssh-rsa"
#define SSH_RSA_HEADER_LEN (sizeof(SSH_RSA_HEADER) - 1)

errno_t cert_to_ssh_key(TALLOC_CTX *mem_ctx, const char *ca_db,
                        const uint8_t *der_blob, size_t der_size,
                        struct cert_verify_opts *cert_verify_opts,
                        uint8_t **key, size_t *key_size)
{
    int ret;
    size_t size;
    const unsigned char *d;
    uint8_t *buf = NULL;
    size_t c;
    X509 *cert = NULL;
    EVP_PKEY *cert_pub_key = NULL;
    const BIGNUM *n;
    const BIGNUM *e;
    int modulus_len;
    unsigned char modulus[OPENSSL_RSA_MAX_MODULUS_BITS/8];
    int exponent_len;
    unsigned char exponent[OPENSSL_RSA_MAX_PUBEXP_BITS/8];

    if (der_blob == NULL || der_size == 0) {
        return EINVAL;
    }

    d = (const unsigned char *) der_blob;

    cert = d2i_X509(NULL, &d, (int) der_size);
    if (cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "d2i_X509 failed.\n");
        return EINVAL;
    }

    /* TODO: verify certificate !!!!! */

    cert_pub_key = X509_get_pubkey(cert);
    if (cert_pub_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "X509_get_pubkey failed.\n");
        ret = EIO;
        goto done;
    }

    if (EVP_PKEY_base_id(cert_pub_key) != EVP_PKEY_RSA) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected RSA public key, found unsupported [%d].\n",
              EVP_PKEY_base_id(cert_pub_key));
        ret = EINVAL;
        goto done;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    RSA *rsa_pub_key = NULL;
    rsa_pub_key = EVP_PKEY_get0_RSA(cert_pub_key);
    if (rsa_pub_key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    RSA_get0_key(rsa_pub_key, &n, &e, NULL);
#else
    n = cert_pub_key->pkey.rsa->n;
    e = cert_pub_key->pkey.rsa->e;
#endif
    modulus_len = BN_bn2bin(n, modulus);
    exponent_len = BN_bn2bin(e, exponent);

    size = SSH_RSA_HEADER_LEN + 3 * sizeof(uint32_t)
                + modulus_len
                + exponent_len
                + 1; /* see comment about missing 00 below */

    buf = talloc_size(mem_ctx, size);
    if (buf == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        ret = ENOMEM;
        goto done;
    }

    c = 0;

    SAFEALIGN_SET_UINT32(buf, htobe32(SSH_RSA_HEADER_LEN), &c);
    safealign_memcpy(&buf[c], SSH_RSA_HEADER, SSH_RSA_HEADER_LEN, &c);
    SAFEALIGN_SET_UINT32(&buf[c], htobe32(exponent_len), &c);
    safealign_memcpy(&buf[c], exponent, exponent_len, &c);

    /* Adding missing 00 which afaik is added to make sure
     * the bigint is handled as positive number */
    /* TODO: make a better check if 00 must be added or not, e.g. ... & 0x80)
     */
    SAFEALIGN_SET_UINT32(&buf[c], htobe32(modulus_len + 1), &c);
    SAFEALIGN_SETMEM_VALUE(&buf[c], '\0', unsigned char, &c);
    safealign_memcpy(&buf[c], modulus, modulus_len, &c);

    *key = buf;
    *key_size = size;

    ret = EOK;

done:
    if (ret != EOK)  {
        talloc_free(buf);
    }
    EVP_PKEY_free(cert_pub_key);
    X509_free(cert);

    return ret;
}
