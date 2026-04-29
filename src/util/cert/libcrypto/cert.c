/*
   SSSD - certificate handling utils - OpenSSL version

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
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "jose/b64.h"
#include "util/util.h"
#include "util/sss_endian.h"
#include "util/crypto/sss_crypto.h"

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

/* SSH EC keys are defined in https://tools.ietf.org/html/rfc5656 */
#define ECDSA_SHA2_HEADER "ecdsa-sha2-"
/* Looks like OpenSSH currently only supports the following 3 required
 * curves. */
#define IDENTIFIER_NISTP256 "nistp256"
#define IDENTIFIER_NISTP384 "nistp384"
#define IDENTIFIER_NISTP521 "nistp521"


static char *sss_jose_b64_enc_buf(TALLOC_CTX *mem_ctx,
                                  unsigned char *in, size_t in_len)
{
    char *out = NULL;
    size_t out_len;

    out_len = jose_b64_enc_buf(in, in_len, NULL, 0);
    if (out_len == 0 || out_len == SIZE_MAX) {
        DEBUG(SSSDBG_OP_FAILURE, "jose_b64_enc_buf() failed.\n");
        return NULL;
    }

    out = talloc_zero_size(mem_ctx, out_len + 1);
    if (out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size() failed.\n");
        return NULL;
    }

    out_len = jose_b64_enc_buf(in, in_len, out, out_len);
    if (out_len == 0 || out_len == SIZE_MAX) {
        talloc_free(out);
        DEBUG(SSSDBG_OP_FAILURE, "jose_b64_enc_buf() failed.\n");
        return NULL;
    }

    return out;
}

static int sss_bn_to_base64(TALLOC_CTX *mem_ctx, const BIGNUM *in, char **_out)
{
    int len;
    int ret;
    unsigned char *buf;

    len = BN_num_bytes(in);
    if (len == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Given BIGNUM has len 0.\n");
        return EINVAL;
    }

    buf = talloc_size(mem_ctx, len);
    if (buf == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size() failed.\n");
        return ENOMEM;
    }

    ret = BN_bn2bin(in, buf);
    if (ret != len) {
        DEBUG(SSSDBG_OP_FAILURE, "Return of BN_bn2bin and BN_num_bytes differ.\n");
        ret = EINVAL;
        goto done;
    }

    *_out = sss_jose_b64_enc_buf(mem_ctx, buf, len);
    if (*_out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_jose_b64_enc_buf() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(buf);

    return ret;
}

static int sss_ec_get_x_y_d(BN_CTX *bn_ctx, const EVP_PKEY *cert_pub_key,
                            EC_GROUP **_ec_group,
                            BIGNUM **_x, BIGNUM **_y, BIGNUM **_d)
{
    int ret;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *d = NULL;
    static char curve_name[4096];
    EC_GROUP *ec_group = NULL;

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_EC_PUB_X, &x);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve EC x coordinate.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve EC y coordinate.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_PRIV_KEY, &d);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve EC y coordinate.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_utf8_string_param(cert_pub_key,
                                         OSSL_PKEY_PARAM_GROUP_NAME,
                                         curve_name, sizeof(curve_name), NULL);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve EC group name.\n");
        ret = EINVAL;
        goto done;
    }

    ec_group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(curve_name));
    if (ec_group == NULL) {
        ret = EINVAL;
        goto done;
    }

    *_x = x;
    *_y = y;
    *_d = d;
    *_ec_group = ec_group;

    ret = EOK;

done:
    if (ret != EOK) {
        BN_free(x);
        BN_free(y);
        BN_free(d);
        EC_GROUP_free(ec_group);
    }

    return ret;
}

#define CRV_P256 "P-256"
#define CRV_P384 "P-384"
#define CRV_P521 "P-521"

static errno_t ec_priv_key_jwk(TALLOC_CTX *mem_ctx, EVP_PKEY *cert_priv_key,
                               const char *cert_hash, char **_jwk)
{
    int ret;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *d = NULL;
    EC_GROUP *ec_group = NULL;
    const char *jwk_crv;
    char *out = NULL;
    char *x_str = NULL;
    char *y_str = NULL;
    char *d_str = NULL;
    BN_CTX *bn_ctx = NULL;

    bn_ctx =  BN_CTX_new();
    if (bn_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "BN_CTX_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_ec_get_x_y_d(bn_ctx, cert_priv_key, &ec_group, &x, &y, &d);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve EC parameters.\n");
        goto done;
    }

    switch(EC_GROUP_get_curve_name(ec_group)) {
    case NID_X9_62_prime256v1:
        jwk_crv = CRV_P256;
        break;
    case NID_secp384r1:
        jwk_crv = CRV_P384;
        break;
    case NID_secp521r1:
        jwk_crv = CRV_P521;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported curve [%s]\n",
              OBJ_nid2sn(EC_GROUP_get_curve_name(ec_group)));
        ret = EINVAL;
        goto done;
    }

    ret = sss_bn_to_base64(mem_ctx, x, &x_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, y, &y_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, d, &d_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    if (x_str == NULL || y_str == NULL || d_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to convert BIGNUM to base64.\n");
        ret = ENOMEM;
        goto done;
    }

    out = talloc_asprintf(mem_ctx,
                          "\"kty\":\"EC\","
                          "\"crv\":\"%s\","
                          "\"x\":\"%s\","
                          "\"y\":\"%s\","
                          "\"d\":\"%s\","
                          "\"x5t#S256\":\"%s\"", jwk_crv, x_str, y_str, d_str,
                                                 cert_hash);
    if (out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate JSON snippet.\n");
        ret = ENOMEM;
        goto done;
    }

    *_jwk = out;

    ret = EOK;
done:
    talloc_free(x_str);
    talloc_free(y_str);
    talloc_free(d_str);
    BN_free(x);
    BN_free(y);
    BN_free(d);
    EC_GROUP_free(ec_group);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int sss_rsa_get_priv_comps(const EVP_PKEY *cert_pub_key,
                                  BIGNUM **_n, BIGNUM **_e,
                                  BIGNUM **_d,
                                  BIGNUM **_p, BIGNUM **_q,
                                  BIGNUM **_dp, BIGNUM **_dq,
                                  BIGNUM **_qi)
{
    int ret;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *dp = NULL;
    BIGNUM *dq = NULL;
    BIGNUM *qi = NULL;

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_N, &n);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_E, &e);
    if (ret != 1) {
        BN_clear_free(n);
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_D, &d);
    if (ret != 1) {
        BN_clear_free(n);
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
    if (ret != 1) {
        BN_clear_free(n);
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
    if (ret != 1) {
        BN_clear_free(n);
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dp);
    if (ret != 1) {
        BN_clear_free(n);
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dq);
    if (ret != 1) {
        BN_clear_free(n);
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &qi);
    if (ret != 1) {
        BN_clear_free(n);
        ret = EINVAL;
        goto done;
    }

    *_e = e;
    *_n = n;
    *_d = d;
    *_p = p;
    *_q = q;
    *_dp = dp;
    *_dq = dq;
    *_qi = qi;

    ret = EOK;

done:
    if (ret != EOK) {
        BN_free(n);
        BN_free(e);
        BN_free(d);
        BN_free(p);
        BN_free(q);
        BN_free(dp);
        BN_free(dq);
        BN_free(qi);
    }

    return ret;
}

errno_t rsa_priv_key_jwk(TALLOC_CTX *mem_ctx, EVP_PKEY *cert_priv_key,
                         const char *cert_hash, char **_jwk)
{
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *dp = NULL;
    BIGNUM *dq = NULL;
    BIGNUM *qi = NULL;
    int ret;
    char *out = NULL;
    char *n_str = NULL;
    char *e_str = NULL;
    char *d_str = NULL;
    char *p_str = NULL;
    char *q_str = NULL;
    char *dp_str = NULL;
    char *dq_str = NULL;
    char *qi_str = NULL;

    ret = sss_rsa_get_priv_comps(cert_priv_key, &n, &e, &d, &p, &q,
                                 &dp, &dq, &qi);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve RSA parameters.\n");
        goto done;
    }

    ret = sss_bn_to_base64(mem_ctx, n, &n_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, e, &e_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, d, &d_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, p, &p_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, q, &q_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, dp, &dp_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, dq, &dq_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, qi, &qi_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    if (n_str == NULL || e_str == NULL || d_str == NULL || p_str == NULL
                      || q_str == NULL || dp_str == NULL || dq_str == NULL
                      || qi_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to convert BIGNUM to base64.\n");
        ret = ENOMEM;
        goto done;
    }

    out = talloc_asprintf(mem_ctx,
                          "\"kty\":\"RSA\","
                          "\"n\":\"%s\","
                          "\"e\":\"%s\","
                          "\"d\":\"%s\","
                          "\"p\":\"%s\","
                          "\"q\":\"%s\","
                          "\"dp\":\"%s\","
                          "\"dq\":\"%s\","
                          "\"qi\":\"%s\","
                          "\"alg\":\"%s\","
                          "\"x5t#S256\":\"%s\"", n_str, e_str, d_str, p_str,
                                                 q_str, dp_str, dq_str, qi_str,
                                                 "RS256", cert_hash);
    if (out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate JSON snippet.\n");
        ret = ENOMEM;
        goto done;
    }

    *_jwk = out;

    ret = EOK;
done:

    talloc_free(n_str);
    talloc_free(e_str);
    talloc_free(d_str);
    talloc_free(p_str);
    talloc_free(q_str);
    talloc_free(dp_str);
    talloc_free(dq_str);
    talloc_free(qi_str);

    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dp);
    BN_free(dq);
    BN_free(qi);

    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static int sss_ec_get_key(BN_CTX *bn_ctx, EVP_PKEY *cert_pub_key,
#else
static int sss_ec_get_key(BN_CTX *bn_ctx, const EVP_PKEY *cert_pub_key,
#endif
                          EC_GROUP **_ec_group, EC_POINT **_ec_public_key)
{
    EC_GROUP *ec_group = NULL;
    EC_POINT *ec_public_key = NULL;
    int ret;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    static char curve_name[4096];
    static unsigned char pubkey[4096];
    size_t len;

    ret = EVP_PKEY_get_utf8_string_param(cert_pub_key,
                                         OSSL_PKEY_PARAM_GROUP_NAME,
                                         curve_name, sizeof(curve_name), NULL);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ec_group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(curve_name));
    if (ec_group == NULL) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_octet_string_param(cert_pub_key,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          pubkey, sizeof(pubkey), &len);
    if (ret != 1) {
        EC_GROUP_free(ec_group);
        ret = EINVAL;
        goto done;
    }

    ec_public_key = EC_POINT_new(ec_group);
    if (ec_public_key == NULL) {
        EC_GROUP_free(ec_group);
        ret = EINVAL;
        goto done;
    }

    ret = EC_POINT_oct2point(ec_group, ec_public_key, pubkey, len, bn_ctx);
    if (ret != 1) {
        EC_GROUP_free(ec_group);
        EC_POINT_free(ec_public_key);
        ret = EINVAL;
        goto done;
    }

#else
    EC_KEY *ec_key = NULL;
    const EC_GROUP *gr;
    const EC_POINT *pk;

    ec_key = EVP_PKEY_get0_EC_KEY(cert_pub_key);
    if (ec_key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    gr = EC_KEY_get0_group(ec_key);

    pk = EC_KEY_get0_public_key(ec_key);

    ec_group = EC_GROUP_dup(gr);
    if (ec_group == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ec_public_key = EC_POINT_dup(pk, gr);
    if (ec_public_key == NULL) {
        EC_GROUP_free(ec_group);
        ret = ENOMEM;
        goto done;
    }
#endif

    *_ec_group = ec_group;
    *_ec_public_key = ec_public_key;

    ret = EOK;

done:
    return ret;
}

static errno_t ec_pub_key_to_ssh(TALLOC_CTX *mem_ctx, EVP_PKEY *cert_pub_key,
                                 uint8_t **key_blob, size_t *key_size)
{
    int ret;
    size_t c;
    uint8_t *buf = NULL;
    size_t buf_len;
    EC_GROUP *ec_group = NULL;
    EC_POINT *ec_public_key = NULL;
    BN_CTX *bn_ctx = NULL;
    int key_len;
    const char *identifier = NULL;
    int identifier_len;
    const char *header = NULL;
    int header_len;

    bn_ctx =  BN_CTX_new();
    if (bn_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "BN_CTX_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_ec_get_key(bn_ctx, cert_pub_key, &ec_group, &ec_public_key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get curve details.\n");
        goto done;
    }

    switch(EC_GROUP_get_curve_name(ec_group)) {
    case NID_X9_62_prime256v1:
        identifier = IDENTIFIER_NISTP256;
        header = ECDSA_SHA2_HEADER IDENTIFIER_NISTP256;
        break;
    case NID_secp384r1:
        identifier = IDENTIFIER_NISTP384;
        header = ECDSA_SHA2_HEADER IDENTIFIER_NISTP384;
        break;
    case NID_secp521r1:
        identifier = IDENTIFIER_NISTP521;
        header = ECDSA_SHA2_HEADER IDENTIFIER_NISTP521;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported curve [%s]\n",
              OBJ_nid2sn(EC_GROUP_get_curve_name(ec_group)));
        ret = EINVAL;
        goto done;
    }

    header_len = strlen(header);
    identifier_len = strlen(identifier);

    key_len = EC_POINT_point2oct(ec_group, ec_public_key,
                             POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx);
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

    if (EC_POINT_point2oct(ec_group, ec_public_key,
                           POINT_CONVERSION_UNCOMPRESSED, buf + c, key_len,
                           bn_ctx)
            != key_len) {
        DEBUG(SSSDBG_OP_FAILURE, "EC_POINT_point2oct failed.\n");
        ret = EINVAL;
        goto done;
    }

    *key_size = buf_len;
    *key_blob = buf;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(buf);
    }

    BN_CTX_free(bn_ctx);
    EC_GROUP_free(ec_group);
    EC_POINT_free(ec_public_key);

    return ret;
}


#define SSH_RSA_HEADER "ssh-rsa"
#define SSH_RSA_HEADER_LEN (sizeof(SSH_RSA_HEADER) - 1)

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static int sss_rsa_get_key(EVP_PKEY *cert_pub_key,
#else
static int sss_rsa_get_key(const EVP_PKEY *cert_pub_key,
#endif
                           BIGNUM **_n, BIGNUM **_e)
{
    int ret;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_N, &n);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_pub_key, OSSL_PKEY_PARAM_RSA_E, &e);
    if (ret != 1) {
        BN_clear_free(n);
        ret = EINVAL;
        goto done;
    }

#else

    const BIGNUM *tmp_n;
    const BIGNUM *tmp_e;
    const RSA *rsa_pub_key = NULL;
    rsa_pub_key = EVP_PKEY_get0_RSA(cert_pub_key);
    if (rsa_pub_key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    RSA_get0_key(rsa_pub_key, &tmp_n, &tmp_e, NULL);

    n = BN_dup(tmp_n);
    if (n == NULL) {
        ret = ENOMEM;
        goto done;
    }

    e = BN_dup(tmp_e);
    if (e == NULL) {
        BN_clear_free(n);
        ret = ENOMEM;
        goto done;
    }

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

    *_e = e;
    *_n = n;

    ret = EOK;

done:
    return ret;
}

static errno_t rsa_pub_key_to_ssh(TALLOC_CTX *mem_ctx, EVP_PKEY *cert_pub_key,
                                  uint8_t **key_blob, size_t *key_size)
{
    int ret;
    size_t c;
    size_t size;
    uint8_t *buf = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    int modulus_len;
    unsigned char modulus[OPENSSL_RSA_MAX_MODULUS_BITS/8];
    int exponent_len;
    unsigned char exponent[OPENSSL_RSA_MAX_PUBEXP_BITS/8];

    ret = sss_rsa_get_key(cert_pub_key, &n, &e);
    if (ret != EOK) {
        goto done;
    }

    modulus_len = BN_bn2bin(n, modulus);
    exponent_len = BN_bn2bin(e, exponent);

    size = SSH_RSA_HEADER_LEN + 3 * sizeof(uint32_t)
                + modulus_len
                + exponent_len
                + 1; /* see comment about missing 00 below */
    if (exponent[0] & 0x80)
      size++;

    buf = talloc_size(mem_ctx, size);
    if (buf == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        ret = ENOMEM;
        goto done;
    }

    c = 0;

    SAFEALIGN_SET_UINT32(buf, htobe32(SSH_RSA_HEADER_LEN), &c);
    safealign_memcpy(&buf[c], SSH_RSA_HEADER, SSH_RSA_HEADER_LEN, &c);
    if (exponent[0] & 0x80){
      SAFEALIGN_SET_UINT32(&buf[c], htobe32(exponent_len+1), &c);
      SAFEALIGN_SETMEM_VALUE(&buf[c], '\0', unsigned char, &c);
    } else {
      SAFEALIGN_SET_UINT32(&buf[c], htobe32(exponent_len), &c);
    }
    safealign_memcpy(&buf[c], exponent, exponent_len, &c);

    /* Adding missing 00 which AFAIK is added to make sure
     * the bigint is handled as positive number */
    /* TODO: make a better check if 00 must be added or not, e.g. ... & 0x80)
     */
    SAFEALIGN_SET_UINT32(&buf[c], htobe32(modulus_len + 1), &c);
    SAFEALIGN_SETMEM_VALUE(&buf[c], '\0', unsigned char, &c);
    safealign_memcpy(&buf[c], modulus, modulus_len, &c);

    *key_blob = buf;
    *key_size = size;

    ret = EOK;

done:
    BN_clear_free(n);
    BN_clear_free(e);

    if (ret != EOK)  {
        talloc_free(buf);
    }

    return ret;
}

errno_t get_ssh_key_from_cert(TALLOC_CTX *mem_ctx,
                              const uint8_t *der_blob, size_t der_size,
                              uint8_t **key_blob, size_t *key_size)
{
    int ret;
    const unsigned char *d;
    X509 *cert = NULL;
    EVP_PKEY *cert_pub_key = NULL;

    if (der_blob == NULL || der_size == 0) {
        return EINVAL;
    }

    d = (const unsigned char *) der_blob;

    cert = d2i_X509(NULL, &d, (int) der_size);
    if (cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "d2i_X509 failed.\n");
        return EINVAL;
    }

    cert_pub_key = X509_get_pubkey(cert);
    if (cert_pub_key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "X509_get_pubkey failed.\n");
        ret = EIO;
        goto done;
    }

    switch (EVP_PKEY_base_id(cert_pub_key)) {
    case EVP_PKEY_RSA:
        ret = rsa_pub_key_to_ssh(mem_ctx, cert_pub_key, key_blob, key_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "rsa_pub_key_to_ssh failed.\n");
            goto done;
        }
        break;
    case EVP_PKEY_EC:
        ret = ec_pub_key_to_ssh(mem_ctx, cert_pub_key, key_blob, key_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "rsa_pub_key_to_ssh failed.\n");
            goto done;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected RSA or EC public key, found unsupported [%d].\n",
              EVP_PKEY_base_id(cert_pub_key));
        ret = EINVAL;
        goto done;
    }

done:

    EVP_PKEY_free(cert_pub_key);
    X509_free(cert);

    return ret;
}

static char *get_cert_sha256_hash(TALLOC_CTX *mem_ctx, X509 *cert)
{
    EVP_MD *md = NULL;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char *out;
    int ret;

    md = EVP_MD_fetch(NULL, "sha256", NULL);
    if (md == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize hashing.\n");
        return NULL;
    }

    ret = X509_digest(cert, md, md_value, &md_len);
    EVP_MD_free(md);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to calculate hash.\n");
        return NULL;
    }

    out = sss_jose_b64_enc_buf(mem_ctx, md_value, md_len);
    if (out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to base64-encode hash value.\n");
        return NULL;
    }

    return out;
}

errno_t get_jwk_from_pkcs12(TALLOC_CTX *mem_ctx,
                            const uint8_t *der_blob, size_t der_size,
                            const char *password,
                            char **_jwk)
{
    int ret;
    const unsigned char *d;
    PKCS12 *pkcs12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    char *jwk_base = NULL;
    char *jwk = NULL;
    char *cert_hash = NULL;

    if (der_blob == NULL || der_size == 0) {
        return EINVAL;
    }

    d = (const unsigned char *) der_blob;

    pkcs12 = d2i_PKCS12(NULL, &d, (int) der_size);
    if (pkcs12 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "d2i_PKCS12 failed.\n");
        return EINVAL;
    }

    ret = PKCS12_parse(pkcs12, password, &pkey, &cert, NULL);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to extract private key.\n");
        ret = EIO;
        goto done;
    }

    cert_hash = get_cert_sha256_hash(mem_ctx, cert);
    if (cert_hash == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get SHA-256 hash of certificate.\n");
        ret = EIO;
        goto done;
    }

    switch (EVP_PKEY_base_id(pkey)) {
    case EVP_PKEY_RSA:
        ret = rsa_priv_key_jwk(mem_ctx, pkey, cert_hash, &jwk_base);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "rsa_priv_key_jwk failed.\n");
            goto done;
        }
        break;
    case EVP_PKEY_EC:
        ret = ec_priv_key_jwk(mem_ctx, pkey, cert_hash, &jwk_base);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ec_priv_key_jwk failed.\n");
            goto done;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected RSA or EC public key, found unsupported [%d].\n",
              EVP_PKEY_base_id(pkey));
        ret = EINVAL;
        goto done;
    }

    if (jwk_base == NULL || *jwk_base == '\0') {
        DEBUG(SSSDBG_OP_FAILURE, "Missing JWK key data.\n");
        ret = EINVAL;
        goto done;
    }

    /* optional "use" or "kid" items can be added here */
    jwk = talloc_asprintf(mem_ctx, "{\"keys\":[{%s}]}", jwk_base);
    talloc_free(jwk_base);
    if (jwk == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate JWK.\n");
        ret = ENOMEM;
        goto done;
    }

    *_jwk = jwk;

    ret = EOK;

done:
    EVP_PKEY_free(pkey);
    PKCS12_free(pkcs12);
    X509_free(cert);
    talloc_free(cert_hash);

    return ret;
}
