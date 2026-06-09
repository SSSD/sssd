/*
    SSSD

    Helper child for OIDC and OAuth 2.0 Device Authorization Grant
    Utilities using OpenSSL's libcrypto

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2026 Red Hat

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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "jose/b64.h"
#include "util/util.h"
#include "util/crypto/sss_crypto.h"

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

static int sss_bn_to_base64(TALLOC_CTX *mem_ctx, const BIGNUM *in, int exp_len,
                            char **_out)
{
    int in_len;
    int len;
    int ret;
    unsigned char *buf;

    in_len = BN_num_bytes(in);
    if (in_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Given BIGNUM has len 0.\n");
        return EINVAL;
    }

    if (exp_len == 0) {
        len = in_len;
    } else if (exp_len < 0 || (exp_len > 0 && exp_len < in_len)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Expected length [%d] is smaller than needed [%d].\n",
              exp_len, in_len);
        return EINVAL;
    } else {
        len = exp_len;
    }

    buf = talloc_size(mem_ctx, len);
    if (buf == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size() failed.\n");
        return ENOMEM;
    }
    talloc_set_destructor((void *) buf, sss_erase_talloc_mem_securely);

    ret = BN_bn2binpad(in, buf, len);
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

    talloc_set_destructor((void *) *_out, sss_erase_talloc_mem_securely);

    ret = EOK;
done:
    talloc_free(buf);

    return ret;
}

/* This function extracts the ecliptic curve private key parameters from a
 * given EC private key so that the private key can be represented in a
 * different format, e.g. JWK. */
static int sss_ec_get_x_y_d(BN_CTX *bn_ctx, const EVP_PKEY *cert_priv_key,
                            EC_GROUP **_ec_group,
                            BIGNUM **_x, BIGNUM **_y, BIGNUM **_d)
{
    int ret;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *d = NULL;
    char curve_name[4096];
    EC_GROUP *ec_group = NULL;

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_EC_PUB_X, &x);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve EC x coordinate.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve EC y coordinate.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_PRIV_KEY, &d);
    if (ret != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve EC private key.\n");
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_utf8_string_param(cert_priv_key,
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

/* Extract to components of an EC private key and return a string with the
 * corresponding items of a JWK private key. */
static errno_t ec_priv_key_jwk(TALLOC_CTX *mem_ctx, EVP_PKEY *cert_priv_key,
                               char **_jwk)
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
    const char *alg;
    int nid;
    const char *curve_name;
    int len;

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

    nid = EC_GROUP_get_curve_name(ec_group);
    switch(nid) {
    case NID_X9_62_prime256v1:
        jwk_crv = CRV_P256;
        alg  = "ES256";
        break;
    case NID_secp384r1:
        jwk_crv = CRV_P384;
        alg  = "ES384";
        break;
    case NID_secp521r1:
        jwk_crv = CRV_P521;
        alg = "ES512";
        break;
    default:
        curve_name = OBJ_nid2sn(nid);
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported curve [%d][%s]\n",
              nid, curve_name != NULL ? curve_name : "- no name -");
        ret = EINVAL;
        goto done;
    }

    /* The encoded parameters must have a fixed byte length based on the curve, see
     * e.g section 6.2.1.2 of RFC-7518. */
    len = (EC_GROUP_get_degree(ec_group) + 7) / 8;

    ret = sss_bn_to_base64(mem_ctx, x, len, &x_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, y, len, &y_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, d, len, &d_str);
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
                          "\"alg\":\"%s\","
                          "\"x\":\"%s\","
                          "\"y\":\"%s\","
                          "\"d\":\"%s\"", jwk_crv, alg, x_str, y_str, d_str);
    if (out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate JSON snippet.\n");
        ret = ENOMEM;
        goto done;
    }
    talloc_set_destructor((void *) out, sss_erase_talloc_mem_securely);

    *_jwk = out;

    ret = EOK;
done:
    talloc_free(x_str);
    talloc_free(y_str);
    talloc_free(d_str);
    BN_clear_free(x);
    BN_clear_free(y);
    BN_clear_free(d);
    EC_GROUP_free(ec_group);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int sss_rsa_get_priv_comps(const EVP_PKEY *cert_priv_key,
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

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_RSA_N, &n);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_RSA_E, &e);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_RSA_D, &d);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dp);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dq);
    if (ret != 1) {
        ret = EINVAL;
        goto done;
    }

    ret = EVP_PKEY_get_bn_param(cert_priv_key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &qi);
    if (ret != 1) {
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
        BN_clear_free(n);
        BN_clear_free(e);
        BN_clear_free(d);
        BN_clear_free(p);
        BN_clear_free(q);
        BN_clear_free(dp);
        BN_clear_free(dq);
        BN_clear_free(qi);
    }

    return ret;
}

static errno_t rsa_priv_key_jwk(TALLOC_CTX *mem_ctx, EVP_PKEY *cert_priv_key,
                                char **_jwk)
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
    /* Currently it looks like it is sufficient to support RS256 for all RSA
     * keys, this might change in future. */
    const char *alg = "RS256";

    ret = sss_rsa_get_priv_comps(cert_priv_key, &n, &e, &d, &p, &q,
                                 &dp, &dq, &qi);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve RSA parameters.\n");
        goto done;
    }

    ret = sss_bn_to_base64(mem_ctx, n, 0, &n_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, e, 0, &e_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, d, 0, &d_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, p, 0, &p_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, q, 0, &q_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, dp, 0, &dp_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, dq, 0, &dq_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_bn_to_base64() failed.\n");
        goto done;
    }
    ret = sss_bn_to_base64(mem_ctx, qi, 0, &qi_str);
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
                          "\"alg\":\"%s\"", n_str, e_str, d_str, p_str,
                                            q_str, dp_str, dq_str, qi_str,
                                            alg);
    if (out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate JSON snippet.\n");
        ret = ENOMEM;
        goto done;
    }
    talloc_set_destructor((void *) out, sss_erase_talloc_mem_securely);

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

    BN_clear_free(n);
    BN_clear_free(e);
    BN_clear_free(d);
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(dp);
    BN_clear_free(dq);
    BN_clear_free(qi);

    return ret;
}

static char *get_cert_sha256_hash(TALLOC_CTX *mem_ctx, const X509 *cert)
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

    if (pkey == NULL || cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to extract required data from PKCS#12 file, "
              "certificate or private key is missing.\n");
        ret = EINVAL;
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
        ret = rsa_priv_key_jwk(mem_ctx, pkey, &jwk_base);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "rsa_priv_key_jwk failed.\n");
            goto done;
        }
        break;
    case EVP_PKEY_EC:
        ret = ec_priv_key_jwk(mem_ctx, pkey, &jwk_base);
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
    jwk = talloc_asprintf(mem_ctx, "{\"keys\":[{%s,\"x5t#S256\":\"%s\"}]}",
                                   jwk_base, cert_hash);
    talloc_free(jwk_base);
    if (jwk == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate JWK.\n");
        ret = ENOMEM;
        goto done;
    }
    talloc_set_destructor((void *) jwk, sss_erase_talloc_mem_securely);

    *_jwk = jwk;

    ret = EOK;

done:
    EVP_PKEY_free(pkey);
    PKCS12_free(pkcs12);
    X509_free(cert);
    talloc_free(cert_hash);

    return ret;
}
