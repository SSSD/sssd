/*
   SSSD

   KCM Server - ccache JSON (un)marshalling for storing ccaches in
                sssd-secrets

   Copyright (C) Red Hat, 2017

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

#include <stdio.h>
#include <talloc.h>
#include <jansson.h>

#include "util/util.h"
#include "util/util_creds.h"
#include "util/crypto/sss_crypto.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"

/*
 * We keep the JSON representation of the ccache versioned to allow
 * us to modify the format in a future version
 */
#define KS_JSON_VERSION     1

/* Compat definition of json_array_foreach for older systems */
#ifndef json_array_foreach
#define json_array_foreach(array, idx, value) \
    for(idx = 0; \
            idx < json_array_size(array) && (value = json_array_get(array, idx)); \
            idx++)
#endif

/*
 * Creates an array of principal elements that will be used later
 * in the form of:
 *          "components": [ "elem1", "elem2", ...]
 */
static json_t *princ_data_to_json(TALLOC_CTX *mem_ctx,
                                  krb5_principal princ)
{
    json_t *jdata = NULL;
    json_t *data_array = NULL;
    int ret;
    char *str_princ_data;

    data_array = json_array();
    if (data_array == NULL) {
        return NULL;
    }

    for (ssize_t i = 0; i < princ->length; i++) {
        /* FIXME - it might be cleaner to use stringn here, but the libjansson
         * version on RHEL-7 doesn't support that
         */
        str_princ_data = talloc_zero_array(mem_ctx,
                                           char,
                                           princ->data[i].length + 1);
        if (str_princ_data == NULL) {
            return NULL;
        }
        memcpy(str_princ_data, princ->data[i].data, princ->data[i].length);
        str_princ_data[princ->data[i].length] = '\0';

        jdata = json_string(str_princ_data);
        talloc_free(str_princ_data);
        if (jdata == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert principal data to string\n");
            json_decref(data_array);
            return NULL;
        }

        ret = json_array_append_new(data_array, jdata);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot append principal data to array\n");
            json_decref(jdata);
            json_decref(data_array);
            return NULL;
        }
        /* data_array now owns the reference to jdata */
    }

    return data_array;
}

/* Creates:
 *      {
 *          "type": "number",
 *          "realm": "string",
 *          "components": [ "elem1", "elem2", ...]
 *      }
 */
static json_t *princ_to_json(TALLOC_CTX *mem_ctx,
                             krb5_principal princ)
{
    json_t *jprinc = NULL;
    json_t *components = NULL;
    json_error_t error;
    char *str_realm_data;

    if (princ == NULL) {
        jprinc = json_pack_ex(&error,
                              JSON_STRICT,
                              "{}");
        if (jprinc == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to pack JSON princ structure on line %d: %s\n",
                  error.line, error.text);
            return NULL;
        }

        return jprinc;
    }

    components = princ_data_to_json(mem_ctx, princ);
    if (components == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert principal data to JSON\n");
        return NULL;
    }

    /* FIXME - it might be cleaner to use the s% specifier here, but the libjansson
     * version on RHEL-7 doesn't support that
     */
    str_realm_data = talloc_zero_array(mem_ctx,
                                        char,
                                        princ->realm.length + 1);
    if (str_realm_data == NULL) {
        return NULL;
    }
    memcpy(str_realm_data, princ->realm.data, princ->realm.length);
    str_realm_data[princ->realm.length] = '\0';

    jprinc = json_pack_ex(&error,
                          JSON_STRICT,
                          "{s:i, s:s, s:o}",
                          "type", princ->type,
                          "realm", str_realm_data,
                          "components", components);
    talloc_free(str_realm_data);
    if (jprinc == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to pack JSON princ structure on line %d: %s\n",
              error.line, error.text);
        json_decref(components);
        return NULL;
    }

    return jprinc;
}

/* Creates:
 *          {
 *              "uuid": <data>,
 *              "payload": <data>,
 *          },
 */
static json_t *cred_to_json(struct kcm_cred *crd)
{
    char uuid_str[UUID_STR_SIZE];
    uint8_t *cred_blob_data;
    size_t cred_blob_size;
    json_t *jcred;
    json_error_t error;
    char *base64_cred_blob;

    uuid_unparse(crd->uuid, uuid_str);
    cred_blob_data = sss_iobuf_get_data(crd->cred_blob);
    cred_blob_size = sss_iobuf_get_size(crd->cred_blob);

    base64_cred_blob = sss_base64_encode(crd, cred_blob_data, cred_blob_size);
    if (base64_cred_blob == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot base64 encode the certificate blob\n");
        return NULL;
    }

    jcred = json_pack_ex(&error,
                         JSON_STRICT,
                         "{s:s, s:s}",
                         "uuid", uuid_str,
                         "payload", base64_cred_blob);
    talloc_free(base64_cred_blob);
    if (jcred == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to pack JSON cred structure on line %d: %s\n",
              error.line, error.text);
        return NULL;
    }
    return jcred;
}

/*
 * Creates:
 *      [
 *          {
 *              "uuid": <data>,
 *              "payload": <data>,
 *          },
 *          ...
 *      ]
 */
static json_t *creds_to_json_array(struct kcm_cred *creds)
{
    struct kcm_cred *crd;
    json_t *array;
    json_t *jcred;

    array = json_array();
    if (array == NULL) {
        return NULL;
    }

    DLIST_FOR_EACH(crd, creds) {
        jcred = cred_to_json(crd);
        if (jcred == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert credentials to JSON\n");
            json_decref(array);
            return NULL;
        }

        json_array_append_new(array, jcred);
        /* array now owns jcred */
        jcred = NULL;
    }

    return array;
}

/*
 * The ccache is formatted in JSON as:
 * {
 *      version: number
 *      kdc_offset: number
 *      principal : {
 *          "type": "number",
 *          "realm": "string",
 *          "components": [ "elem1", "elem2", ...]
 *      }
 *      creds : [
 *                  {
 *                      "uuid": <data>,
 *                      "payload": <data>,
 *                  },
 *                  {
 *                      ...
 *                  }
 *             ]
 *      }
 * }
 */
static json_t *ccache_to_json(struct kcm_ccache *cc)
{
    json_t *princ = NULL;
    json_t *creds = NULL;
    json_t *jcc = NULL;
    json_error_t error;

    princ = princ_to_json(cc, cc->client);
    if (princ == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert princ to JSON\n");
        return NULL;
    }

    creds = creds_to_json_array(cc->creds);
    if (creds == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert creds to JSON array\n");
        json_decref(princ);
        return NULL;
    }

    jcc = json_pack_ex(&error,
                       JSON_STRICT,
                       "{s:i, s:i, s:o, s:o}",
                       "version", KS_JSON_VERSION,
                       "kdc_offset", cc->kdc_offset,
                       "principal", princ,
                       "creds", creds);
    if (jcc == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to pack JSON ccache structure on line %d: %s\n",
              error.line, error.text);
        json_decref(creds);
        json_decref(princ);
        return NULL;
    }

    return jcc;
}

static errno_t ccache_to_sec_val(TALLOC_CTX *mem_ctx,
                                 struct kcm_ccache *cc,
                                 const char **_sec_value)
{
    json_t *jcc = NULL;
    char *jdump;

    jcc = ccache_to_json(cc);
    if (jcc == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert ccache to JSON\n");
        return ERR_JSON_ENCODING;
    }

    /* it would be more efficient to learn the size with json_dumpb and
     * a NULL buffer, but that's only available since 2.10
     */
    jdump = json_dumps(jcc, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    if (jdump == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot dump JSON\n");
        return ERR_JSON_ENCODING;
    }

    *_sec_value = talloc_strdup(mem_ctx, jdump);
    free(jdump);
    json_decref(jcc);
    if (*_sec_value == NULL) {
        return ENOMEM;
    }

    return EOK;
}

errno_t kcm_ccache_to_sec_input_json(TALLOC_CTX *mem_ctx,
                                     struct kcm_ccache *cc,
                                     struct sss_iobuf **_payload)
{
    errno_t ret;
    const char *value;
    struct sss_iobuf *payload;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ccache_to_sec_val(mem_ctx, cc, &value);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert cache %s to JSON [%d]: %s\n",
              cc->name, ret, sss_strerror(ret));
        goto done;
    }

    payload = sss_iobuf_init_readonly(tmp_ctx,
                                      (const uint8_t *) value,
                                      strlen(value)+1);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot create payload buffer\n");
        goto done;
    }

    ret = EOK;
    *_payload = talloc_steal(mem_ctx, payload);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sec_value_to_json(const char *input,
                                 json_t **_root)
{
    json_t *root = NULL;
    json_error_t error;
    int ok;

    root = json_loads(input, 0, &error);
    if (root == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse JSON payload on line %d: %s\n",
              error.line, error.text);
        return ERR_JSON_DECODING;
    }

    ok = json_is_object(root);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json data is not an object.\n");
        json_decref(root);
        return ERR_JSON_DECODING;
    }

    *_root = root;
    return EOK;
}

/*
 * ccache unmarshalling from JSON
 */
static errno_t json_element_to_krb5_data(TALLOC_CTX *mem_ctx,
                                         json_t *element,
                                         krb5_data *data)
{
    const char *str_value;
    size_t str_len;

    /* FIXME - it might be cleaner to use stringn here, but the libjansson
     * version on RHEL-7 doesn't support that
     */
    str_value = json_string_value(element);
    if (str_value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "JSON element not a string\n");
        return EINVAL;
    }
    str_len = strlen(str_value);
    /* make sure that the unsigned int length component of krb5_data can store
     * str_len. */
    if (str_len > UINT_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "String too long");
        return EINVAL;
    }

    data->data = talloc_strndup(mem_ctx, str_value, str_len);
    if (data->data == NULL) {
        return ENOMEM;
    }
    data->length = (unsigned int) str_len;

    return EOK;
}

static errno_t json_array_to_krb5_data(TALLOC_CTX *mem_ctx,
                                       json_t *array,
                                       krb5_data **_data,
                                       size_t *_len)
{
    errno_t ret;
    int ok;
    size_t len;
    size_t idx;
    json_t *element;
    krb5_data *data;

    ok = json_is_array(array);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json object is not an array.\n");
        return ERR_JSON_DECODING;
    }

    len = json_array_size(array);
    if (len == 0) {
        *_data = NULL;
        *_len = 0;
        return EOK;
    }

    data = talloc_zero_array(mem_ctx, krb5_data, len);
    if (data == NULL) {
        return ENOMEM;
    }

    json_array_foreach(array, idx, element) {
        ret = json_element_to_krb5_data(data, element, &data[idx]);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert krb5 data element from JSON");
            talloc_free(data);
            return ret;
        }
    }

    *_data = data;
    *_len = len;
    return EOK;
}

static errno_t json_to_nonempty_princ(TALLOC_CTX *mem_ctx,
                                      json_t *js_princ,
                                      krb5_principal *_princ)
{
    errno_t ret;
    json_t *components = NULL;
    krb5_principal princ = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    char *realm_str;
    size_t realm_size;
    size_t comp_count;
    json_error_t error;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    princ = talloc_zero(tmp_ctx, struct krb5_principal_data);
    if (princ == NULL) {
        return ENOMEM;
    }
    princ->magic = KV5M_PRINCIPAL;

    /* FIXME - it might be cleaner to use the s% specifier here, but the libjansson
     * version on RHEL-7 doesn't support that
     */
    ret = json_unpack_ex(js_princ,
                         &error,
                         JSON_STRICT,
                         "{s:i, s:s, s:o}",
                         "type", &princ->type,
                         "realm", &realm_str,
                         "components", &components);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON princ structure on line %d: %s\n",
              error.line, error.text);
        ret = EINVAL;
        goto done;
    }

    realm_size = strlen(realm_str);
    /* Since the realm should be put into a krb5_data which uses unsigned int
     * to store the length we have to make sure that the realm is not too long
     * since size_t might be bigger than unsigned int. */
    if (realm_size > UINT_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Realm name is too long.\n");
        ret = EINVAL;
        goto done;
    }

    princ->realm.data = talloc_strndup(mem_ctx, realm_str, realm_size);
    if (princ->realm.data == NULL) {
        return ENOMEM;
    }
    princ->realm.length = (unsigned int) realm_size;
    princ->realm.magic = 0;

    /* json_array_to_krb5_data expects size_t* as last argument but the length
     * component of krb5_principal_data is krb5_int32 so it cannot be used
     * directly here because size_t and krb5_int32 might differ in size.
     * Additionally we have to check that the result will fit into the int32
     * range (although we would have other problems if the principal really
     * has more then INT32_MAX components). */
    ret = json_array_to_krb5_data(princ, components,
                                  &princ->data,
                                  &comp_count);
    if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert principal from JSON");
        ret = EINVAL;
        goto done;
    }
    if (comp_count > INT32_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Too many principal components.\n");
        ret = EINVAL;
        goto done;
    }
    princ->length = (krb5_int32) comp_count;

    *_princ = talloc_steal(mem_ctx, princ);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static bool is_nonempty_principal(json_t *js_princ)
{
    errno_t ret;
    json_error_t error;

    ret = json_unpack_ex(js_princ,
                         &error,
                         JSON_VALIDATE_ONLY,
                         "{s:i, s:s, s:o}",
                         "type",
                         "realm",
                         "components");

    return ret == 0 ? true : false;
}

static bool is_empty_principal(json_t *js_princ)
{
    errno_t ret;
    json_error_t error;

    ret = json_unpack_ex(js_princ,
                         &error,
                         JSON_VALIDATE_ONLY,
                         "{}");

    return ret == 0 ? true : false;
}

static errno_t json_to_princ(TALLOC_CTX *mem_ctx,
                             json_t *js_princ,
                             krb5_principal *_princ)
{
    int ok;

    ok = json_is_object(js_princ);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json principal is not an object.\n");
        return ERR_JSON_DECODING;
    }

    if (is_nonempty_principal(js_princ)) {
        return json_to_nonempty_princ(mem_ctx, js_princ, _princ);
    } else if (is_empty_principal(js_princ)) {
        *_princ = NULL;
        return EOK;
    }

    return ERR_JSON_DECODING;
}

static errno_t json_elem_to_cred(TALLOC_CTX *mem_ctx,
                                 json_t *element,
                                 struct kcm_cred **_crd)
{
    errno_t ret;
    char *uuid_str;
    json_error_t error;
    uuid_t uuid;
    struct sss_iobuf *cred_blob;
    const char *base64_cred_blob;
    struct kcm_cred *crd;
    uint8_t *outbuf;
    size_t outbuf_size;
    TALLOC_CTX *tmp_ctx = NULL;

    ret = json_unpack_ex(element,
                         &error,
                         JSON_STRICT,
                         "{s:s, s:s}",
                         "uuid", &uuid_str,
                         "payload", &base64_cred_blob);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON cred structure on line %d: %s\n",
              error.line, error.text);
        return EINVAL;
    }

    uuid_parse(uuid_str, uuid);

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    outbuf = sss_base64_decode(tmp_ctx, base64_cred_blob, &outbuf_size);
    if (outbuf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot decode cred blob\n");
        ret = EIO;
        goto done;
    }

    cred_blob = sss_iobuf_init_readonly(tmp_ctx, outbuf, outbuf_size);
    if (cred_blob == NULL) {
        ret = ENOMEM;
        goto done;
    }

    crd = kcm_cred_new(tmp_ctx, uuid, cred_blob);
    if (crd == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
    *_crd = talloc_steal(mem_ctx, crd);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t json_to_creds(struct kcm_ccache *cc,
                             json_t *jcreds)
{
    errno_t ret;
    int ok;
    size_t idx;
    json_t *value;
    struct kcm_cred *crd;

    ok = json_is_array(jcreds);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json creds object is not an array.\n");
        return ERR_JSON_DECODING;
    }

    json_array_foreach(jcreds, idx, value) {
        ret = json_elem_to_cred(cc, value, &crd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert JSON cred element [%d]: %s\n",
                  ret, sss_strerror(ret));
            return ret;
        }

        ret = kcm_cc_store_creds(cc, crd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot store creds in ccache [%d]: %s\n",
                  ret, sss_strerror(ret));
            return ret;
        }
    }

    return EOK;
}

static errno_t sec_json_value_to_ccache(struct kcm_ccache *cc,
                                        json_t *root)
{
    errno_t ret;
    json_t *princ = NULL;
    json_t *creds = NULL;
    json_error_t error;
    int version;

    ret = json_unpack_ex(root,
                         &error,
                         JSON_STRICT,
                         "{s:i, s:i, s:o, s:o}",
                         "version", &version,
                         "kdc_offset", &cc->kdc_offset,
                         "principal", &princ,
                         "creds", &creds);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON creds structure on line %d: %s\n",
              error.line, error.text);
        return EINVAL;
    }

    if (version != KS_JSON_VERSION) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected version %d, received version %d\n",
              KS_JSON_VERSION, version);
        return EINVAL;
    }

    ret = json_to_princ(cc, princ, &cc->client);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot store JSON to principal [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = json_to_creds(cc, creds);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot store JSON to creds [%d]: %s\n",
              ret, sss_strerror(ret));
        return EOK;
    }

    return EOK;
}

/*
 * sec_key is a concatenation of the ccache's UUID and name
 * sec_value is the JSON dump of the ccache contents
 */
errno_t sec_kv_to_ccache_json(TALLOC_CTX *mem_ctx,
                              const char *sec_key,
                              const char *sec_value,
                              struct cli_creds *client,
                              struct kcm_ccache **_cc)
{
    errno_t ret;
    json_t *root = NULL;
    struct kcm_ccache *cc = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    ret = sec_value_to_json(sec_value, &root);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot store secret to JSON [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cc = talloc_zero(tmp_ctx, struct kcm_ccache);
    if (cc == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = kcm_cc_set_header(cc, sec_key, client);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot store ccache header [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sec_json_value_to_ccache(cc, root);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannt parse secret value [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
    *_cc = talloc_steal(mem_ctx, cc);
done:
    talloc_free(tmp_ctx);
    json_decref(root);
    return ret;
}
