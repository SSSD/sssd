/*
   SSSD - certificate handling utils - OpenSSL version
   The calls defined here should be usable outside of SSSD as well, e.g. in
   libsss_certmap.

   Copyright (C) Sumit Bose <sbose@redhat.com> 2017

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

#include <talloc.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>

#include "util/crypto/sss_crypto.h"
#include "util/cert.h"
#include "lib/certmap/sss_certmap.h"
#include "lib/certmap/sss_certmap_int.h"

#define OID_NTDS_CA_SECURITY_EXT "1.3.6.1.4.1.311.25.2"
#define OID_NTDS_OBJECTSID "1.3.6.1.4.1.311.25.2.1"

typedef struct PrincipalName_st {
    ASN1_INTEGER *name_type;
    STACK_OF(ASN1_GENERALSTRING) *name_string;
} PrincipalName;

ASN1_SEQUENCE(PrincipalName) = {
    ASN1_EXP(PrincipalName, name_type, ASN1_INTEGER, 0),
    ASN1_EXP_SEQUENCE_OF(PrincipalName, name_string, ASN1_GENERALSTRING, 1)
} ASN1_SEQUENCE_END(PrincipalName)

IMPLEMENT_ASN1_FUNCTIONS(PrincipalName)

typedef struct KRB5PrincipalName_st {
    ASN1_STRING *realm;
    PrincipalName *principal_name;
} KRB5PrincipalName;

ASN1_SEQUENCE(KRB5PrincipalName) = {
    ASN1_EXP(KRB5PrincipalName, realm, ASN1_GENERALSTRING, 0),
    ASN1_EXP(KRB5PrincipalName, principal_name, PrincipalName, 1)
} ASN1_SEQUENCE_END(KRB5PrincipalName)

IMPLEMENT_ASN1_FUNCTIONS(KRB5PrincipalName)

/* Microsoft's CA Security Extension as described in section 2.2.2.7.7.4 of
 * [MS-WCCE]: Windows Client Certificate Enrollment Protocol
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71
 */
typedef struct NTDS_OBJECTSID_st {
    ASN1_OBJECT *type_id;
    ASN1_OCTET_STRING *value;
} NTDS_OBJECTSID;

ASN1_SEQUENCE(NTDS_OBJECTSID) = {
    ASN1_SIMPLE(NTDS_OBJECTSID, type_id, ASN1_OBJECT),
    ASN1_EXP(NTDS_OBJECTSID, value, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(NTDS_OBJECTSID)

IMPLEMENT_ASN1_FUNCTIONS(NTDS_OBJECTSID)

typedef struct NTDS_CA_SECURITY_EXT_st {
#define NTDS_CA_SECURITY_EXT_OBJECTSID 0
    int type;
    union {
        NTDS_OBJECTSID *sid;
    } d;
} NTDS_CA_SECURITY_EXT;

ASN1_CHOICE(NTDS_CA_SECURITY_EXT) = {
    ASN1_IMP(NTDS_CA_SECURITY_EXT, d.sid, NTDS_OBJECTSID, NTDS_CA_SECURITY_EXT_OBJECTSID)
} ASN1_CHOICE_END(NTDS_CA_SECURITY_EXT)

IMPLEMENT_ASN1_FUNCTIONS(NTDS_CA_SECURITY_EXT)

typedef STACK_OF(NTDS_CA_SECURITY_EXT) NTDS_CA_SECURITY_EXTS;

ASN1_ITEM_TEMPLATE(NTDS_CA_SECURITY_EXTS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, SecExts, NTDS_CA_SECURITY_EXT)
ASN1_ITEM_TEMPLATE_END(NTDS_CA_SECURITY_EXTS)

IMPLEMENT_ASN1_FUNCTIONS(NTDS_CA_SECURITY_EXTS)

enum san_opt openssl_name_type_to_san_opt(int type)
{
    switch (type) {
    case GEN_OTHERNAME:
        return SAN_OTHER_NAME;
    case GEN_EMAIL:
        return SAN_RFC822_NAME;
    case GEN_DNS:
        return SAN_DNS_NAME;
    case GEN_X400:
        return SAN_X400_ADDRESS;
    case GEN_DIRNAME:
        return SAN_DIRECTORY_NAME;
    case GEN_EDIPARTY:
        return SAN_EDIPART_NAME;
    case GEN_URI:
        return SAN_URI;
    case GEN_IPADD:
        return SAN_IP_ADDRESS;
    case GEN_RID:
        return SAN_REGISTERED_ID;
    default:
        return SAN_INVALID;
    }
}

static int add_string_other_name_to_san_list(TALLOC_CTX *mem_ctx,
                                             enum san_opt san_opt,
                                             OTHERNAME *other_name,
                                             struct san_list **item)
{
    struct san_list *i = NULL;
    int ret;
    char oid_buf[128]; /* FIXME: any other size ?? */
    int len;
    unsigned char *p;

    len = OBJ_obj2txt(oid_buf, sizeof(oid_buf), other_name->type_id, 1);
    if (len <= 0) {
        return EINVAL;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    i->other_name_oid = talloc_strndup(i, oid_buf, len);
    if (i->other_name_oid == NULL) {
        ret = ENOMEM;
        goto done;
    }

    len = i2d_ASN1_TYPE(other_name->value, NULL);
    if (len <= 0) {
        ret = EINVAL;
        goto done;
    }

    i->bin_val = talloc_size(mem_ctx, len);
    if (i->bin_val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* i2d_TYPE increment the second argument so that it points to the end of
     * the written data hence we cannot use i->bin_val directly. */
    p = i->bin_val;
    i->bin_val_len = i2d_ASN1_TYPE(other_name->value, &p);

    ret = 0;

done:
    if (ret == 0) {
        *item = i;
    } else {
        talloc_free(i);
    }

    return ret;
}

static int add_nt_princ_to_san_list(TALLOC_CTX *mem_ctx,
                                    enum san_opt san_opt,
                                    GENERAL_NAME *current,
                                    struct san_list **item)
{
    struct san_list *i = NULL;
    int ret;
    OTHERNAME *other_name = current->d.otherName;

    if (ASN1_TYPE_get(other_name->value) != V_ASN1_UTF8STRING) {
        return EINVAL;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    i->val = talloc_strndup(i,
                 (const char *) ASN1_STRING_get0_data(
                                           other_name->value->value.utf8string),
                 ASN1_STRING_length(other_name->value->value.utf8string));
    if (i->val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = get_short_name(i, i->val, '@', &(i->short_name));
    if (ret != 0) {
        goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
        *item = i;
    } else {
        talloc_free(i);
    }

    return ret;
}

void *ASN1_TYPE_unpack_sequence(const ASN1_ITEM *it, const ASN1_TYPE *t)
{
    if (t == NULL || t->type != V_ASN1_SEQUENCE || t->value.sequence == NULL)
        return NULL;
    return ASN1_item_unpack(t->value.sequence, it);
}

static int add_pkinit_princ_to_san_list(TALLOC_CTX *mem_ctx,
                                        enum san_opt san_opt,
                                        GENERAL_NAME *current,
                                        struct san_list **item)
{
    struct san_list *i = NULL;
    int ret;
    KRB5PrincipalName *princ = NULL;
    size_t c;
    const unsigned char *p;
    const ASN1_STRING *oct;
    ASN1_GENERALSTRING *name_comp;

    oct = current->d.otherName->value->value.sequence;
    p = oct->data;
    princ = d2i_KRB5PrincipalName(NULL, &p, oct->length);
    if (princ == NULL) {
        return EINVAL;
    }

    if (princ->realm == NULL
            || princ->principal_name == NULL
            || princ->principal_name->name_string == NULL
            || sk_ASN1_GENERALSTRING_num(princ->principal_name->name_string)
                                                                         == 0) {
        ret = EINVAL;
        goto done;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        ret = ENOMEM;
        goto done;
    }
    i->san_opt = san_opt;

    i->val = talloc_strdup(i, "");
    if (i->val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (c = 0;
         c < sk_ASN1_GENERALSTRING_num(princ->principal_name->name_string);
         c++) {

        if (c > 0) {
            i->val = talloc_strdup_append(i->val, "/");
            if (i->val == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }

        name_comp = sk_ASN1_GENERALSTRING_value(
                                         princ->principal_name->name_string, c);
        i->val = talloc_strndup_append(i->val,
                                (const char *) ASN1_STRING_get0_data(name_comp),
                                ASN1_STRING_length(name_comp));
        if (i->val == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    i->val = talloc_asprintf_append(i->val, "@%.*s",
                                    ASN1_STRING_length(princ->realm),
                                    ASN1_STRING_get0_data(princ->realm));
    if (i->val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = get_short_name(i, i->val, '@', &(i->short_name));
    if (ret != 0) {
        goto done;
    }

    ret = 0;

done:
    KRB5PrincipalName_free(princ);
    if (ret == 0) {
        *item = i;
    } else {
        talloc_free(i);
    }

    return ret;
}

static int add_ip_to_san_list(TALLOC_CTX *mem_ctx, enum san_opt san_opt,
                              const uint8_t *data, size_t len,
                              struct san_list **item)
{
    struct san_list *i = NULL;

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    i->val = talloc_strndup(i, (const char *) data, len);
    if (i->val == NULL) {
        talloc_free(i);
        return ENOMEM;
    }

    *item = i;
    return 0;
}

static int get_rdn_list(TALLOC_CTX *mem_ctx, X509_NAME *name,
                        const char ***rdn_list)
{
    int ret;
    size_t c;
    const char **list = NULL;
    X509_NAME_ENTRY *e;
    ASN1_STRING *rdn_str;
    ASN1_OBJECT *rdn_name;
    BIO *bio_mem = NULL;
    char *tmp_str;
    long tmp_str_size;

    int nid;
    const char *sn;

    bio_mem = BIO_new(BIO_s_mem());
    if (bio_mem == NULL) {
        ret = ENOMEM;
        goto done;
    }

    list = talloc_zero_array(mem_ctx, const char *,
                             X509_NAME_entry_count(name) + 1);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; c < X509_NAME_entry_count(name); c++) {
        e = X509_NAME_get_entry(name, c);
        rdn_str = X509_NAME_ENTRY_get_data(e);

        ret = ASN1_STRING_print_ex(bio_mem, rdn_str, ASN1_STRFLGS_RFC2253);
        if (ret < 0) {
            ret = EIO;
            goto done;
        }

        tmp_str_size = BIO_get_mem_data(bio_mem, &tmp_str);
        if (tmp_str_size == 0) {
            ret = EINVAL;
            goto done;
        }

        rdn_name = X509_NAME_ENTRY_get_object(e);
        nid = OBJ_obj2nid(rdn_name);
        sn = OBJ_nid2sn(nid);

        list[c] = talloc_asprintf(list, "%s=%.*s", openssl_2_nss_attr_name(sn),
                                                   (int) tmp_str_size, tmp_str);
        ret = BIO_reset(bio_mem);
        if (ret != 1) {
            /* BIO_reset() for BIO_s_mem returns 1 for sucess */
            ret = ENOMEM;
            goto done;
        }
        if (list[c] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = 0;

done:
    BIO_free_all(bio_mem);
    if (ret == 0) {
        *rdn_list = list;
    } else {
        talloc_free(list);
    }

    return ret;
}

static int add_rdn_list_to_san_list(TALLOC_CTX *mem_ctx,
                                    enum san_opt san_opt,
                                    X509_NAME *name,
                                    struct san_list **item)
{
    struct san_list *i = NULL;
    int ret;

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    ret = get_rdn_list(i, name, &(i->rdn_list));
    if (ret != 0) {
        talloc_free(i);
        return ret;
    }

    *item = i;
    return 0;
}

static int add_oid_to_san_list(TALLOC_CTX *mem_ctx,
                               enum san_opt san_opt,
                               ASN1_OBJECT *oid,
                               struct san_list **item)
{
    struct san_list *i = NULL;
    char oid_buf[128]; /* FIXME: any other size ?? */
    int len;

    len = OBJ_obj2txt(oid_buf, sizeof(oid_buf), oid, 1);
    if (len <= 0) {
        return EINVAL;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    i->val = talloc_strndup(i, oid_buf, len);
    if (i->val == NULL) {
        talloc_free(i);
        return ENOMEM;
    }

    *item = i;
    return 0;
}

/* Due to CVE-2023-0286 the type of the x400Address member of the
 * GENERAL_NAME struct was changed from ASN1_TYPE to ASN1_STRING. The
 * following code tries to make sure that the x400Address can be extracted from
 * the certificate in either case. */
static int get_x400address_data(TALLOC_CTX *mem_ctx, GENERAL_NAME *current,
                                unsigned char **_data, int *_len)
{
    int ret;
    unsigned char *data = NULL;
    int len;

#ifdef HAVE_X400ADDRESS_STRING
    len = ASN1_STRING_length(current->d.x400Address);
    if (len <= 0) {
        ret = EINVAL;
        goto done;
    }

    data = (unsigned char *) talloc_strndup(mem_ctx,
                   (const char *) ASN1_STRING_get0_data(current->d.x400Address),
                   len);
    if (data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* just make sure we have the right length in case the original
     * x400Address contained some unexpected \0-bytes. */
    len = strlen((char *) data);
#else
    unsigned char *p;

    len = i2d_ASN1_TYPE(current->d.x400Address, NULL);

    if (len <= 0) {
        ret = EINVAL;
        goto done;
    }

    data = talloc_size(mem_ctx, len);
    if (data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* i2d_ASN1_TYPE increment the second argument so that it points to the end
     * of the written data hence we cannot use data directly. */
    p = data;
    len = i2d_ASN1_TYPE(current->d.x400Address, &p);
#endif

    ret = 0;

done:
    if (ret == 0) {
        if (_data != NULL) {
            *_data = data;
        }
        if (_len != NULL) {
            *_len = len;
        }
    } else {
        talloc_free(data);
    }

    return ret;
}
static int get_san(TALLOC_CTX *mem_ctx, X509 *cert, struct san_list **san_list)
{
    STACK_OF(GENERAL_NAME) *extsan = NULL;
    GENERAL_NAME *current;
    size_t c;
    int ret;
    int crit;
    struct san_list *list = NULL;
    struct san_list *item = NULL;
    struct san_list *item_s = NULL;
    struct san_list *item_p = NULL;
    struct san_list *item_pb = NULL;
    int len;
    unsigned char *data;
    unsigned char *p;

    extsan = X509_get_ext_d2i(cert, NID_subject_alt_name, &crit, NULL);
    if (extsan == NULL) {
        if (crit == -1) { /* extension could not be found */
            return EOK;
        } else {
            return EINVAL;
        }
    }

    for (c = 0; c < sk_GENERAL_NAME_num(extsan); c++) {
        current = sk_GENERAL_NAME_value(extsan, c);
        switch (current->type) {
        case GEN_OTHERNAME:
            ret = add_string_other_name_to_san_list(mem_ctx,
                                                    SAN_STRING_OTHER_NAME,
                                                    current->d.otherName,
                                                    &item_s);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item_s);

            item_p = NULL;
            if (strcmp(item_s->other_name_oid, NT_PRINCIPAL_OID) == 0) {
                ret = add_nt_princ_to_san_list(mem_ctx, SAN_NT, current,
                                               &item_p);
                if (ret != 0) {
                    goto done;
                }
                DLIST_ADD(list, item_p);
            } else if (strcmp(item_s->other_name_oid, PKINIT_OID) == 0) {
                ret = add_pkinit_princ_to_san_list(mem_ctx, SAN_PKINIT,
                                                   current, &item_p);
                if (ret != 0) {
                    goto done;
                }
                DLIST_ADD(list, item_p);
            }

            if (item_p != NULL) {
                ret = add_principal_to_san_list(mem_ctx, SAN_PRINCIPAL,
                                                item_p->val, &item_pb);
                if (ret != 0) {
                    goto done;
                }
                DLIST_ADD(list, item_pb);
            }

            break;
        case GEN_EMAIL:
            ret = add_to_san_list(mem_ctx, false,
                                  openssl_name_type_to_san_opt(current->type),
                                  ASN1_STRING_get0_data(current->d.rfc822Name),
                                  ASN1_STRING_length(current->d.rfc822Name),
                                  &item);
            if (ret != 0) {
                goto done;
            }

            ret = get_short_name(item, item->val, '@', &(item->short_name));
            if (ret != 0) {
                goto done;
            }

            DLIST_ADD(list, item);
            break;
        case GEN_DNS:
            ret = add_to_san_list(mem_ctx, false,
                                  openssl_name_type_to_san_opt(current->type),
                                  ASN1_STRING_get0_data(current->d.dNSName),
                                  ASN1_STRING_length(current->d.dNSName),
                                  &item);
            if (ret != 0) {
                goto done;
            }

            ret = get_short_name(item, item->val, '.', &(item->short_name));
            if (ret != 0) {
                goto done;
            }

            DLIST_ADD(list, item);
            break;
        case GEN_URI:
            ret = add_to_san_list(mem_ctx, false,
                    openssl_name_type_to_san_opt(current->type),
                    ASN1_STRING_get0_data(current->d.uniformResourceIdentifier),
                    ASN1_STRING_length(current->d.uniformResourceIdentifier),
                    &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        case GEN_IPADD:
            ret = add_ip_to_san_list(mem_ctx,
                                    openssl_name_type_to_san_opt(current->type),
                                    ASN1_STRING_get0_data(current->d.iPAddress),
                                    ASN1_STRING_length(current->d.iPAddress),
                                    &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        case GEN_DIRNAME:
            ret = add_rdn_list_to_san_list(mem_ctx,
                                    openssl_name_type_to_san_opt(current->type),
                                    current->d.directoryName, &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        case GEN_RID:
            ret = add_oid_to_san_list(mem_ctx,
                                    openssl_name_type_to_san_opt(current->type),
                                    current->d.registeredID, &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        case GEN_X400:
            ret = get_x400address_data(mem_ctx, current, &data, &len);
            if (ret != 0) {
                goto done;
            }

            ret = add_to_san_list(mem_ctx, true,
                                  openssl_name_type_to_san_opt(current->type),
                                  data, len, &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        case GEN_EDIPARTY:
            len = i2d_EDIPARTYNAME(current->d.ediPartyName, NULL);
            if (len <= 0) {
                ret = EINVAL;
                goto done;
            }

            data = talloc_size(mem_ctx, len);
            if (data == NULL) {
                ret = ENOMEM;
                goto done;
            }

            /* i2d_EDIPARTYNAME increment the second argument so that it points
             * to the end of the written data hence we cannot use data directly.
             */
            p = data;
            len = i2d_EDIPARTYNAME(current->d.ediPartyName, &p);

            ret = add_to_san_list(mem_ctx, true,
                                  openssl_name_type_to_san_opt(current->type),
                                  data, len, &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        default:
            ret = EINVAL;
            goto done;
        }
    }

    ret = EOK;

done:
    GENERAL_NAMES_free(extsan);

    if (ret == EOK) {
        *san_list = list;
    }

    return ret;
}

static int get_sid_ext(TALLOC_CTX *mem_ctx, X509 *cert, const char **_sid)
{
    int ret;
    ASN1_OBJECT *sid_ext_oid = NULL;
    ASN1_OBJECT *sid_oid = NULL;
    int idx;
    X509_EXTENSION *ext = NULL;
    const unsigned char *p;
    NTDS_CA_SECURITY_EXTS *sec_exts = NULL;
    NTDS_CA_SECURITY_EXT *current;
    char *sid = NULL;
    const ASN1_OCTET_STRING *ext_data = NULL;
    size_t c;

    sid_ext_oid = OBJ_txt2obj(OID_NTDS_CA_SECURITY_EXT, 1);
    if (sid_ext_oid == NULL) {
        return EIO;
    }

    idx = X509_get_ext_by_OBJ(cert, sid_ext_oid, -1);
    ASN1_OBJECT_free(sid_ext_oid);
    if (idx == -1) {
        /* Extension most probably not available, no error. */
        return 0;
    }

    ext = X509_get_ext(cert, idx);
    if (ext == NULL) {
        return EINVAL;
    }

    ext_data = X509_EXTENSION_get_data(ext);
    if (ext_data == NULL) {
        return EINVAL;
    }

    p = ext_data->data;
    sec_exts = d2i_NTDS_CA_SECURITY_EXTS(NULL, &p, ext_data->length);
    if (sec_exts == NULL) {
        return EIO;
    }

    ret = EINVAL;
    for (c = 0; c < OPENSSL_sk_num((const OPENSSL_STACK *) sec_exts); c++) {
        current = (NTDS_CA_SECURITY_EXT *)
                          OPENSSL_sk_value((const OPENSSL_STACK *) sec_exts, c);
        /* Only handle NTDS_CA_SECURITY_EXT_OBJECTSID. So far no other types
         * are defined. */
        if (current->type == NTDS_CA_SECURITY_EXT_OBJECTSID) {
            if (sid != NULL) {
                /* second SID found, currently not expected */
                talloc_free(sid);
                ret = EINVAL;
                goto done;
            }

            sid_oid = OBJ_txt2obj(OID_NTDS_OBJECTSID, 1);
            if (sid_oid == NULL) {
                ret = EIO;
                goto done;
            }
            if (current->d.sid->type_id == NULL
                    || OBJ_cmp(current->d.sid->type_id, sid_oid) != 0) {
                /* Unexpected OID */
                ret = EINVAL;
                goto done;
            }

            sid = talloc_strndup(mem_ctx, (char *) current->d.sid->value->data,
                                          current->d.sid->value->length);
            if (sid == NULL) {
                ret = ENOMEM;
                goto done;
            }
            ret = 0;
        }
    }

done:
    NTDS_CA_SECURITY_EXTS_free(sec_exts);
    ASN1_OBJECT_free(sid_oid);

    if (ret == 0) {
        *_sid = sid;
    }
    return ret;
}

static int get_extended_key_usage_oids(TALLOC_CTX *mem_ctx,
                                       X509 *cert,
                                       const char ***_oids)
{
    const char **oids_list = NULL;
    size_t c;
    int ret;
    char oid_buf[128]; /* FIXME: any other size ?? */
    int len;
    EXTENDED_KEY_USAGE *extusage = NULL;
    int crit;
    size_t eku_count = 0;

    extusage = X509_get_ext_d2i(cert, NID_ext_key_usage, &crit, NULL);
    if (extusage == NULL) {
        if (crit == -1) { /* extension could not be found */
            eku_count = 0;
        } else {
            return EINVAL;
        }
    } else {
        eku_count = sk_ASN1_OBJECT_num(extusage);
    }

    oids_list = talloc_zero_array(mem_ctx, const char *, eku_count + 1);
    if (oids_list == NULL) {
        return ENOMEM;
    }

    for (c = 0; c < eku_count; c++) {
        len = OBJ_obj2txt(oid_buf, sizeof(oid_buf),
                          sk_ASN1_OBJECT_value(extusage, c), 1);
        if (len < 0) {
            return EIO;
        }

        oids_list[c] = talloc_strndup(oids_list, oid_buf, len);
        if (oids_list[c] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = 0;

done:
    sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
    if (ret == 0) {
        *_oids = oids_list;
    } else {
        talloc_free(oids_list);
    }

    return ret;
}

static int get_serial_number(TALLOC_CTX *mem_ctx, X509 *cert,
                             uint8_t **serial_number,
                             size_t *serial_number_size,
                             const char **serial_number_dec_str)
{
    const ASN1_INTEGER *serial;
    BIGNUM *bn = NULL;
    size_t size;
    uint8_t *buf = NULL;
    int ret;
    char *tmp_str = NULL;

    serial = X509_get0_serialNumber(cert);
    bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn == NULL) {
        *serial_number_size = 0;
        *serial_number = NULL;
        *serial_number_dec_str = NULL;
        return 0;
    }

    /* The serial number MUST be a positive integer. */
    if (BN_is_zero(bn) || BN_is_negative(bn)) {
        ret = EINVAL;
        goto done;
    }

    size = BN_num_bytes(bn);
    if (size == 0) {
        ret = EINVAL;
        goto done;
    }

    tmp_str = BN_bn2dec(bn);
    if (tmp_str == NULL) {
        ret = EIO;
        goto done;
    }

    buf = talloc_size(mem_ctx, size);
    if (buf == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = BN_bn2bin(bn, buf);
    if (ret != size) {
        ret = EIO;
        goto done;
    }

    *serial_number_dec_str = talloc_strdup(mem_ctx, tmp_str);
    if (*serial_number_dec_str == NULL) {
        ret = ENOMEM;
        goto done;
    }
    *serial_number = buf;
    *serial_number_size = size;

    ret =  0;

done:
    if (ret != 0) {
        talloc_free(buf);
    }
    BN_free(bn);
    OPENSSL_free(tmp_str);

    return ret;
}

static int get_subject_key_id(TALLOC_CTX *mem_ctx, X509 *cert,
                              uint8_t **subject_key_id,
                              size_t *subject_key_id_size)
{
    const ASN1_OCTET_STRING *ski;
    size_t size = 0;
    uint8_t *buf;

    ski = X509_get0_subject_key_id(cert);
    if (ski != NULL) {
        size = ASN1_STRING_length(ski);
    }
    if (size == 0) {
        *subject_key_id_size = 0;
        *subject_key_id = NULL;
        return 0;
    }

    buf = talloc_memdup(mem_ctx, ASN1_STRING_get0_data(ski), size);
    if (buf == NULL) {
        return ENOMEM;
    }

    *subject_key_id = buf;
    *subject_key_id_size = size;

    return 0;
}

int sss_cert_get_content(TALLOC_CTX *mem_ctx,
                         const uint8_t *der_blob, size_t der_size,
                         struct sss_cert_content **content)
{
    int ret;
    struct sss_cert_content *cont = NULL;
    X509 *cert = NULL;
    const unsigned char *der;
    BIO *bio_mem = NULL;
    X509_NAME *tmp_name;

    if (der_blob == NULL || der_size == 0) {
        return EINVAL;
    }

    cont = talloc_zero(mem_ctx, struct sss_cert_content);
    if (cont == NULL) {
        return ENOMEM;
    }

    bio_mem = BIO_new(BIO_s_mem());
    if (bio_mem == NULL) {
        ret = ENOMEM;
        goto done;
    }

    der = (const unsigned char *) der_blob;
    cert = d2i_X509(NULL, &der, (int) der_size);
    if (cert == NULL) {
        ret = EINVAL;
        goto done;
    }

    tmp_name = X509_get_issuer_name(cert);

    ret = get_rdn_list(cont, tmp_name, &cont->issuer_rdn_list);
    if (ret != 0) {
        goto done;
    }

    ret = rdn_list_2_dn_str(cont, NULL, cont->issuer_rdn_list,
                            &cont->issuer_str);
    if (ret != 0) {
        goto done;
    }

    tmp_name = X509_get_subject_name(cert);

    ret = get_rdn_list(cont, tmp_name, &cont->subject_rdn_list);
    if (ret != 0) {
        goto done;
    }

    ret = rdn_list_2_dn_str(cont, NULL, cont->subject_rdn_list,
                            &cont->subject_str);
    if (ret != 0) {
        goto done;
    }

    ret = X509_check_purpose(cert, -1, -1);
    if (ret < 0) {
        ret = EIO;
        goto done;
    }
    if ((X509_get_extension_flags(cert) & EXFLAG_KUSAGE)) {
        cont->key_usage = X509_get_key_usage(cert);
    } else {
        /* According to X.509 https://www.itu.int/rec/T-REC-X.509-201610-I
         * section 13.3.2 "Certificate match" "keyUsage matches if all of the
         * bits set in the presented value are also set in the key usage
         * extension in the stored attribute value, or if there is no key
         * usage extension in the stored attribute value;". So we set all bits
         * in our key_usage to make sure everything matches is keyUsage is not
         * set in the certificate.
         *
         * Please note that NSS currently
         * (https://bugzilla.mozilla.org/show_bug.cgi?id=549952) does not
         * support 'decipherOnly' and will only use 0xff in this case. To have
         * a consistent behavior with both libraries we will use UINT32_MAX
         * for NSS as well. Since comparisons should be always done with a
         * bit-wise and-operation the difference should not matter. */
        cont->key_usage = UINT32_MAX;
    }

    ret = get_extended_key_usage_oids(cont, cert,
                                      &(cont->extended_key_usage_oids));
    if (ret != 0) {
        goto done;
    }

    ret = get_san(cont, cert, &(cont->san_list));
    if (ret != 0) {
        goto done;
    }

    ret = get_serial_number(cont, cert, &(cont->serial_number),
                            &(cont->serial_number_size),
                            &(cont->serial_number_dec_str));
    if (ret != 0) {
        goto done;
    }

    ret = get_subject_key_id(cont, cert, &(cont->subject_key_id),
                             &(cont->subject_key_id_size));
    if (ret != 0) {
        goto done;
    }

    ret = get_sid_ext(cont, cert, &(cont->sid_ext));
    if (ret != 0) {
        goto done;
    }

    cont->cert_der = talloc_memdup(cont, der_blob, der_size);
    if (cont->cert_der == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cont->cert_der_size = der_size;

    ret = EOK;

done:

    X509_free(cert);
    BIO_free_all(bio_mem);
    CRYPTO_cleanup_all_ex_data();

    if (ret == EOK) {
        *content = cont;
    } else {
        talloc_free(cont);
    }

    return ret;
}
