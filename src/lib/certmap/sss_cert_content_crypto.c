/*
   SSSD - certificate handling utils - OpenSSL version
   The calls defined here should be useable outside of SSSD as well, e.g. in
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

/* backward compatible macros for OpenSSL < 1.1 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define ASN1_STRING_get0_data(o) ASN1_STRING_data(o)
#define X509_get_extension_flags(o) ((o)->ex_flags)
#define X509_get_key_usage(o) ((o)->ex_kusage)
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

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

            /* i2d_TYPE increment the second argument so that it points to the end of
             * the written data hence we cannot use i->bin_val directly. */
            p = data;
            len = i2d_ASN1_TYPE(current->d.x400Address, &p);

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

            /* i2d_TYPE increment the second argument so that it points to the end of
             * the written data hence we cannot use i->bin_val directly. */
            p = data;
            len = i2d_EDIPARTYNAME(current->d.ediPartyName, &data);

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
    if (!(X509_get_extension_flags(cert) & EXFLAG_KUSAGE)) {
        ret = EINVAL;
        goto done;
    }
    cont->key_usage = X509_get_key_usage(cert);

    ret = get_extended_key_usage_oids(cont, cert,
                                      &(cont->extended_key_usage_oids));
    if (ret != 0) {
        goto done;
    }

    ret = get_san(cont, cert, &(cont->san_list));
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
