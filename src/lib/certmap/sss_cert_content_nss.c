/*
   SSSD - certificate handling utils - NSS version
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

#include <nss.h>
#include <cert.h>
#include <base64.h>
#include <prerror.h>
#include <secport.h>
#include <secerr.h>
#include <prprf.h>
#include <prnetdb.h>
#include <talloc.h>

#include "util/crypto/sss_crypto.h"
#include "util/crypto/nss/nss_util.h"
#include "util/cert.h"
#include "lib/certmap/sss_certmap.h"
#include "lib/certmap/sss_certmap_int.h"


/* The following two functions are copied from NSS's lib/certdb/secname.c
 * because CERT_AddAVA is not exported. I just renamed it and made it static
 * to avoid issues if the call gets exported some time in future. */

static void **
AddToArray(PLArenaPool *arena, void **array, void *element)
{
    unsigned count;
    void **ap;

    /* Count up number of slots already in use in the array */
    count = 0;
    ap = array;
    if (ap) {
        while (*ap++) {
            count++;
        }
    }

    if (array) {
        array = (void**) PORT_ArenaGrow(arena, array,
                                        (count + 1) * sizeof(void *),
                                        (count + 2) * sizeof(void *));
    } else {
        array = (void**) PORT_ArenaAlloc(arena, (count + 2) * sizeof(void *));
    }
    if (array) {
        array[count] = element;
        array[count+1] = 0;
    }
    return array;
}


static SECStatus
sss_CERT_AddAVA(PLArenaPool *arena, CERTRDN *rdn, CERTAVA *ava)
{
    rdn->avas = (CERTAVA**) AddToArray(arena, (void**) rdn->avas, ava);
    return rdn->avas ? SECSuccess : SECFailure;
}

static SECItem *
cert_get_ext_by_tag(CERTCertificate *cert, SECOidTag tag)
{
    SECOidData *oid;
    int i;

    oid = SECOID_FindOIDByTag(tag);
    for (i = 0;
         (cert->extensions != NULL) && (cert->extensions[i] != NULL);
         i++)
        if (SECITEM_ItemsAreEqual(&cert->extensions[i]->id, &oid->oid))
            return &cert->extensions[i]->value;
    return NULL;
}

static int get_extended_key_usage_oids(TALLOC_CTX *mem_ctx,
                                       CERTCertificate *cert,
                                       const char ***_oids)
{
    PLArenaPool *pool;
    SECItem *ext;
    SECItem **oids = NULL;
    const char **oids_list = NULL;
    size_t c;
    SECStatus rv;
    char *tmp_str;
    int ret;

    pool = PORT_NewArena(sizeof(double));
    ext = cert_get_ext_by_tag(cert, SEC_OID_X509_EXT_KEY_USAGE);
    if (ext != NULL) {
        rv = SEC_ASN1DecodeItem(pool, &oids,
                                SEC_ASN1_GET(SEC_SequenceOfObjectIDTemplate),
                                ext);
        if (rv != SECSuccess) {
            ret = EINVAL;
            goto done;
        }
    }

    for (c = 0; (oids != NULL && oids[c] != NULL); c++);
    oids_list = talloc_zero_array(mem_ctx, const char *, c + 1);
    if (oids_list == NULL) {
        return ENOMEM;
    }

    for (c = 0; (oids != NULL && oids[c] != NULL); c++) {
        tmp_str = CERT_GetOidString(oids[c]);
        /* it is expected that NSS OID strings start with "OID." but we
         * prefer the plain dotted-decimal version so the prefix is skipped */
        if (tmp_str == NULL || strncmp(tmp_str, "OID.", 4) != 0) {
            PR_smprintf_free(tmp_str);
            ret = EINVAL;
            goto done;
        }

        oids_list[c] = talloc_strdup(oids_list, tmp_str + 4);
        PR_smprintf_free(tmp_str);
        if(oids_list[c] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = 0;

done:
    PORT_FreeArena(pool, PR_TRUE);
    if (ret == 0) {
        *_oids = oids_list;
    } else {
        talloc_free(oids_list);
    }

    return ret;

}

static int get_rdn_str(TALLOC_CTX *mem_ctx, CERTAVA **avas,
                       const char **rdn_str)
{
    size_t c;
    char *tmp_name = NULL;
    const char *tmp_str = NULL;
    int ret;
    SECStatus rv;
    CERTRDN rdn = { 0 };
    CERTName *name = NULL;
    PLArenaPool *arena = NULL;

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        ret = ENOMEM;
        goto done;
    }


    /* Multiple AVAs should be avoided because there is no general ordering
     * rule and the RDN strings are not reproducible */
    for (c = 0; avas[c] != NULL; c++) {
        rv = sss_CERT_AddAVA(arena, &rdn, avas[c]);
        if (rv != SECSuccess) {
            ret = EIO;
            goto done;
        }
    }

    name = CERT_CreateName(&rdn, NULL);
    if (name == NULL) {
        ret = EIO;
        goto done;
    }

    tmp_name = CERT_NameToAscii(name);
    CERT_DestroyName(name);
    if (tmp_name == NULL) {
        ret = EIO;
        goto done;
    }

    tmp_str = talloc_strdup(mem_ctx, tmp_name);
    PORT_Free(tmp_name);
    if (tmp_str == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
        *rdn_str = tmp_str;
    } else {
        talloc_free(discard_const(tmp_str));
    }
    PORT_FreeArena(arena, PR_FALSE);

    return ret;
}

static int get_rdn_list(TALLOC_CTX *mem_ctx, CERTRDN **rdns,
                        const char ***rdn_list)
{
    int ret;
    size_t c;
    const char **list = NULL;

    for (c = 0; rdns[c] != NULL; c++);
    list = talloc_zero_array(mem_ctx, const char *, c + 1);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }
    for (c = 0; rdns[c] != NULL; c++) {
        ret = get_rdn_str(list, rdns[c]->avas,
                          &(list[c]));
        if (ret != 0) {
            goto done;
        }
    }

    ret = 0;

done:
    if (ret == 0) {
        *rdn_list = list;
    } else {
        talloc_free(list);
    }

    return ret;
}

enum san_opt nss_name_type_to_san_opt(CERTGeneralNameType type)
{
    switch (type) {
    case certOtherName:
        return SAN_OTHER_NAME;
    case certRFC822Name:
        return SAN_RFC822_NAME;
    case certDNSName:
        return SAN_DNS_NAME;
    case certX400Address:
        return SAN_X400_ADDRESS;
    case certDirectoryName:
        return SAN_DIRECTORY_NAME;
    case certEDIPartyName:
        return SAN_EDIPART_NAME;
    case certURI:
        return SAN_URI;
    case certIPAddress:
        return SAN_IP_ADDRESS;
    case certRegisterID:
        return SAN_REGISTERED_ID;
    default:
        return SAN_INVALID;
    }
}

/* taken from pkinit_crypto_nss.c of MIT Kerberos */
/* KerberosString: RFC 4120, 5.2.1. */
static const SEC_ASN1Template kerberos_string_template[] = {
    {
        SEC_ASN1_GENERAL_STRING,
        0,
        NULL,
        sizeof(SECItem),
    }
};

/* Realm: RFC 4120, 5.2.2. */
struct realm {
    SECItem name;
};
static const SEC_ASN1Template realm_template[] = {
    {
        SEC_ASN1_GENERAL_STRING,
        0,
        NULL,
        sizeof(SECItem),
    }
};

/* PrincipalName: RFC 4120, 5.2.2. */
static const SEC_ASN1Template sequence_of_kerberos_string_template[] = {
    {
        SEC_ASN1_SEQUENCE_OF,
        0,
        &kerberos_string_template,
        0,
    }
};

struct principal_name {
    SECItem name_type;
    SECItem **name_string;
};
static const SEC_ASN1Template principal_name_template[] = {
    {
        SEC_ASN1_SEQUENCE,
        0,
        NULL,
        sizeof(struct principal_name),
    },
    {
        SEC_ASN1_CONTEXT_SPECIFIC | 0 | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT,
        offsetof(struct principal_name, name_type),
        &SEC_IntegerTemplate,
        sizeof(SECItem),
    },
    {
        SEC_ASN1_CONTEXT_SPECIFIC | 1 | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT,
        offsetof(struct principal_name, name_string),
        sequence_of_kerberos_string_template,
        sizeof(struct SECItem **),
    },
    {0, 0, NULL, 0},
};

/* KRB5PrincipalName: RFC 4556, 3.2.2. */
struct kerberos_principal_name {
    SECItem realm;
    struct principal_name principal_name;
};
static const SEC_ASN1Template kerberos_principal_name_template[] = {
    {
        SEC_ASN1_SEQUENCE,
        0,
        NULL,
        sizeof(struct kerberos_principal_name),
    },
    {
        SEC_ASN1_CONTEXT_SPECIFIC | 0 | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT,
        offsetof(struct kerberos_principal_name, realm),
        &realm_template,
        sizeof(struct realm),
    },
    {
        SEC_ASN1_CONTEXT_SPECIFIC | 1 | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT,
        offsetof(struct kerberos_principal_name, principal_name),
        &principal_name_template,
        sizeof(struct principal_name),
    },
    {0, 0, NULL, 0}
};

static int add_string_other_name_to_san_list(TALLOC_CTX *mem_ctx,
                                             enum san_opt san_opt,
                                             CERTGeneralName *current,
                                             struct san_list **item)
{
    struct san_list *i = NULL;
    int ret;
    char *tmp_str;

    tmp_str = CERT_GetOidString(&(current->name.OthName.oid));
    /* it is expected that NSS OID strings start with "OID." but we
     * prefer the plain dotted-decimal version so the prefix is skipped */
    if (tmp_str == NULL || strncmp(tmp_str, "OID.", 4) != 0) {
        PR_smprintf_free(tmp_str);
        return EINVAL;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        PR_smprintf_free(tmp_str);
        return ENOMEM;
    }
    i->san_opt = san_opt;

    i->other_name_oid = talloc_strdup(i, tmp_str + 4);
    PR_smprintf_free(tmp_str);
    if (i->other_name_oid == NULL) {
        ret = ENOMEM;
        goto done;
    }

    i->bin_val = talloc_memdup(i, current->name.OthName.name.data,
                                        current->name.OthName.name.len);
    if (i->bin_val == NULL) {
        ret = ENOMEM;
        goto done;
    }
    i->bin_val_len = current->name.OthName.name.len;

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
                                    PLArenaPool *pool,
                                    enum san_opt san_opt,
                                    CERTGeneralName *current,
                                    struct san_list **item)
{
    struct san_list *i = NULL;
    SECStatus rv;
    SECItem tmp_secitem = { 0 };
    int ret;

    rv = SEC_ASN1DecodeItem(pool, &tmp_secitem,
                            SEC_ASN1_GET(SEC_UTF8StringTemplate),
                            &(current->name.OthName.name));
    if (rv != SECSuccess) {
        return EINVAL;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    i->val = talloc_strndup(i, (char *) tmp_secitem.data,
                                              tmp_secitem.len);
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

static int add_pkinit_princ_to_san_list(TALLOC_CTX *mem_ctx,
                                        PLArenaPool *pool,
                                        enum san_opt san_opt,
                                        CERTGeneralName *current,
                                        struct san_list **item)
{
    struct san_list *i = NULL;
    SECStatus rv;
    /* To avoid 'Wmissing-braces' warnings with older versions of
     * gcc kerberos_principal_name cannot be initialized with { 0 }
     * but must be initialized with memset().
     */
    struct kerberos_principal_name kname;
    int ret;
    size_t c;

    memset(&kname, 0, sizeof(kname));

    rv = SEC_ASN1DecodeItem(pool, &kname,
                            kerberos_principal_name_template,
                            &(current->name.OthName.name));
    if (rv != SECSuccess) {
        return EINVAL;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    if (kname.principal_name.name_string != NULL) {
        i->val = talloc_strdup(i, "");
        if (i->val == NULL) {
            ret = ENOMEM;
            goto done;
        }
        for (c = 0; kname.principal_name.name_string[c] != NULL; c++) {
            if (c > 0) {
                i->val = talloc_strdup_append(i->val, "/");
                if (i->val == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }
            i->val = talloc_strndup_append(i->val,
                         (char *) kname.principal_name.name_string[c]->data,
                          kname.principal_name.name_string[c]->len);
            if (i->val == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
        i->val = talloc_asprintf_append(i->val, "@%.*s",
                                             kname.realm.len,
                                             (char *) kname.realm.data);
        if (i->val == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = get_short_name(i, i->val, '@', &(i->short_name));
        if (ret != 0) {
            goto done;
        }
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

static int add_oid_to_san_list(TALLOC_CTX *mem_ctx,
                               enum san_opt san_opt,
                               SECItem oid,
                               struct san_list **item)
{
    struct san_list *i = NULL;
    char *tmp_str;

    tmp_str = CERT_GetOidString(&oid);
    /* it is expected that NSS OID strings start with "OID." but we
     * prefer the plain dotted-decimal version so the prefix is skipped */
    if (tmp_str == NULL || strncmp(tmp_str, "OID.", 4) != 0) {
        PR_smprintf_free(tmp_str);
        return EINVAL;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        PR_smprintf_free(tmp_str);
        return ENOMEM;
    }
    i->san_opt = san_opt;

    i->val = talloc_strdup(i, tmp_str + 4);
    PR_smprintf_free(tmp_str);
    if (i->val == NULL) {
        talloc_free(i);
        return ENOMEM;
    }

    *item = i;
    return 0;
}

static int add_rdn_list_to_san_list(TALLOC_CTX *mem_ctx,
                                    enum san_opt san_opt,
                                    CERTName name,
                                    struct san_list **item)
{
    struct san_list *i = NULL;
    int ret;

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    ret = get_rdn_list(i, name.rdns, &(i->rdn_list));
    if (ret != 0) {
        talloc_free(i);
        return ret;
    }

    *item = i;
    return 0;
}

static int add_ip_to_san_list(TALLOC_CTX *mem_ctx, enum san_opt san_opt,
                              uint8_t *data, size_t len,
                              struct san_list **item)
{
    struct san_list *i;
    PRStatus   st;
    PRNetAddr  addr;
    char       addrBuf[80];

    if (data == NULL || len == 0 || san_opt == SAN_INVALID) {
        return EINVAL;
    }

    /* taken from secu_PrintIPAddress() */
    memset(&addr, 0, sizeof addr);
    if (len == 4) {
        addr.inet.family = PR_AF_INET;
        memcpy(&addr.inet.ip, data, len);
    } else if (len == 16) {
        addr.ipv6.family = PR_AF_INET6;
        memcpy(addr.ipv6.ip.pr_s6_addr, data, len);
        if (PR_IsNetAddrType(&addr, PR_IpAddrV4Mapped)) {
            /* convert to IPv4.  */
            addr.inet.family = PR_AF_INET;
            memcpy(&addr.inet.ip, &addr.ipv6.ip.pr_s6_addr[12], 4);
            memset(&addr.inet.pad[0], 0, sizeof addr.inet.pad);
        }
    } else {
        return EINVAL;
    }

    st = PR_NetAddrToString(&addr, addrBuf, sizeof addrBuf);
    if (st != PR_SUCCESS) {
        return EIO;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }

    i->san_opt = san_opt;
    i->val = talloc_strdup(i, addrBuf);
    if (i->val == NULL) {
        talloc_free(i);
        return ENOMEM;
    }

    *item = i;
    return 0;
}

static int get_san(TALLOC_CTX *mem_ctx, CERTCertificate *cert,
                   struct san_list **san_list)
{

    SECItem subAltName = { 0 };
    SECStatus rv;
    CERTGeneralName *name_list = NULL;
    CERTGeneralName *current;
    PLArenaPool *pool = NULL;
    int ret;
    struct san_list *list = NULL;
    struct san_list *item = NULL;
    struct san_list *item_s = NULL;
    struct san_list *item_p = NULL;
    struct san_list *item_pb = NULL;

    rv = CERT_FindCertExtension(cert, SEC_OID_X509_SUBJECT_ALT_NAME,
                                &subAltName);
    if (rv != SECSuccess) {
        if (rv == SECFailure
                && PORT_GetError() == SEC_ERROR_EXTENSION_NOT_FOUND) {
            ret = EOK;
        } else {
            ret = EIO;
        }
        goto done;
    }

    pool = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (pool == NULL) {
        ret = ENOMEM;
        goto done;
    }

    name_list = CERT_DecodeAltNameExtension(pool, &subAltName);
    if (name_list == NULL ) {
        ret = EIO;
        goto done;
    }

    current = name_list;
    do {
        switch (current->type) {
        case certOtherName:
            ret = add_string_other_name_to_san_list(mem_ctx,
                                                    SAN_STRING_OTHER_NAME,
                                                    current, &item_s);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item_s);

            item_p = NULL;
            if (strcmp(item_s->other_name_oid, NT_PRINCIPAL_OID) == 0) {
                ret = add_nt_princ_to_san_list(mem_ctx, pool, SAN_NT, current,
                                               &item_p);
                if (ret != 0) {
                    goto done;
                }
                DLIST_ADD(list, item_p);
            } else if (strcmp(item_s->other_name_oid, PKINIT_OID) == 0) {
                ret = add_pkinit_princ_to_san_list(mem_ctx, pool, SAN_PKINIT,
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
        case certRFC822Name:
        case certDNSName:
        case certURI:
            ret = add_to_san_list(mem_ctx, false,
                                  nss_name_type_to_san_opt(current->type),
                                  current->name.other.data,
                                  current->name.other.len, &item);
            if (ret != 0) {
                goto done;
            }

            if (current->type == certRFC822Name
                    || current->type == certDNSName) {
                ret = get_short_name(item, item->val,
                                     (current->type == certRFC822Name
                                                          ? '@' : '.'),
                                     &(item->short_name));
                if (ret != 0) {
                    goto done;
                }
            }

            DLIST_ADD(list, item);
            break;
        case certIPAddress:
            ret = add_ip_to_san_list(mem_ctx,
                                     nss_name_type_to_san_opt(current->type),
                                     current->name.other.data,
                                     current->name.other.len, &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        case certDirectoryName:
            ret = add_rdn_list_to_san_list(mem_ctx,
                                        nss_name_type_to_san_opt(current->type),
                                        current->name.directoryName, &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        case certRegisterID:
            ret = add_oid_to_san_list(mem_ctx,
                                      nss_name_type_to_san_opt(current->type),
                                      current->name.other, &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        case certX400Address:
        case certEDIPartyName:
            ret = add_to_san_list(mem_ctx, true,
                                  nss_name_type_to_san_opt(current->type),
                                  current->name.other.data,
                                  current->name.other.len, &item);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(list, item);
            break;
        default:
            ret = EINVAL;
            goto done;
        }

        current = CERT_GetNextGeneralName(current);
        if (current == NULL) {
            ret = EIO;
            goto done;
        }
    } while (current != name_list);

done:

    /* Don't free nameList, it's part of the arena. */

    if (pool != NULL) {
        PORT_FreeArena(pool, PR_FALSE);
    }

    if (subAltName.data != NULL) {
        SECITEM_FreeItem(&subAltName, PR_FALSE);
    }

    if (ret == EOK) {
        *san_list = list;
    }
    return ret;
}

int sss_cert_get_content(TALLOC_CTX *mem_ctx,
                         const uint8_t *der_blob, size_t der_size,
                         struct sss_cert_content **content)
{
    int ret;
    struct sss_cert_content *cont = NULL;
    CERTCertDBHandle *handle;
    CERTCertificate *cert = NULL;
    SECItem der_item;
    NSSInitContext *nss_ctx;

    if (der_blob == NULL || der_size == 0) {
        return EINVAL;
    }

    nss_ctx = NSS_InitContext("", "", "", "", NULL, NSS_INIT_READONLY
                                                    |  NSS_INIT_NOCERTDB
                                                    | NSS_INIT_NOMODDB
                                                    | NSS_INIT_FORCEOPEN
                                                    | NSS_INIT_NOROOTINIT
                                                    |  NSS_INIT_OPTIMIZESPACE);
    if (nss_ctx == NULL) {
        return EIO;
    }

    cont = talloc_zero(mem_ctx, struct sss_cert_content);
    if (cont == NULL) {
        return ENOMEM;
    }

    handle = CERT_GetDefaultCertDB();
    der_item.len = der_size;
    der_item.data = discard_const(der_blob);

    cert = CERT_NewTempCertificate(handle, &der_item, NULL, PR_FALSE, PR_TRUE);
    if (cert == NULL) {
        ret = EINVAL;
        goto done;
    }

    cont->issuer_str = talloc_strdup(cont, cert->issuerName);
    if (cont->issuer_str == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = get_rdn_list(cont, cert->issuer.rdns, &cont->issuer_rdn_list);
    if (ret != 0) {
        goto done;
    }

    cont->subject_str = talloc_strdup(cont, cert->subjectName);
    if (cont->subject_str == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = get_rdn_list(cont, cert->subject.rdns, &cont->subject_rdn_list);
    if (ret != 0) {
        goto done;
    }


    cont->key_usage = cert->keyUsage;

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

    CERT_DestroyCertificate(cert);
    NSS_ShutdownContext(nss_ctx);

    if (ret == EOK) {
        *content = cont;
    } else {
        talloc_free(cont);
    }

    return ret;
}
