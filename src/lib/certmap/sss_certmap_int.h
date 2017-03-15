/*
    SSSD

    Library for rule based certificate to user mapping

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef __SSS_CERTMAP_INT_H__
#define __SSS_CERTMAP_INT_H__

#include <sys/types.h>
#include <regex.h>
#include <stdint.h>
#include <talloc.h>

#define CM_DEBUG(cm_ctx, format, ...) do { \
    if (cm_ctx != NULL && cm_ctx->debug != NULL) { \
        cm_ctx->debug(cm_ctx->debug_priv, __FILE__, __LINE__, __FUNCTION__, \
                      format, ##__VA_ARGS__); \
    } \
} while (0)

#define DEFAULT_MATCH_RULE "<KU>digitalSignature<EKU>clientAuth"
#define DEFAULT_MAP_RULE "LDAP:(userCertificate;binary={cert!bin})"

enum san_opt {
    SAN_OTHER_NAME = 0,
    SAN_RFC822_NAME,
    SAN_DNS_NAME,
    SAN_X400_ADDRESS,
    SAN_DIRECTORY_NAME,
    SAN_EDIPART_NAME,
    SAN_URI,
    SAN_IP_ADDRESS,
    SAN_REGISTERED_ID,
    SAN_PKINIT,
    SAN_NT,
    SAN_PRINCIPAL,
    SAN_STRING_OTHER_NAME,

    SAN_END,
    SAN_INVALID
};

/* KRB5 matching rule */
enum relation_type {
    relation_none = 0,
    relation_and,
    relation_or
};

struct component_list {
    char *val;
    regex_t regexp;
    uint32_t ku;
    const char **eku_oid_list;
    enum san_opt san_opt;
    char *str_other_name_oid;
    uint8_t *bin_val;
    size_t bin_val_len;
    struct component_list *prev;
    struct component_list *next;
};

struct krb5_match_rule {
    enum relation_type r;
    struct component_list *issuer;
    struct component_list *subject;
    struct component_list *ku;
    struct component_list *eku;
    struct component_list *san;
};

enum comp_type {
    comp_none = 0,
    comp_string,
    comp_template
};

struct parsed_template {
    char *name;
    char *attr_name;
    char *conversion;
};

struct ldap_mapping_rule_comp {
    enum comp_type type;
    char *val;
    struct parsed_template *parsed_template;
    struct ldap_mapping_rule_comp *prev;
    struct ldap_mapping_rule_comp *next;
};

struct ldap_mapping_rule {
    struct ldap_mapping_rule_comp *list;
};

struct match_map_rule {
    uint32_t priority;
    char *match_rule;
    struct krb5_match_rule *parsed_match_rule;
    char *map_rule;
    struct ldap_mapping_rule *parsed_mapping_rule;
    char **domains;
    struct match_map_rule *prev;
    struct match_map_rule *next;
};

struct priority_list {
    uint32_t priority;
    struct match_map_rule *rule_list;
    struct priority_list *prev;
    struct priority_list *next;
};

struct sss_certmap_ctx {
    struct priority_list *prio_list;
    sss_certmap_ext_debug *debug;
    void *debug_priv;
    struct ldap_mapping_rule *default_mapping_rule;
};

struct san_list {
    enum san_opt san_opt;
    char *val;
    uint8_t *bin_val;
    size_t bin_val_len;
    char *other_name_oid;
    char *short_name;
    const char **rdn_list;
    struct san_list *prev;
    struct san_list *next;
};

/* key usage flags, see RFC 3280 section 4.2.1.3 */
#define SSS_KU_DIGITAL_SIGNATURE    0x0080
#define SSS_KU_NON_REPUDIATION      0x0040
#define SSS_KU_KEY_ENCIPHERMENT     0x0020
#define SSS_KU_DATA_ENCIPHERMENT    0x0010
#define SSS_KU_KEY_AGREEMENT        0x0008
#define SSS_KU_KEY_CERT_SIGN        0x0004
#define SSS_KU_CRL_SIGN             0x0002
#define SSS_KU_ENCIPHER_ONLY        0x0001
#define SSS_KU_DECIPHER_ONLY        0x8000

struct sss_cert_content {
    const char *issuer_str;
    const char **issuer_rdn_list;
    const char *subject_str;
    const char **subject_rdn_list;
    uint32_t key_usage;
    const char **extended_key_usage_oids;
    struct san_list *san_list;

    uint8_t *cert_der;
    size_t cert_der_size;
};

int sss_cert_get_content(TALLOC_CTX *mem_ctx,
                         const uint8_t *der_blob, size_t der_size,
                         struct sss_cert_content **content);

char *check_ad_attr_name(TALLOC_CTX *mem_ctx, const char *rdn);

int parse_krb5_match_rule(struct sss_certmap_ctx *ctx,
                          const char *rule_start,
                          struct krb5_match_rule **match_rule);

int parse_ldap_mapping_rule(struct sss_certmap_ctx *ctx,
                            const char *rule_start,
                            struct ldap_mapping_rule **mapping_rule);
#endif /* __SSS_CERTMAP_INT_H__ */
