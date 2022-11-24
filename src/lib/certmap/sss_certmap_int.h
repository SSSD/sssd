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
#include <stdbool.h>
#include <talloc.h>

#include "lib/certmap/sss_certmap.h"

#define CM_DEBUG(cm_ctx, format, ...) do { \
    if (cm_ctx != NULL && cm_ctx->debug != NULL) { \
        cm_ctx->debug(cm_ctx->debug_priv, __FILE__, __LINE__, __FUNCTION__, \
                      format, ##__VA_ARGS__); \
    } \
} while (0)

#define DEFAULT_MATCH_RULE "<KU>digitalSignature<EKU>clientAuth"
#define DEFAULT_MAP_RULE "LDAP:(userCertificate;binary={cert!bin})"

#define PKINIT_OID "1.3.6.1.5.2.2"
#define NT_PRINCIPAL_OID "1.3.6.1.4.1.311.20.2.3"

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
    const char *name;
    const char *attr_name;
    const char *conversion;
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

enum mapping_rule_version {
    mapv_ldap = 0,
    mapv_ldapu1
};

struct sss_certmap_ctx {
    struct priority_list *prio_list;
    sss_certmap_ext_debug *debug;
    void *debug_priv;
    struct ldap_mapping_rule *default_mapping_rule;
    enum mapping_rule_version mapv;
    const char **digest_list;
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

struct sss_key_usage {
    const char *name;
    uint32_t flag;
};

extern const struct sss_key_usage sss_key_usage[];

struct sss_ext_key_usage {
    const char *name;
    const char *oid;
};

extern const struct sss_ext_key_usage sss_ext_key_usage[];

struct sss_san_name {
    const char *name;
    enum san_opt san_opt;
    bool is_string;
};

extern const struct sss_san_name sss_san_names[];

struct sss_cert_content {
    char *issuer_str;
    const char **issuer_rdn_list;
    char *subject_str;
    const char **subject_rdn_list;
    uint32_t key_usage;
    const char **extended_key_usage_oids;
    struct san_list *san_list;

    uint8_t *cert_der;
    size_t cert_der_size;

    uint8_t *serial_number;
    size_t serial_number_size;
    const char *serial_number_dec_str;

    uint8_t *subject_key_id;
    size_t subject_key_id_size;

    const char *sid_ext;
};

/**
 * @brief Extract various attributes from a binary X.509 certificate
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  der_blob    Binary DER encoded X.509 certificate
 * @param[in]  der_size    Length of the binary certificate
 * @param[out] content     Struct with parsed certificate data
 *
 * @return
 *  - 0:      success
 *  - EINVAL: invalid input
 *  - ENOMEM: memory allocation error
 */
int sss_cert_get_content(TALLOC_CTX *mem_ctx,
                         const uint8_t *der_blob, size_t der_size,
                         struct sss_cert_content **content);

/**
 * @brief Translate an RDN with NSS attribute names into AD names
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  rdn         RDN input string
 *
 * @return
 *  - NULL in case of an error
 *  - RDN string with AD attribute name and the same value as the input
 */
char *check_ad_attr_name(TALLOC_CTX *mem_ctx, const char *rdn);

/**
 * @brief Translate OpenSSL attribute name to NSS name
 *
 * @param[in]  attr         OpenSSL attribute name
 *
 * @return
 *  - NSS attribute name, most of the time it will be the same but there are
 *    some differences like e.g. 'GN' vs 'givenName'
 */
char *openssl_2_nss_attr_name(const char *attr);

/**
 * @brief Parse matching rule
 *
 * @param[in]  ctx          Certmap context
 * @param[in]  rule_start   Matching rule string
 * @param[out] mapping_rule Parsed rule struct
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: memory allocation failure
 *  - EINVAL: invalid input
 */
int parse_krb5_match_rule(struct sss_certmap_ctx *ctx,
                          const char *rule_start,
                          struct krb5_match_rule **match_rule);

/**
 * @brief Check hex conversion string
 *
 * @param[in]  inp         Conversion string
 * @param[in]  dec_allowed Flag to indicate if 'dec' for decimal output is
 *                         allowed in the conversion string
 * @param[out] _dec        Flag to indicate decimal output
 * @param[out] _upper      Upper flag found in the conversion string
 * @param[out] _colon      Colon flag found in the conversion string
 * @param[out] _reverse    Reverse flag found in the conversion string
 *
 * @return
 *  - 0:      success
 *  - EINVAL: invalid input
 */
int check_hex_conversion(const char *inp, bool dec_allowed, bool *_dec,
                         bool *_upper, bool *_colon, bool *_reverse);

/**
 * @brief Check digest conversion string
 *
 * @param[in]  inp         Conversion string
 * @param[in]  digest_list List of know digest/hash functions
 * @param[out] _dgst       Name of digest found in the conversion string
 * @param[out] _upper      Upper flag found in the conversion string
 * @param[out] _colon      Colon flag found in the conversion string
 * @param[out] _reverse    Reverse flag found in the conversion string
 *
 * @return
 *  - 0:      success
 *  - EINVAL: invalid input
 */
int check_digest_conversion(const char *inp, const char **digest_list,
                            const char **_dgst, bool *_upper, bool *_colon,
                            bool *_reverse);

/**
 * @brief Parse mapping rule
 *
 * @param[in]  ctx          Certmap context
 * @param[in]  rule_start   Mapping rule string
 * @param[out] mapping_rule Parsed rule struct
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: memory allocation failure
 *  - EINVAL: invalid input
 */
int parse_ldap_mapping_rule(struct sss_certmap_ctx *ctx,
                            const char *rule_start,
                            struct ldap_mapping_rule **mapping_rule);

/**
 * @brief Split attribute selector option
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  inp         Attribute selector string in the format:
 *                          - attr_name
 *                          - [number]
 *                          - attr_name[number]
 *                         The number 0 is not allowed in the input
 * @param[out] _attr_name  Attribute name from the input if present, NULL if
 *                         there is no name in the input
 * @param[out] _number     Number from the input if present, 0 if there is no
 *                         number in the input
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: memory allocation failure
 *  - EINVAL: invalid input
 */
int check_attr_name_and_or_number(TALLOC_CTX *mem_ctx, const char *inp,
                                  char **_attr_name, int32_t *_number);

/**
 * @brief Get the short name from a fully-qulified name
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  full_name   Fully-qulified name in the format
 *                         "short-name""delimiter""suffix"
 * @param[in]  delim       Delimiter character
 * @param[out] short_name  Resulting short name
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: memory allocation failure
 *  - EINVAL: invalid input
 */
int get_short_name(TALLOC_CTX *mem_ctx, const char *full_name,
                   char delim, char **short_name);

/**
 * @brief Add generic data to a new san_list item
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  is_bin      Binary data not a string
 * @param[in]  san_opt     Type of Subject alternative name (SAN)
 * @param[in]  data        Data
 * @param[in]  len         Length of data
 * @param[out] san_list    New san_list item
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: memory allocation failure
 *  - EINVAL: invalid input
 */
int add_to_san_list(TALLOC_CTX *mem_ctx, bool is_bin,
                    enum san_opt san_opt, const uint8_t *data, size_t len,
                    struct san_list **item);

/**
 * @brief Add a principal and the related short name to a new san_list item
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  san_opt     Type of Subject alternative name (SAN)
 * @param[in]  princ       String representation of the principal
 * @param[out] item        New san_list item
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: memory allocation failure
 */
int add_principal_to_san_list(TALLOC_CTX *mem_ctx, enum san_opt san_opt,
                              const char *princ, struct san_list **item);

/**
 * @brief Get DN specified by 'conversion' from 'rdn_list'
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  conversion  Specifies how the DN should be formatted:
 *                          - (ad|ad_x500)|ad_ldap|nss_x500|(nss|nss_ldap)
 *                         where 'x500' means most specific RDN comes last and
 *                         'ldap' most specific RDN comes first. 'ad' and
 *                         'nss' specify if the attributes names should be
 *                         translated in the way Active Directory or the NSS
 *                         library is using them.
 * @param[in]  rdn_list    String array with the the individual RDNs of a DN
 *                         starting with the most specific component
 * @param[out] result      The resulting DN
 *
 * @return
 *  - 0:      success
 *  - EINVAL: unsupported 'conversion'
 *  - ENOMEM: memory allocation failure
 */
int rdn_list_2_dn_str(TALLOC_CTX *mem_ctx, const char *conversion,
                      const char **rdn_list, char **result);

/**
 * @brief Get attribute value specified by 'conversion' from 'rdn_list'
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  conversion  Selection by position and/or name, format:
 *                          - name
 *                          - [pos]
 *                          - name[pos]
 *                         where 'name' is an attribute name and pos to
 *                         position of the attribute in the DN starting with
 *                         1, negative numbers will start at the least
 *                         specific component of the DN
 * @param[in]  rdn_list    String array with the the individual RDNs of a DN
 *                         starting with the most specific component
 * @param[out] result      The selected attribute value
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: memory allocation failure
 *  - EINVAL: unsupported 'conversion' or 'rdn_list'
 *  - EIO:    no value could be returned
 */
int rdn_list_2_component(TALLOC_CTX *mem_ctx, const char *conversion,
                         const char **rdn_list, char **result);

/**
 * @brief Get list of supported has/digest types
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[out] digest_list Resulting list of hash type names
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: memory allocation failure
 */
int get_digest_list(TALLOC_CTX *mem_ctx, const char ***digest_list);

/**
 * @brief Calculate the digest/hash of some binary data and return it as hex
 * string
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  blob        Binary data to calculate the hash of
 * @param[in]  blob_size   Length of binary data
 * @param[in]  digest      Type of hash/digest
 * @param[in]  upper_case  Use upper-case letters in hex string
 * @param[in]  colon_sep   Seperate each byte in the hex string with a ':'
 * @param[in]  reverse     Start at the end of the binary blob
 * @param[out] out         Resulting hex string
 *
 * @return
 *  - 0:      success
 *  - EINVAL: invalid hash type
 *  - EIO:    error while calculating the hash
 *  - ENOMEM: memory allocation failure
 */
int get_hash(TALLOC_CTX *mem_ctx, const uint8_t *blob, size_t blob_size,
             const char *digest, bool upper, bool colon, bool reverse,
             char **out);

/**
 * @brief Convert a binary blob into a hex string
 *
 * @param[in]  mem_ctx     Talloc memory context
 * @param[in]  upper_case  Use upper-case letters in hex string
 * @param[in]  colon_sep   Seperate each byte in the hex string with a ':'
 * @param[in]  reverse     Start at the end of the binary blob
 * @param[in]  buf         Start of the binary blob
 * @param[in]  len         Length of the binary blob
 * @param[out] out         Resulting hex string
 *
 * @return
 *  - 0:      success
 *  - EINVAL: invalid buffer or length
 *  - ENOMEM: memory allocation failure
 */
int bin_to_hex(TALLOC_CTX *mem_ctx, bool upper_case, bool colon_sep,
               bool reverse, uint8_t *buf, size_t len, char **out);
#endif /* __SSS_CERTMAP_INT_H__ */
