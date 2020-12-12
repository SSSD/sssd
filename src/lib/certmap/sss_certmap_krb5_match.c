/*
    SSSD

    Library for rule based certificate to user mapping - KRB5 matching rules

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

#include <ctype.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "lib/certmap/sss_certmap.h"
#include "lib/certmap/sss_certmap_int.h"

const struct sss_key_usage sss_key_usage[] = {
    {"digitalSignature" , SSS_KU_DIGITAL_SIGNATURE},
    {"nonRepudiation"   , SSS_KU_NON_REPUDIATION},
    {"keyEncipherment"  , SSS_KU_KEY_ENCIPHERMENT},
    {"dataEncipherment" , SSS_KU_DATA_ENCIPHERMENT},
    {"keyAgreement"     , SSS_KU_KEY_AGREEMENT},
    {"keyCertSign"      , SSS_KU_KEY_CERT_SIGN},
    {"cRLSign"          , SSS_KU_CRL_SIGN},
    {"encipherOnly"     , SSS_KU_ENCIPHER_ONLY},
    {"decipherOnly"     , SSS_KU_DECIPHER_ONLY},
    {NULL ,0}
};

const struct sss_ext_key_usage sss_ext_key_usage[] = {
    /* RFC 3280 section 4.2.1.13 */
    {"serverAuth",      "1.3.6.1.5.5.7.3.1"},
    {"clientAuth",      "1.3.6.1.5.5.7.3.2"},
    {"codeSigning",     "1.3.6.1.5.5.7.3.3"},
    {"emailProtection", "1.3.6.1.5.5.7.3.4"},
    {"timeStamping",    "1.3.6.1.5.5.7.3.8"},
    {"OCSPSigning",     "1.3.6.1.5.5.7.3.9"},

    /* RFC 4556 section 3.2.2 */
    {"KPClientAuth",    "1.3.6.1.5.2.3.4"},
    {"pkinit",          "1.3.6.1.5.2.3.4"},

    /* https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography*/
    {"msScLogin",       "1.3.6.1.4.1.311.20.2.2"},

    {NULL ,0}
};

const struct sss_san_name sss_san_names[] = {
    /* https://www.ietf.org/rfc/rfc3280.txt section 4.2.1.7 */
    {"otherName", SAN_OTHER_NAME, false},
    {"rfc822Name", SAN_RFC822_NAME, true},
    {"dNSName", SAN_DNS_NAME, true},
    {"x400Address", SAN_X400_ADDRESS, false},
    {"directoryName", SAN_DIRECTORY_NAME, true},
    {"ediPartyName", SAN_EDIPART_NAME, false},
    {"uniformResourceIdentifier", SAN_URI, true},
    {"iPAddress", SAN_IP_ADDRESS, true},
    {"registeredID", SAN_REGISTERED_ID, true},
    /* https://www.ietf.org/rfc/rfc4556.txt section 3.2.2 */
    {"pkinitSAN", SAN_PKINIT, true},
    /* https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography */
    {"ntPrincipalName", SAN_NT, true},
    /* both previous principal types */
    {"Principal", SAN_PRINCIPAL, true},
    {"stringOtherName", SAN_STRING_OTHER_NAME, true},
    {NULL, SAN_END, false}
};

static bool is_dotted_decimal(const char *s, size_t len)
{
    size_t c = 0;
    bool has_dot = false;

    if (s == NULL || !isdigit(s[c++])) {
        return false;
    }

    while ((len == 0 && s[c] != '\0') || (len != 0 && c < len)) {
        if (s[c] != '.' && !isdigit(s[c])) {
            return false;
        }
        if (!has_dot && s[c] == '.') {
            has_dot = true;
        }
        c++;
    }

    return (has_dot && isdigit(s[c - 1]));
}

static int component_list_destructor(void *data)
{
    struct component_list *comp = talloc_get_type(data, struct component_list);

    if (comp != NULL) {
        regfree(&(comp->regexp));
    }

    return 0;
}

/*
 * The syntax of the MIT Kerberos style matching rules is:
 *     [KRB5:][relation-operator]component-rule ...
 *
 * where:
 *
 *  relation-operator
 *   can be either &&, meaning all component rules must match, or ||,
 *   meaning only one component rule must match.  The default is &&.
 *
 *  component-rule
 *   can be one of the following.  Note that there is no punctuation or whitespace between component rules.
 *    <SUBJECT>regular-expression
 *    <ISSUER>regular-expression
 *    <SAN>regular-expression
 *    <EKU>extended-key-usage
 *    <KU>key-usage
 *
 *  see man sss-certmap for more details
 *
 */

static int get_comp_value(TALLOC_CTX *mem_ctx,
                          struct sss_certmap_ctx *ctx,
                          const char **cur,
                          struct component_list **_comp)

{
    struct component_list *comp = NULL;
    const char *end;
    int ret;

    comp = talloc_zero(mem_ctx, struct component_list);
    if (comp == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor((TALLOC_CTX *) comp, component_list_destructor);

    end = strchr(*cur, '<');

    if (end == NULL) {
        comp->val = talloc_strdup(comp, *cur);
    } else {
        comp->val = talloc_strndup(comp, *cur, end - *cur);
    }
    if (comp->val == NULL) {
        ret = ENOMEM;
        goto done;
    }
    if (*(comp->val) == '\0') {
        CM_DEBUG(ctx, "Missing component value.");
        ret = EINVAL;
        goto done;
    }

    *cur += strlen(comp->val);
    *_comp = comp;
    ret = 0;

done:
    if (ret != 0) {
        talloc_free(comp);
    }

    return ret;
}

static int parse_krb5_get_eku_value(TALLOC_CTX *mem_ctx,
                                    struct sss_certmap_ctx *ctx,
                                    const char **cur,
                                    struct component_list **_comp)
{
    struct component_list *comp = NULL;
    int ret;
    char **eku_list;
    size_t c;
    size_t k;
    const char *o;
    size_t e = 0;
    int eku_list_size;

    ret = get_comp_value(mem_ctx, ctx, cur, &comp);
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to parse regexp.");
        goto done;
    }

    ret = split_on_separator(mem_ctx, comp->val, ',', true, true,
                             &eku_list, &eku_list_size);
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to split list.");
        goto done;
    }

    comp->eku_oid_list = talloc_zero_array(comp, const char *,
                                           eku_list_size + 1);
    if (comp->eku_oid_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; eku_list[c] != NULL; c++) {
        for (k = 0; sss_ext_key_usage[k].name != NULL; k++) {
            if (strcasecmp(eku_list[c], sss_ext_key_usage[k].name) == 0) {
                comp->eku_oid_list[e] = talloc_strdup(comp->eku_oid_list,
                                                      sss_ext_key_usage[k].oid);
                if (comp->eku_oid_list[e] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                e++;
                break;
            }
        }

        if (sss_ext_key_usage[k].name == NULL) {
            /* check for an dotted-decimal OID */
            if (*(eku_list[c]) != '.') {
                o = eku_list[c];
                if (is_dotted_decimal(o, 0)) {
                    /* looks like a OID, only '.' and digits */
                    comp->eku_oid_list[e] = talloc_strdup(comp->eku_oid_list,
                                                          eku_list[c]);
                    if (comp->eku_oid_list[e] == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                    e++;
                    continue;
                }
            }
            CM_DEBUG(ctx, "No matching extended key usage found.");
            ret = EINVAL;
            goto done;
        }
    }

    if (e == 0) {
        talloc_free(comp->eku_oid_list);
        comp->eku_oid_list = NULL;
    }

    ret = 0;

done:
    if (ret == 0) {
        *_comp = comp;
    } else {
        talloc_free(comp);
    }

    return ret;
}

static int parse_krb5_get_ku_value(TALLOC_CTX *mem_ctx,
                                   struct sss_certmap_ctx *ctx,
                                   const char **cur,
                                   struct component_list **_comp)
{
    struct component_list *comp = NULL;
    int ret;
    char **ku_list;
    size_t c;
    size_t k;

    ret = get_comp_value(mem_ctx, ctx, cur, &comp);
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to get value.");
        goto done;
    }

    ret = split_on_separator(mem_ctx, comp->val, ',', true, true,
                             &ku_list, NULL);
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to split list.");
        goto done;
    }

    for (c = 0; ku_list[c] != NULL; c++) {
        for (k = 0; sss_key_usage[k].name != NULL; k++) {
            if (strcasecmp(ku_list[c], sss_key_usage[k].name) == 0) {
                comp->ku |= sss_key_usage[k].flag;
                break;
            }
        }

        if (sss_key_usage[k].name == NULL) {
            /* FIXME: add check for numerical ku */
            CM_DEBUG(ctx, "No matching key usage found.");
            ret = EINVAL;
            goto done;
        }
    }

    ret = 0;

done:
    if (ret == 0) {
        *_comp = comp;
    } else {
        talloc_free(comp);
    }

    return ret;
}

static int parse_krb5_get_component_value(TALLOC_CTX *mem_ctx,
                                          struct sss_certmap_ctx *ctx,
                                          const char **cur,
                                          struct component_list **_comp)
{
    struct component_list *comp = NULL;
    int ret;

    ret = get_comp_value(mem_ctx, ctx, cur, &comp);
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to parse regexp.");
        goto done;
    }

    ret = regcomp(&(comp->regexp), comp->val, REG_EXTENDED);
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to parse regexp.");
        goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
        *_comp = comp;
    } else {
        talloc_free(comp);
    }

    return ret;
}

static int parse_krb5_get_san_option(TALLOC_CTX *mem_ctx,
                                     struct sss_certmap_ctx *ctx,
                                     const char **cur,
                                     enum san_opt *option,
                                     char **str_other_name_oid)
{
    char *end;
    size_t c;
    size_t len;

    end = strchr(*cur, '>');
    if (end == NULL) {
        CM_DEBUG(ctx, "Failed to parse SAN option.");
        return EINVAL;
    }

    len = end - *cur;

    if (len == 0) {
        c= SAN_PRINCIPAL;
    } else {
        for (c = 0; sss_san_names[c].name != NULL; c++) {
            if (strncasecmp(*cur, sss_san_names[c].name, len) == 0) {
                break;
            }
        }
        if (sss_san_names[c].name == NULL) {
            if (is_dotted_decimal(*cur, len)) {
                c = SAN_STRING_OTHER_NAME;
                *str_other_name_oid = talloc_strndup(mem_ctx, *cur, len);
                if (*str_other_name_oid == NULL) {
                    CM_DEBUG(ctx, "talloc_strndup failed.");
                    return ENOMEM;
                }
            } else {
                CM_DEBUG(ctx, "Unknown SAN option.");
                return EINVAL;
            }
        }
    }

    *option = sss_san_names[c].san_opt;
    *cur = end + 1;

    return 0;
}

static int parse_krb5_get_san_value(TALLOC_CTX *mem_ctx,
                                    struct sss_certmap_ctx *ctx,
                                    const char **cur,
                                    struct component_list **_comp)
{
    struct component_list *comp = NULL;
    enum san_opt san_opt = SAN_PRINCIPAL;
    int ret;
    char *str_other_name_oid = NULL;

    if (*(*cur - 1) == ':') {
        ret = parse_krb5_get_san_option(mem_ctx, ctx, cur, &san_opt,
                                        &str_other_name_oid);
        if (ret != 0) {
            goto done;
        }
    }

    if (sss_san_names[san_opt].is_string) {
        ret = parse_krb5_get_component_value(mem_ctx, ctx, cur, &comp);
        if (ret != 0) {
            goto done;
        }
    } else {
        ret = get_comp_value(mem_ctx, ctx, cur, &comp);
        if (ret != 0) {
            goto done;
        }

        if (comp->val != NULL) {
            comp->bin_val = sss_base64_decode(comp, comp->val,
                                              &comp->bin_val_len);
            if (comp->bin_val == NULL || comp->bin_val_len == 0) {
                CM_DEBUG(ctx, "Base64 decode failed.");
                ret = EINVAL;
                goto done;
            }
        }
    }
    comp->san_opt = san_opt;

done:
    if (ret == 0) {
        comp->str_other_name_oid = talloc_steal(comp, str_other_name_oid);
        *_comp = comp;
    } else {
        talloc_free(comp);
        talloc_free(str_other_name_oid);
    }

    return ret;
}

int parse_krb5_match_rule(struct sss_certmap_ctx *ctx,
                          const char *rule_start,
                          struct krb5_match_rule **match_rule)
{
    const char *cur;
    struct krb5_match_rule *rule;
    struct component_list *comp;
    int ret;

    rule = talloc_zero(ctx, struct krb5_match_rule);
    if (rule == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cur = rule_start;
    /* check relation */
    if (strncmp(cur, "&&", 2) == 0) {
        rule->r = relation_and;
        cur += 2;
    } else if (strncmp(cur, "||", 2) == 0) {
        rule->r = relation_or;
        cur += 2;
    } else {
        rule->r = relation_and;
    }

    while (*cur != '\0') {
        /* new component must start with '<' */
        if (*cur != '<') {
            CM_DEBUG(ctx, "Invalid KRB5 matching rule.");
            ret = EINVAL;
            goto done;
        }
        cur++;

        if (strncmp(cur, "ISSUER>", 7) == 0) {
            cur += 7;
            ret = parse_krb5_get_component_value(rule, ctx, &cur, &comp);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(rule->issuer, comp);
        } else if (strncmp(cur, "SUBJECT>", 8) == 0) {
            cur += 8;
            ret = parse_krb5_get_component_value(rule, ctx, &cur, &comp);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(rule->subject, comp);
        } else if (strncmp(cur, "KU>", 3) == 0) {
            cur += 3;
            ret = parse_krb5_get_ku_value(rule, ctx, &cur, &comp);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(rule->ku, comp);
        } else if (strncmp(cur, "EKU>", 4) == 0) {
            cur += 4;
            ret = parse_krb5_get_eku_value(rule, ctx, &cur, &comp);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(rule->eku, comp);
        } else if (strncmp(cur, "SAN>", 4) == 0
                        || strncmp(cur, "SAN:", 4) == 0) {
            cur += 4;
            ret = parse_krb5_get_san_value(rule, ctx, &cur, &comp);
            if (ret != 0) {
                goto done;
            }
            DLIST_ADD(rule->san, comp);
        } else {
            CM_DEBUG(ctx, "Invalid KRB5 matching rule.");
            ret = EINVAL;
            goto done;
        }
    }

    ret = 0;

done:
    if (ret == 0) {
        *match_rule = rule;
    } else {
        talloc_free(rule);
    }

    return ret;
}
