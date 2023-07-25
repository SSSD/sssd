/*
    SSSD

    Library for rule based certificate to user mapping - LDAP mapping rules

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

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <talloc.h>

#include "util/dlinklist.h"
#include "util/strtonum.h"
#include "lib/certmap/sss_certmap.h"
#include "lib/certmap/sss_certmap_int.h"

#define HEX_CONVERSION "hex_conversion"
#define HEX_DEC_CONVERSION "hex_dec_conversion"
#define READ_DIGESTS_FROM_CTX "read_digests_from_ctx"
#define ATTR_NAME_AND_OR_NUMBER "attr_name_an_or_number"

struct template_table {
    const char *name;
    const char **attr_name;
    const char **conversion;
};

const char *empty[] = {NULL};
const char *name_attr[] = {"short_name", NULL};
const char *attr_name_and_or_number[] = { ATTR_NAME_AND_OR_NUMBER, NULL};
const char *x500_conv[] = {"ad_x500",  "ad",  "ad_ldap",
                           "nss_x500", "nss", "nss_ldap", NULL};
const char *bin_conv[] = {"bin", "base64", NULL};
const char *hex_conv[] = {HEX_CONVERSION, NULL};
const char *dec_hex_conv[] = {HEX_DEC_CONVERSION, NULL};
const char *digest_conv[] = { READ_DIGESTS_FROM_CTX, NULL};
const char *sid_rid_attr[] = {"rid", NULL};

struct template_table template_table_base[] = {
    {"issuer_dn", empty, x500_conv},
    {"subject_dn", empty, x500_conv},
    {"cert", empty, bin_conv},
    {"subject_rfc822_name", name_attr, empty},
    {"subject_dns_name", name_attr, empty},
    {"subject_x400_address", empty, empty},
    {"subject_directory_name", empty, empty},
    {"subject_ediparty_name", empty, empty},
    {"subject_uri", empty, empty},
    {"subject_ip_address", empty, empty},
    {"subject_registered_id", empty, empty},
    {"subject_pkinit_principal", name_attr, empty},
    {"subject_nt_principal", name_attr, empty},
    {"subject_principal", name_attr, empty},
    {NULL, NULL, NULL}};

struct template_table template_table_u1[] = {
    {"serial_number", empty, dec_hex_conv},
    {"subject_key_id", empty, hex_conv},
    {"cert", empty, digest_conv},
    {"subject_dn_component", attr_name_and_or_number, empty},
    {"issuer_dn_component", attr_name_and_or_number, empty},
    {"sid", sid_rid_attr, empty},
    {NULL, NULL, NULL}};

int check_attr_name_and_or_number(TALLOC_CTX *mem_ctx, const char *inp,
                                  char **_attr_name, int32_t *_number)
{
    int ret;
    char *sep;
    char *end;
    char *endptr = NULL;
    char *attr_name = NULL;
    int32_t number = 0;

    if (inp == NULL) {
        attr_name = NULL;
        number = 0;
        ret = 0;
        goto done;
    }

    sep = strchr(inp, '[');
    if (sep == NULL) {
        attr_name = talloc_strdup(mem_ctx, inp);
        if (attr_name == NULL) {
            return ENOMEM;
        }
        number = 0;
    } else {
        end = strchr(sep, ']');
        if (end == NULL || end == (sep + 1) || *(end + 1) != '\0') {
            return EINVAL;
        }

        number = strtoint32(sep+1, &endptr, 10);
        if (errno !=0 || number == 0 || *endptr != ']') {
            return EINVAL;
        }

        if (sep == inp) {
            attr_name = NULL;
        } else {
            attr_name = talloc_strndup(mem_ctx, inp, sep - inp);
            if (attr_name == NULL) {
                return ENOMEM;
            }
        }

    }

    ret = 0;

done:

    if (ret == 0) {
        if (_attr_name != NULL) {
            *_attr_name = attr_name;
        }
        if (_number != NULL) {
            *_number = number;
        }
    }
    return ret;
}

int check_hex_conversion(const char *inp, bool dec_allowed, bool *_dec,
                         bool *_upper, bool *_colon, bool *_reverse)
{
    int ret;
    char *sep;
    bool dec = false;
    bool upper = false;
    bool colon = false;
    bool reverse = false;
    char *c;

    if (inp == NULL) {
        ret = 0;
        goto done;
    }

    sep = strchr(inp, '_');
    /* We expect either 'hex' or 'dec' as full string or 'hex' before '_'*/
    if ((sep == NULL && strlen(inp) != 3)
            || (sep != NULL && (sep - inp) != 3)) {
        ret = EINVAL;
        goto done;
    }

    if (strncasecmp(inp, "hex", 3) != 0) {
        if (dec_allowed && sep == NULL && strncasecmp(inp, "dec", 3) == 0) {
            dec = true;
        } else {
            ret = EINVAL;
            goto done;
        }
    }

    if (sep != NULL) {
        for (c = sep + 1; *c != '\0'; c++) {
            switch(*c) {
            case 'u':
            case 'U':
                upper = true;
                break;
            case 'c':
            case 'C':
                colon = true;
                break;
            case 'r':
            case 'R':
                reverse = true;
                break;
            default:
                ret = EINVAL;
                goto done;
            }
        }
    }

    ret = 0;
done:
    if (ret == 0) {
        if (_dec != NULL) {
            *_dec = dec;
        }
        if (_upper != NULL) {
            *_upper = upper;
        }
        if (_colon != NULL) {
            *_colon = colon;
        }
        if (_reverse != NULL) {
            *_reverse = reverse;
        }
    }

    return ret;
}

int check_digest_conversion(const char *inp, const char **digest_list,
                            const char **_dgst, bool *_upper, bool *_colon,
                            bool *_reverse)
{
    int ret;
    char *sep;
    size_t d;
    int cmp;
    bool upper = false;
    bool colon = false;
    bool reverse = false;
    char *c;
    size_t len = 0;

    sep = strchr(inp, '_');
    if (sep != NULL) {
        len = sep - inp;
    }

    for (d = 0; digest_list[d] != NULL; d++) {
        if (sep == NULL) {
            cmp = strcasecmp(digest_list[d], inp);
        } else {
            if (strlen(digest_list[d]) != len) {
                continue;
            }
            cmp = strncasecmp(digest_list[d], inp, len);
        }

        if (cmp == 0) {
            break;
        }
    }

    if (digest_list[d] == NULL) {
        return EINVAL;
    }

    if (sep != NULL) {
        for (c = sep + 1; *c != '\0'; c++) {
            switch(*c) {
            case 'u':
            case 'U':
                upper = true;
                break;
            case 'c':
            case 'C':
                colon = true;
                break;
            case 'r':
            case 'R':
                reverse = true;
                break;
            default:
                ret = EINVAL;
                goto done;
            }
        }
    }

    ret = 0;
done:
    if (ret == 0) {
        if (_dgst != NULL) {
            *_dgst = digest_list[d];
        }
        if (_upper != NULL) {
            *_upper = upper;
        }
        if (_colon != NULL) {
            *_colon = colon;
        }
        if (_reverse != NULL) {
            *_reverse = reverse;
        }
    }

    return ret;
}

static int check_parsed_template(struct sss_certmap_ctx *ctx,
                                 struct template_table *template_table,
                                 struct parsed_template *parsed)
{
    size_t n;
    size_t a;
    size_t c;
    bool attr_name_valid = false;
    bool conversion_valid = false;

    for (n = 0; template_table[n].name != NULL; n++) {
        if (strcmp(template_table[n].name, parsed->name) != 0) {
            continue;
        }

        if (parsed->attr_name != NULL) {
            for (a = 0; template_table[n].attr_name[a] != NULL; a++) {
                if (strcmp(template_table[n].attr_name[a],
                           parsed->attr_name) == 0) {
                    attr_name_valid = true;
                    break;
                }
            }

            if (!attr_name_valid && template_table[n].attr_name[0] != NULL
                        && strcmp(template_table[n].attr_name[0],
                                  ATTR_NAME_AND_OR_NUMBER) == 0) {
                if (check_attr_name_and_or_number(ctx, parsed->attr_name, NULL,
                                                  NULL) == 0) {
                    attr_name_valid = true;
                }
            }
        } else {
            attr_name_valid = true;
        }

        if (parsed->conversion != NULL) {
            for (c = 0; template_table[n].conversion[c] != NULL; c++) {
                if (strcmp(template_table[n].conversion[c],
                           parsed->conversion) == 0) {
                    conversion_valid = true;
                    break;
                }
            }

            if (!conversion_valid && template_table[n].conversion[0] != NULL
                        && strcmp(template_table[n].conversion[0],
                                  HEX_DEC_CONVERSION) == 0) {
                if (check_hex_conversion(parsed->conversion, true,
                                         NULL, NULL, NULL, NULL) == 0) {
                    conversion_valid = true;
                }
            }
            if (!conversion_valid && template_table[n].conversion[0] != NULL
                        && strcmp(template_table[n].conversion[0],
                                 HEX_CONVERSION) == 0) {
                if (check_hex_conversion(parsed->conversion, false,
                                         NULL, NULL, NULL, NULL) == 0) {
                    conversion_valid = true;
                }
            }
            if (!conversion_valid && template_table[n].conversion[0] != NULL
                        && strcmp(template_table[n].conversion[0],
                                  READ_DIGESTS_FROM_CTX) == 0) {
                if (check_digest_conversion(parsed->conversion,
                                            ctx->digest_list,
                                            NULL, NULL, NULL, NULL) == 0) {
                    conversion_valid = true;
                }
            }
        } else {
            conversion_valid = true;
        }

        if (attr_name_valid && conversion_valid) {
            return 0;
        }
    }

    return EINVAL;
}

static int parse_template(TALLOC_CTX *mem_ctx, struct sss_certmap_ctx *ctx,
                          const char *template,
                          struct parsed_template **parsed_template)
{
    int ret;
    struct parsed_template *parsed = NULL;
    const char *dot;
    const char *excl;
    const char *p;

    parsed = talloc_zero(mem_ctx, struct parsed_template);
    if (parsed == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* A '.' indicates that a specifier will follow which indicates which part
     * of the value should be added. */
    dot = strchr(template, '.');
    if (dot != NULL) {
        p = strchr(dot + 1, '.');
        if (p != NULL) {
            CM_DEBUG(ctx, "Only one '.' allowed in template.");
            ret = EINVAL;
            goto done;
        }

        if (dot == template) {
            CM_DEBUG(ctx, "Missing name in template.");
            ret = EINVAL;
            goto done;
        }
    }

    /* A '!' indicates that a conversion specifier will follow which indicates
     * how the output should be formatted. */
    excl = strchr(template, '!');
    if (excl != NULL) {
        p = strchr(excl + 1, '!');
        if (p != NULL) {
            CM_DEBUG(ctx, "Only one '!' allowed in template.");
            ret = EINVAL;
            goto done;
        }

        if (excl == template) {
            CM_DEBUG(ctx, "Missing name in template.");
            ret = EINVAL;
            goto done;
        }
    }

    if (excl != NULL && excl[1] != '\0') {
        parsed->conversion = talloc_strdup(parsed, excl + 1);
        if (parsed->conversion == NULL) {
            CM_DEBUG(ctx, "Memory allocation failed.");
            ret = ENOMEM;
            goto done;
        }
    }

    if (dot != NULL && dot[1] != '\0' && dot[1] != '!') {
        if (excl == NULL) {
            parsed->attr_name = talloc_strdup(parsed, dot + 1);
        } else {
            parsed->attr_name = talloc_strndup(parsed, dot + 1,
                                               (excl - dot - 1));
        }
        if (parsed->attr_name == NULL) {
            CM_DEBUG(ctx, "Memory allocation failed.");
            ret = ENOMEM;
            goto done;
        }
    }

    if (dot != NULL) {
        parsed->name = talloc_strndup(parsed, template, (dot - template));
    } else if (excl != NULL) {
        parsed->name = talloc_strndup(parsed, template, (excl - template));
    } else {
        parsed->name = talloc_strdup(parsed, template);
    }
    if (parsed->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* If the template cannot be found in the base table,
     * check LDAPU1 as well. */
    ret = check_parsed_template(ctx, template_table_base, parsed);
    if (ret != 0) {
        if (ctx->mapv == mapv_ldapu1) {
            ret = check_parsed_template(ctx, template_table_u1, parsed);
        }
        if (ret != 0) {
            CM_DEBUG(ctx, "Parse template [%s] invalid.", template);
            goto done;
        }
    }

    ret = 0;

done:
    if (ret == 0) {
        *parsed_template = parsed;
    } else {
        talloc_free(parsed);
    }

    return ret;
}

static int add_comp(struct sss_certmap_ctx *ctx, struct ldap_mapping_rule *rule,
                    const char *string, enum comp_type type)
{
    int ret;
    struct ldap_mapping_rule_comp *comp;

    comp = talloc_zero(rule, struct ldap_mapping_rule_comp);
    if (comp == NULL) {
        return ENOMEM;
    }

    comp->type = type;
    comp->val = talloc_strdup(comp, string);
    if (comp->val == NULL) {
        talloc_free(comp);
        return ENOMEM;
    }

    if (type == comp_template) {
        ret = parse_template(comp, ctx, string, &comp->parsed_template);
        if (ret != 0) {
            talloc_free(comp);
            return ret;
        }
    }

    DLIST_ADD_END(rule->list, comp, struct ldap_mapping_rule_comp *);

    return 0;
}

static int add_string(struct sss_certmap_ctx *ctx,
                      struct ldap_mapping_rule *rule, const char *string)
{
    return add_comp(ctx, rule, string, comp_string);
}

static int add_template(struct sss_certmap_ctx *ctx,
                        struct ldap_mapping_rule *rule, const char *string)
{
    return add_comp(ctx, rule, string, comp_template);
}

int parse_ldap_mapping_rule(struct sss_certmap_ctx *ctx,
                            const char *rule_start,
                            struct ldap_mapping_rule **mapping_rule)
{
    size_t c;
    const char *cur;
    char *tmp_string = NULL;
    size_t tmp_string_size;
    struct ldap_mapping_rule *rule = NULL;
    int ret;
    bool in_template = false;

    rule = talloc_zero(ctx, struct ldap_mapping_rule);
    if (rule == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tmp_string_size = strlen(rule_start) + 1;
    tmp_string = talloc_zero_size(ctx, tmp_string_size);
    if (tmp_string == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cur = rule_start;
    c = 0;

    while (*cur != '\0') {
        if (c > tmp_string_size) {
            CM_DEBUG(ctx, "Cannot parse mapping rule.");
            ret = EIO;
            goto done;
        }
        switch (*cur) {
        case '{':
            if (in_template) {
                CM_DEBUG(ctx, "'{' not allowed in templates.");
                ret = EINVAL;
                goto done;
            }
            if (cur[1] == '{') {
                /* Add only a single '{' to the output */
                tmp_string[c] = '{';
                c++;
                cur += 2;
            } else {
                if (c != 0) {
                    ret = add_string(ctx, rule, tmp_string);
                    if (ret != 0) {
                        CM_DEBUG(ctx, "Failed to add string.");
                        ret = EINVAL;
                        goto done;
                    }
                    memset(tmp_string, 0, tmp_string_size);
                    c = 0;
                }
                cur++;
                in_template = true;
            }
            break;
        case '}':
            if (cur[1] == '}') {
                if (in_template) {
                    CM_DEBUG(ctx, "'}}' not allowed in templates.");
                    ret = EINVAL;
                    goto done;
                } else {
                    /* Add only a single '}' to the output */
                    tmp_string[c] = '}';
                    c++;
                    cur += 2;
                }
            } else {
                ret = add_template(ctx, rule, tmp_string);
                if (ret != 0) {
                    CM_DEBUG(ctx, "Failed to add template.");
                    ret = EINVAL;
                    goto done;
                }
                memset(tmp_string, 0, tmp_string_size);
                c = 0;
                cur++;
                in_template = false;
            }
            break;
        default:
            tmp_string[c] = *cur;
            c++;
            cur++;
        }
    }
    if (in_template) {
        CM_DEBUG(ctx, "Rule ended inside template.");
        ret = EINVAL;
        goto done;
    }
    if (c != 0) {
        ret = add_string(ctx, rule, tmp_string);
        if (ret != 0) {
            CM_DEBUG(ctx, "Failed to add string.");
            ret = EINVAL;
            goto done;
        }
    }

    ret = 0;

done:
    if (ret == 0) {
        *mapping_rule = rule;
    } else {
        talloc_free(rule);
    }

    talloc_free(tmp_string);

    return ret;
}
