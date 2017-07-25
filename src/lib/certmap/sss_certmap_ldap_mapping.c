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
#include "lib/certmap/sss_certmap.h"
#include "lib/certmap/sss_certmap_int.h"

struct template_table {
    const char *name;
    const char **attr_name;
    const char **conversion;
};

const char *empty[] = {NULL};
const char *name_attr[] = {"short_name", NULL};
const char *x500_conv[] = {"ad_x500",  "ad",  "ad_ldap",
                           "nss_x500", "nss", "nss_ldap", NULL};
const char *bin_conv[] = {"bin", "base64", NULL};

struct template_table template_table[] = {
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

static int check_parsed_template(struct sss_certmap_ctx *ctx,
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

    ret = check_parsed_template(ctx, parsed);
    if (ret != 0) {
        CM_DEBUG(ctx, "Parse template invalid.");
        goto done;
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
