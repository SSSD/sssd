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

#include "config.h"

#include <ctype.h>

#include "util/util.h"
#include "util/cert.h"
#include "util/crypto/sss_crypto.h"
#include "lib/certmap/sss_certmap.h"
#include "lib/certmap/sss_certmap_int.h"

int debug_level;
void sss_debug_fn(const char *file,
                  long line,
                  const char *function,
                  int level,
                  const char *format, ...)
{
    return;
}

static int get_type_prefix(TALLOC_CTX *mem_ctx, const char *match_rule,
                           char **type, const char **rule_start)
{
    const char *c;
    char *delim;

    *type = NULL;
    *rule_start = match_rule;

    delim = strchr(match_rule, ':');
    if (delim == NULL) {
        /* no type prefix found */
        return 0;
    }

    /* rule starts with ':', empty type */
    if (delim == match_rule) {
        *rule_start = delim + 1;
        return EOK;
    }

    for (c = match_rule; c < delim; c++) {
        /* type prefix may only contain digits and upper-case ASCII characters */
        if (!(isascii(*c) && (isdigit(*c) || isupper(*c)))) {
            /* no type prefix found */
            return 0;
        }
    }

    *rule_start = delim + 1;
    *type = talloc_strndup(mem_ctx, match_rule, (delim - match_rule));
    if (*type == NULL) {
        return ENOMEM;
    }

    return 0;
}

static int parse_match_rule(struct sss_certmap_ctx *ctx, const char *match_rule,
                            struct krb5_match_rule **parsed_match_rule)
{
    int ret;
    char *type;
    const char *rule_start;

    ret = get_type_prefix(ctx, match_rule, &type, &rule_start);
    if (ret != EOK) {
        CM_DEBUG(ctx, "Failed to read rule type.");
        goto done;
    }

    if (type == NULL || strcmp(type, "KRB5") == 0) {
        ret = parse_krb5_match_rule(ctx, rule_start, parsed_match_rule);
        if (ret != EOK) {
            CM_DEBUG(ctx, "Failed to parse KRB5 matching rule.");
            goto done;
        }
    } else {
        CM_DEBUG(ctx, "Unsupported matching rule type.");
        ret = ESRCH;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(type);

    return ret;
}

static int parse_mapping_rule(struct sss_certmap_ctx *ctx,
                              const char *mapping_rule,
                              struct ldap_mapping_rule **parsed_mapping_rule)
{
    int ret;
    char *type;
    const char *rule_start;

    ret = get_type_prefix(ctx, mapping_rule, &type, &rule_start);
    if (ret != EOK) {
        CM_DEBUG(ctx, "Failed to read rule type.");
        goto done;
    }

    if (type == NULL || strcmp(type, "LDAP") == 0) {
        ret = parse_ldap_mapping_rule(ctx, rule_start, parsed_mapping_rule);
        if (ret != EOK) {
            CM_DEBUG(ctx, "Failed to parse LDAP mapping rule.");
            goto done;
        }
    } else {
        CM_DEBUG(ctx, "Unsupported mapping rule type.");
        ret = ESRCH;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(type);

    return ret;
}

int sss_certmap_add_rule(struct sss_certmap_ctx *ctx,
                         uint32_t priority, const char *match_rule,
                         const char *map_rule, const char **domains)
{
    size_t c;
    int ret;
    struct match_map_rule *rule;
    struct TALLOC_CTX *tmp_ctx;
    struct priority_list *p;
    struct priority_list *p_new;
    struct krb5_match_rule *parsed_match_rule;
    struct ldap_mapping_rule *parsed_mapping_rule;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    rule = talloc_zero(tmp_ctx, struct match_map_rule);
    if (rule == NULL) {
        ret = ENOMEM;
        goto done;
    }

    rule->priority = priority;

    if (match_rule == NULL) {
        match_rule = DEFAULT_MATCH_RULE;
    }
    ret = parse_match_rule(ctx, match_rule, &parsed_match_rule);
    if (ret == 0) {
        rule->parsed_match_rule = talloc_steal(rule, parsed_match_rule);
        rule->match_rule = talloc_strdup(rule, match_rule);
        if (rule->match_rule == NULL) {
            ret = ENOMEM;
            goto done;
        }
    } else if (ret == ESRCH) {
        /* report unsupported rules */
        goto done;
    } else {
        goto done;
    }

    if (map_rule == NULL) {
        map_rule = DEFAULT_MAP_RULE;
    }
    ret = parse_mapping_rule(ctx, map_rule, &parsed_mapping_rule);
    if (ret == 0) {
        rule->parsed_mapping_rule = talloc_steal(rule, parsed_mapping_rule);
        rule->map_rule = talloc_strdup(rule, map_rule);
        if (rule->map_rule == NULL) {
            ret = ENOMEM;
            goto done;
        }
    } else if (ret == ESRCH) {
        /* report unsupported rules */
        goto done;
    } else {
        goto done;
    }

    if (domains != NULL && *domains != NULL) {
        for (c = 0; domains[c] != NULL; c++);
        rule->domains = talloc_zero_array(rule, char *, c + 1);
        if (rule->domains == NULL) {
            ret = ENOMEM;
            goto done;
        }
        for (c = 0; domains[c] != NULL; c++) {
            rule->domains[c] = talloc_strdup(rule->domains, domains[c]);
            if (rule->domains[c] == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    if (ctx->prio_list == NULL) {
        ctx->prio_list = talloc_zero(ctx, struct priority_list);
        if (ctx->prio_list == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ctx->prio_list->priority = rule->priority;
        ctx->prio_list->rule_list = rule;
    } else {
        for (p = ctx->prio_list; p != NULL && p->priority < rule->priority;
                                                                   p = p->next);
        if (p != NULL && p->priority == priority) {
            DLIST_ADD(p->rule_list, rule);
        } else {
            p_new = talloc_zero(ctx, struct priority_list);
            if (p_new == NULL) {
                ret = ENOMEM;
                goto done;
            }

            p_new->priority = rule->priority;
            p_new->rule_list = rule;

            if (p == NULL) {
                DLIST_ADD_END(ctx->prio_list, p_new, struct priority_list *);
            } else if (p->prev == NULL) {
                DLIST_ADD(ctx->prio_list, p_new);
            } else {
                DLIST_ADD_AFTER(ctx->prio_list, p_new, p->prev);
            }
        }
    }

    talloc_steal(ctx, rule);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static int expand_cert(struct sss_certmap_ctx *ctx,
                       struct parsed_template *parsed_template,
                       struct sss_cert_content *cert_content,
                       char **expanded)
{
    int ret;
    char *tmp_str = NULL;

    if (parsed_template->conversion == NULL
            || strcmp(parsed_template->conversion, "bin") == 0) {
        ret = bin_to_ldap_filter_value(ctx, cert_content->cert_der,
                                       cert_content->cert_der_size, &tmp_str);
        if (ret != 0) {
            CM_DEBUG(ctx, "bin conversion failed.");
            goto done;
        }
    } else if (strcmp(parsed_template->conversion, "base64") == 0) {
        tmp_str = sss_base64_encode(ctx, cert_content->cert_der,
                                    cert_content->cert_der_size);
        if (tmp_str == NULL) {
            CM_DEBUG(ctx, "base64 conversion failed.");
            ret = ENOMEM;
            goto done;
        }
    } else {
        CM_DEBUG(ctx, "Unsupported conversion.");
        ret = EINVAL;
        goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
        *expanded = tmp_str;
    } else {
        talloc_free(tmp_str);
    }

    return ret;
}

static int expand_san_blob(struct sss_certmap_ctx *ctx, enum san_opt san_opt,
                           struct san_list *san_list, char **expanded)
{
    struct san_list *item;
    char *exp;
    int ret;

    DLIST_FOR_EACH(item, san_list) {
        if (item->san_opt == san_opt) {
            ret = bin_to_ldap_filter_value(ctx, item->bin_val,
                                           item->bin_val_len, &exp);
            if (ret != 0) {
                CM_DEBUG(ctx, "bin conversion failed.");
                return ret;
            }

            *expanded = exp;
            return 0;
        }
    }

    return ENOENT;
}

static int expand_san_string(struct sss_certmap_ctx *ctx, enum san_opt san_opt,
                             struct san_list *san_list, const char *attr_name,
                             char **expanded)
{
    struct san_list *item;
    char *exp;

    DLIST_FOR_EACH(item, san_list) {
        if (item->san_opt == san_opt) {
            if (attr_name == NULL) {
                exp = talloc_strdup(ctx, item->val);
            } else if (strcasecmp(attr_name, "short_name") == 0) {
                exp = talloc_strdup(ctx, item->short_name);
            } else {
                CM_DEBUG(ctx, "Unsupported attribute name [%s].", attr_name);
                return EINVAL;
            }

            if (exp == NULL) {
                return ENOMEM;
            }

            *expanded = exp;
            return 0;
        }
    }

    return ENOENT;
}

static int expand_san_rdn_list(struct sss_certmap_ctx *ctx,
                               enum san_opt san_opt,
                               struct san_list *san_list,
                               const char *conversion,
                               char **expanded)
{
    struct san_list *item;
    char *exp;
    int ret;

    DLIST_FOR_EACH(item, san_list) {
        if (item->san_opt == san_opt) {
            ret = rdn_list_2_dn_str(ctx, conversion, item->rdn_list, &exp);
            if (ret != 0) {
                return ret;
            }

            *expanded = exp;
            return 0;
        }
    }

    return ENOENT;
}


static int expand_san(struct sss_certmap_ctx *ctx,
                        struct parsed_template *parsed_template,
                        struct san_list *san_list,
                        char **expanded)
{
    int ret;

    if (strcmp("subject_rfc822_name", parsed_template->name) == 0) {
        ret = expand_san_string(ctx, SAN_RFC822_NAME, san_list,
                                parsed_template->attr_name, expanded);
    } else if (strcmp("subject_dns_name", parsed_template->name) == 0) {
        ret = expand_san_string(ctx, SAN_DNS_NAME, san_list,
                                parsed_template->attr_name, expanded);
    } else if (strcmp("subject_x400_address", parsed_template->name) == 0) {
        ret = expand_san_blob(ctx, SAN_X400_ADDRESS, san_list, expanded);
    } else if (strcmp("subject_directory_name", parsed_template->name) == 0) {
        ret = expand_san_rdn_list(ctx, SAN_DIRECTORY_NAME, san_list,
                                  parsed_template->conversion, expanded);
    } else if (strcmp("subject_ediparty_name", parsed_template->name) == 0) {
        ret = expand_san_blob(ctx, SAN_EDIPART_NAME, san_list, expanded);
    } else if (strcmp("subject_uri", parsed_template->name) == 0) {
        ret = expand_san_string(ctx, SAN_URI, san_list,
                                parsed_template->attr_name, expanded);
    } else if (strcmp("subject_ip_address", parsed_template->name) == 0) {
        ret = expand_san_string(ctx, SAN_IP_ADDRESS, san_list,
                                parsed_template->attr_name, expanded);
    } else if (strcmp("subject_registered_id", parsed_template->name) == 0) {
        ret = expand_san_string(ctx, SAN_REGISTERED_ID, san_list,
                                parsed_template->attr_name, expanded);
    } else if (strcmp("subject_pkinit_principal", parsed_template->name) == 0) {
        ret = expand_san_string(ctx, SAN_PKINIT, san_list,
                                parsed_template->attr_name, expanded);
    } else if (strcmp("subject_nt_principal", parsed_template->name) == 0) {
        ret = expand_san_string(ctx, SAN_NT, san_list,
                                parsed_template->attr_name, expanded);
    } else if (strcmp("subject_principal", parsed_template->name) == 0) {
        ret = expand_san_string(ctx, SAN_PRINCIPAL, san_list,
                                parsed_template->attr_name, expanded);
    } else {
        CM_DEBUG(ctx, "Unsupported template name [%s].n",
                      parsed_template->name);
        ret = EINVAL;
    }

    return ret;
}

static int expand_template(struct sss_certmap_ctx *ctx,
                           struct parsed_template *parsed_template,
                           struct sss_cert_content *cert_content,
                           char **expanded)
{
    int ret;
    char *exp = NULL;

    if (strcmp("issuer_dn", parsed_template->name) == 0) {
        ret = rdn_list_2_dn_str(ctx, parsed_template->conversion,
                                cert_content->issuer_rdn_list, &exp);
    } else if (strcmp("subject_dn", parsed_template->name) == 0) {
        ret = rdn_list_2_dn_str(ctx, parsed_template->conversion,
                                cert_content->subject_rdn_list, &exp);
    } else if (strncmp("subject_", parsed_template->name, 8) == 0) {
        ret = expand_san(ctx, parsed_template, cert_content->san_list, &exp);
    } else if (strcmp("cert", parsed_template->name) == 0) {
        ret = expand_cert(ctx, parsed_template, cert_content, &exp);
    } else {
        CM_DEBUG(ctx, "Unsupported template name.");
        ret = EINVAL;
        goto done;
    }
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to expand [%s] template.", parsed_template->name);
        goto done;
    }

    if (exp == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
        *expanded = exp;
    } else {
        talloc_free(exp);
    }

    return ret;
}

static int get_filter(struct sss_certmap_ctx *ctx,
                      struct ldap_mapping_rule *parsed_mapping_rule,
                      struct sss_cert_content *cert_content,
                      char **filter)
{
    struct ldap_mapping_rule_comp *comp;
    char *result = NULL;
    char *expanded = NULL;
    int ret;

    result = talloc_strdup(ctx, "");
    if (result == NULL) {
        return ENOMEM;
    }

    for (comp = parsed_mapping_rule->list; comp != NULL; comp = comp->next) {
        if (comp->type == comp_string) {
            result = talloc_strdup_append(result, comp->val);
        } else if (comp->type == comp_template) {
            ret = expand_template(ctx, comp->parsed_template, cert_content,
                                  &expanded);
            if (ret != 0) {
                CM_DEBUG(ctx, "Failed to expanded template.");
                goto done;
            }

            result = talloc_strdup_append(result, expanded);
            talloc_free(expanded);
            expanded = NULL;
            if (result == NULL) {
                ret = ENOMEM;
                goto done;
            }
        } else {
            ret = EINVAL;
            CM_DEBUG(ctx, "Unsupported component type.");
            goto done;
        }
    }

    ret = 0;
done:
    talloc_free(expanded);
    if (ret == 0) {
        *filter = result;
    } else {
        talloc_free(result);
    }

    return ret;
}

static bool check_san_regexp(struct sss_certmap_ctx *ctx,
                             enum san_opt san_opt, regex_t regexp,
                             struct san_list *san_list)
{
    struct san_list *item;
    bool match = false;
    int ret;
    char *tmp_str = NULL;

    DLIST_FOR_EACH(item, san_list) {
        if (item->san_opt == san_opt) {
            if (item->san_opt == SAN_DIRECTORY_NAME) {
                /* use LDAP order for matching */
                ret = rdn_list_2_dn_str(ctx, NULL, item->rdn_list, &tmp_str);
                if (ret != 0 || tmp_str == NULL) {
                    return false;
                }
                match = (regexec(&regexp, tmp_str, 0, NULL, 0) == 0);
                talloc_free(tmp_str);
            } else {
                match = (item->val != NULL
                            && regexec(&regexp, item->val, 0, NULL, 0) == 0);
            }
            if (!match) {
                return false;
            }
        }
    }

    return match;
}

static bool check_san_blob(enum san_opt san_opt,
                           uint8_t *bin_val, size_t bin_val_len,
                           struct san_list *san_list)
{
    struct san_list *item;
    bool match = false;

    if (bin_val == NULL || bin_val_len == 0) {
        return false;
    }

    DLIST_FOR_EACH(item, san_list) {
        if (item->san_opt == san_opt) {
            match = (item->bin_val != NULL && item->bin_val_len != 0
                        && memmem(item->bin_val, item->bin_val_len,
                                  bin_val, bin_val_len) != NULL);
            if (!match) {
                return false;
            }
        }
    }

    return match;
}

static bool check_san_str_other_name(enum san_opt san_opt,
                                     const char *str_other_name_oid,
                                     regex_t regexp,
                                     struct san_list *san_list)
{
    struct san_list *item;
    bool match = false;
    char *tmp_str;

    if (str_other_name_oid == NULL) {
        return false;
    }

    DLIST_FOR_EACH(item, san_list) {
        if (item->san_opt == san_opt
                && strcmp(item->other_name_oid, str_other_name_oid) == 0) {
            match = false;
            if (item->bin_val != NULL && item->bin_val_len != 0) {
                tmp_str = talloc_strndup(item, (char *) item->bin_val,
                                         item->bin_val_len);
                if (tmp_str != NULL) {
                    match = (regexec(&regexp, tmp_str, 0, NULL, 0) == 0);
                }
                talloc_free(tmp_str);
            }
            if (!match) {
                return false;
            }
        }
    }

    return match;
}

static bool do_san_match(struct sss_certmap_ctx *ctx,
                         struct component_list *comp,
                         struct san_list *san_list)
{
    switch (comp->san_opt) {
    case SAN_OTHER_NAME:
        return check_san_blob(SAN_STRING_OTHER_NAME,
                              comp->bin_val, comp->bin_val_len,
                              san_list);
        break;
    case SAN_X400_ADDRESS:
    case SAN_EDIPART_NAME:
        return check_san_blob(comp->san_opt, comp->bin_val, comp->bin_val_len,
                              san_list);
        break;
    case SAN_RFC822_NAME:
    case SAN_DNS_NAME:
    case SAN_DIRECTORY_NAME:
    case SAN_URI:
    case SAN_IP_ADDRESS:
    case SAN_REGISTERED_ID:
    case SAN_PKINIT:
    case SAN_NT:
    case SAN_PRINCIPAL:
        return check_san_regexp(ctx, comp->san_opt, comp->regexp, san_list);
        break;
    case SAN_STRING_OTHER_NAME:
        return check_san_str_other_name(comp->san_opt, comp->str_other_name_oid,
                                        comp->regexp, san_list);
        break;
    default:
        CM_DEBUG(ctx, "Unsupported SAN option [%d].", comp->san_opt);
        return false;
    }
}

static int do_match(struct sss_certmap_ctx *ctx,
                    struct krb5_match_rule *parsed_match_rule,
                    struct sss_cert_content *cert_content)
{
    struct component_list *comp;
    bool match = false;
    size_t c;

    if (parsed_match_rule == NULL || cert_content == NULL) {
        return EINVAL;
    }

    /* Issuer */
    for (comp = parsed_match_rule->issuer; comp != NULL; comp = comp->next) {
        match = (cert_content->issuer_str != NULL
                    && regexec(&(comp->regexp), cert_content->issuer_str,
                               0, NULL, 0) == 0);
        if (match && parsed_match_rule->r == relation_or) {
            /* match */
            return 0;
        } else if (!match && parsed_match_rule->r == relation_and) {
            /* no match */
            return ENOENT;
        }

    }

    /* Subject */
    for (comp = parsed_match_rule->subject; comp != NULL; comp = comp->next) {
        match = (cert_content->subject_str != NULL
                    && regexec(&(comp->regexp), cert_content->subject_str,
                               0, NULL, 0) == 0);
        if (match && parsed_match_rule->r == relation_or) {
            /* match */
            return 0;
        } else if (!match && parsed_match_rule->r == relation_and) {
            /* no match */
            return ENOENT;
        }

    }

    /* Key Usage */
    for (comp = parsed_match_rule->ku; comp != NULL; comp = comp->next) {
        match = ((cert_content->key_usage & comp->ku) == comp->ku);
        if (match && parsed_match_rule->r == relation_or) {
            /* match */
            return 0;
        } else if (!match && parsed_match_rule->r == relation_and) {
            /* no match */
            return ENOENT;
        }
    }

    /* Extended Key Usage */
    for (comp = parsed_match_rule->eku; comp != NULL; comp = comp->next) {
        for (c = 0; comp->eku_oid_list[c] != NULL; c++) {
            match = string_in_list(comp->eku_oid_list[c],
                                   discard_const(
                                         cert_content->extended_key_usage_oids),
                                   true);
            if (match && parsed_match_rule->r == relation_or) {
                /* match */
                return 0;
            } else if (!match && parsed_match_rule->r == relation_and) {
                /* no match */
                return ENOENT;
            }
        }
    }

    /* SAN */
    for (comp = parsed_match_rule->san; comp != NULL; comp = comp->next) {
        match = do_san_match(ctx, comp, cert_content->san_list);
        if (match && parsed_match_rule->r == relation_or) {
            /* match */
            return 0;
        } else if (!match && parsed_match_rule->r == relation_and) {
            /* no match */
            return ENOENT;
        }
    }

    if (match) {
        /* match */
        return 0;
    }

    /* no match */
    return ENOENT;
}

int sss_certmap_match_cert(struct sss_certmap_ctx *ctx,
                           const uint8_t *der_cert, size_t der_size)
{
    int ret;
    struct match_map_rule *r;
    struct priority_list *p;
    struct sss_cert_content *cert_content = NULL;

    ret = sss_cert_get_content(ctx, der_cert, der_size, &cert_content);
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to get certificate content.");
        return ret;
    }

    if (ctx->prio_list == NULL) {
        /* Match all certificates if there are no rules applied */
        ret = 0;
        goto done;
    }

    for (p = ctx->prio_list; p != NULL; p = p->next) {
        for (r = p->rule_list; r != NULL; r = r->next) {
            ret = do_match(ctx, r->parsed_match_rule, cert_content);
            if (ret == 0) {
                /* match */
                goto done;
            }
        }
    }

    ret = ENOENT;
done:
    talloc_free(cert_content);

    return ret;
}

int sss_certmap_get_search_filter(struct sss_certmap_ctx *ctx,
                                  const uint8_t *der_cert, size_t der_size,
                                  char **_filter, char ***_domains)
{
    int ret;
    struct match_map_rule *r;
    struct priority_list *p;
    struct sss_cert_content *cert_content = NULL;
    char *filter = NULL;
    char **domains = NULL;
    size_t c;

    if (_filter == NULL || _domains == NULL) {
        return EINVAL;
    }

    ret = sss_cert_get_content(ctx, der_cert, der_size, &cert_content);
    if (ret != 0) {
        CM_DEBUG(ctx, "Failed to get certificate content [%d].", ret);
        return ret;
    }

    if (ctx->prio_list == NULL) {
        if (ctx->default_mapping_rule == NULL) {
            CM_DEBUG(ctx, "No matching or mapping rules available.");
            return EINVAL;
        }

        ret = get_filter(ctx, ctx->default_mapping_rule, cert_content, &filter);
        goto done;
    }

    for (p = ctx->prio_list; p != NULL; p = p->next) {
        for (r = p->rule_list; r != NULL; r = r->next) {
            ret = do_match(ctx, r->parsed_match_rule, cert_content);
            if (ret == 0) {
                /* match */
                ret = get_filter(ctx, r->parsed_mapping_rule, cert_content,
                                 &filter);
                if (ret != 0) {
                    CM_DEBUG(ctx, "Failed to get filter");
                    goto done;
                }

                if (r->domains != NULL) {
                    for (c = 0; r->domains[c] != NULL; c++);
                    domains = talloc_zero_array(ctx, char *, c + 1);
                    if (domains == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }

                    for (c = 0; r->domains[c] != NULL; c++) {
                        domains[c] = talloc_strdup(domains, r->domains[c]);
                        if (domains[c] == NULL) {
                            ret = ENOMEM;
                            goto done;
                        }
                    }
                }

                ret = 0;
                goto done;
            }
        }
    }

    ret = ENOENT;

done:
    talloc_free(cert_content);
    if (ret == 0) {
        *_filter = filter;
        *_domains = domains;
    } else {
        talloc_free(filter);
        talloc_free(domains);
    }

    return ret;
}

int sss_certmap_init(TALLOC_CTX *mem_ctx,
                     sss_certmap_ext_debug *debug, void *debug_priv,
                     struct sss_certmap_ctx **ctx)
{
    int ret;

    if (ctx == NULL) {
        return EINVAL;
    }

    *ctx = talloc_zero(mem_ctx, struct sss_certmap_ctx);
    if (*ctx == NULL) {
        return ENOMEM;
    }

    (*ctx)->debug = debug;
    (*ctx)->debug_priv = debug_priv;

    ret  = parse_mapping_rule(*ctx, DEFAULT_MAP_RULE,
                              &((*ctx)->default_mapping_rule));
    if (ret != 0) {
        CM_DEBUG((*ctx), "Failed to parse default mapping rule.");
        talloc_free(*ctx);
        *ctx = NULL;
        return ret;
    }

    CM_DEBUG((*ctx), "sss_certmap initialized.");
    return EOK;
}

void sss_certmap_free_ctx(struct sss_certmap_ctx *ctx)
{
    talloc_free(ctx);
}

void sss_certmap_free_filter_and_domains(char *filter, char **domains)
{
    talloc_free(filter);
    talloc_free(domains);
}

static const char *sss_eku_oid2name(const char *oid)
{
    size_t c;

    for (c = 0; sss_ext_key_usage[c].name != NULL; c++) {
        if (strcmp(sss_ext_key_usage[c].oid, oid) == 0) {
            return sss_ext_key_usage[c].name;
        }
    }

    return NULL;
}

struct parsed_template san_parsed_template[] = {
    { NULL, NULL, NULL }, /* SAN_OTHER_NAME handled separately */
    { "subject_rfc822_name", NULL, NULL},
    { "subject_dns_name", NULL, NULL},
    { "subject_x400_address", NULL, NULL},
    { "subject_directory_name", NULL, NULL},
    { "subject_ediparty_name", NULL, NULL},
    { "subject_uri", NULL, NULL},
    { "subject_ip_address", NULL, NULL},
    { "subject_registered_id", NULL, NULL},
    { "subject_pkinit_principal", NULL, NULL},
    { "subject_nt_principal", NULL, NULL},
    { "subject_principal", NULL, NULL},
    { NULL, NULL, NULL }, /* SAN_STRING_OTHER_NAME handled separately */
    { NULL, NULL, NULL }  /* SAN_END */
};

static int sss_cert_dump_content(TALLOC_CTX *mem_ctx,
                                 struct sss_cert_content *c,
                                 char **content_str)
{
    char *out = NULL;
    size_t o;
    struct san_list *s;
    struct sss_certmap_ctx *ctx = NULL;
    char *expanded = NULL;
    int ret;
    char *b64 = NULL;
    const char *eku_str = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_certmap_init(tmp_ctx, NULL, NULL, &ctx);
    if (ret != EOK) {
        return ret;
    }

    ret = ENOMEM; /* default error code for upcoming memory allocation issues */
    out = talloc_strdup(tmp_ctx, "sss cert content (format might change):\n");
    if (out == NULL) goto done;

    out = talloc_asprintf_append(out, "Issuer: %s\n", c->issuer_str != NULL
                                                         ? c->issuer_str
                                                         : "- not available -");
    if (out == NULL) goto done;
    out = talloc_asprintf_append(out, "Subject: %s\n", c->subject_str != NULL
                                                         ? c->subject_str
                                                         : "- not available -");
    if (out == NULL) goto done;

    out = talloc_asprintf_append(out, "Key Usage: %u(0x%04x)", c->key_usage,
                                                               c->key_usage);
    if (out == NULL) goto done;

    if (c->key_usage != 0) {
        out = talloc_asprintf_append(out, " (");
        if (out == NULL) goto done;
        for (o = 0; sss_key_usage[o].name != NULL; o++) {
            if ((c->key_usage & sss_key_usage[o].flag) != 0) {
                out = talloc_asprintf_append(out, "%s%s",
                                             o == 0 ? "" : ",",
                                             sss_key_usage[o].name);
                if (out == NULL) goto done;
            }
        }
        out = talloc_asprintf_append(out, ")");
        if (out == NULL) goto done;
    }
    out = talloc_asprintf_append(out, "\n");
    if (out == NULL) goto done;

    for (o = 0; c->extended_key_usage_oids[o] != NULL; o++) {
        eku_str = sss_eku_oid2name(c->extended_key_usage_oids[o]);
        out = talloc_asprintf_append(out, "Extended Key Usage #%zu: %s%s%s%s\n",
                                          o, c->extended_key_usage_oids[o],
                                          eku_str == NULL ? "" : " (",
                                          eku_str == NULL ? "" : eku_str,
                                          eku_str == NULL ? "" : ")");
        if (out == NULL) goto done;
    }

    DLIST_FOR_EACH(s, c->san_list) {
        out = talloc_asprintf_append(out, "SAN type: %s\n",
                                     s->san_opt < SAN_END
                                                ? sss_san_names[s->san_opt].name
                                                : "- unsupported -");
        if (out == NULL) goto done;

        if (san_parsed_template[s->san_opt].name != NULL) {
            ret = expand_san(ctx, &san_parsed_template[s->san_opt], c->san_list,
                             &expanded);
            if (ret != EOK) {
                goto done;
            }
            out = talloc_asprintf_append(out, " %s=%s\n\n",
                                         san_parsed_template[s->san_opt].name,
                                         expanded);
            talloc_free(expanded);
            if (out == NULL) {
                ret = ENOMEM;
                goto done;
            }
        } else if (s->san_opt == SAN_STRING_OTHER_NAME) {
            b64 = sss_base64_encode(tmp_ctx, s->bin_val, s->bin_val_len);
            out = talloc_asprintf_append(out, " %s=%s\n\n", s->other_name_oid,
                                              b64 != NULL ? b64
                                                          : "- cannot encode -");
            talloc_free(b64);
            if (out == NULL) goto done;
        }
    }

    *content_str = talloc_steal(mem_ctx, out);

    ret = EOK;

done:

    talloc_free(tmp_ctx);
    return ret;
}

int sss_certmap_display_cert_content(TALLOC_CTX *mem_cxt,
                                     const uint8_t *der_cert, size_t der_size,
                                     char **desc)
{
    int ret;
    struct sss_cert_content *content = NULL;

    ret = sss_cert_get_content(mem_cxt, der_cert, der_size, &content);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_cert_dump_content(mem_cxt, content, desc);
    talloc_free(content);
    if (ret != EOK) {
        return ret;
    }

    return 0;
}
