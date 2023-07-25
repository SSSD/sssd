/*
    Copyright (C) 2017 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/sssctl/sssctl.h"
#include "sbus/sbus_opath.h"
#include "responder/ifp/ifp_iface/ifp_iface_sync.h"

/*
 * We're searching the cache directly..
 */
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ipa/ipa_rules_common.h"

typedef errno_t (*sssctl_dom_access_reporter_fn)(struct sss_tool_ctx *tool_ctx,
                                                 struct sss_domain_info *domain);

static errno_t get_rdn_value(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *dom,
                             const char *dn_attr,
                             const char **_rdn_value)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn = NULL;
    const struct ldb_val *rdn_val;
    const char *rdn_str;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new(tmp_ctx, sysdb_ctx_get_ldb(dom->sysdb), dn_attr);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    rdn_val = ldb_dn_get_rdn_val(dn);
    if (rdn_val == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No RDN value?\n");
        ret = ENOMEM;
        goto done;
    }

    rdn_str = talloc_strndup(tmp_ctx,
                               (const char *)rdn_val->data,
                               rdn_val->length);
    if (rdn_str == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
    *_rdn_value = talloc_steal(mem_ctx, rdn_str);
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t is_member_group(struct sss_domain_info *dom,
                               const char *dn_attr,
                               const char *group_rdn,
                               bool *_is_group)
{
    const char *comp_name;
    const struct ldb_val *comp_val;
    TALLOC_CTX *tmp_ctx;
    bool is_group = false;
    errno_t ret;
    struct ldb_dn *dn = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new(tmp_ctx, sysdb_ctx_get_ldb(dom->sysdb), dn_attr);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    comp_name = ldb_dn_get_component_name(dn, 1);
    comp_val = ldb_dn_get_component_val(dn, 1);
    if (strcasecmp("cn", comp_name) == 0
            && strncasecmp(group_rdn,
                           (const char *) comp_val->data,
                           comp_val->length) == 0) {
        is_group = true;
    }

    ret = EOK;
done:
    *_is_group = is_group;
    talloc_zfree(tmp_ctx);
    return ret;
}

static void print_category(struct sss_domain_info *domain,
                           struct ldb_message *rule_msg,
                           const char *category_attr_name,
                           const char *category_label)
{
    struct ldb_message_element *category_attr;

    category_attr = ldb_msg_find_element(rule_msg, category_attr_name);
    if (category_attr == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot find %s\n", category_attr_name);
        return;
    }

    if (category_attr->num_values > 0) {
        PRINT("\t%s: ", category_label);
        for (unsigned i = 0; i < category_attr->num_values; i++) {
            PRINT("%s%s",
                  i > 0 ? ", " : "",
                  (const char *) category_attr->values[i].data);
        }
        PRINT("\n");
    }
}

static void print_member_attr(struct sss_domain_info *domain,
                              struct ldb_message *rule_msg,
                              const char *member_attr_name,
                              const char *group_rdn,
                              const char *object_label,
                              const char *group_label)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    const char **member_names = NULL;
    size_t name_count = 0;
    const char **member_group_names = NULL;
    size_t group_count = 0;
    struct ldb_message_element *member_attr = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return;
    }

    member_attr = ldb_msg_find_element(rule_msg, member_attr_name);
    if (member_attr == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot find %s\n", member_attr_name);
        goto done;
    }

    member_names = talloc_zero_array(tmp_ctx,
                                      const char *,
                                      member_attr->num_values + 1);
    member_group_names = talloc_zero_array(tmp_ctx,
                                           const char *,
                                           member_attr->num_values + 1);
    if (member_names == NULL || member_group_names == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "OOM?\n");
        goto done;
    }

    for (size_t i = 0; i < member_attr->num_values; i++) {
        bool is_group;
        const char *rdn_string;
        const char *dn_attr;

        dn_attr = (const char *) member_attr->values[i].data;

        ret = is_member_group(domain, dn_attr, group_rdn, &is_group);
        if (ret != EOK) {
            continue;
        }

        ret = get_rdn_value(tmp_ctx, domain, dn_attr, &rdn_string);
        if (ret != EOK) {
            continue;
        }

        if (is_group == false) {
            member_names[name_count] = talloc_steal(member_names,
                                                    rdn_string);
            if (member_names[name_count] == NULL) {
                goto done;
            }
            name_count++;
        } else {
            member_group_names[group_count] = talloc_strdup(member_group_names,
                                                            rdn_string);
            if (member_group_names[group_count] == NULL) {
                goto done;
            }
            group_count++;
        }
    }

    if (member_names[0] != NULL) {
        PRINT("\t%s: ", object_label);
        for (int i = 0; member_names[i]; i++) {
            PRINT("%s%s", i > 0 ? ", " : "", member_names[i]);
        }
        PRINT("\n");
    }

    if (member_group_names[0] != NULL) {
        PRINT("\t%s: ", group_label);
        for (int i = 0; member_group_names[i]; i++) {
            PRINT("%s%s", i > 0 ? ", " : "", member_group_names[i]);
        }
        PRINT("\n");
    }

done:
    talloc_free(tmp_ctx);
}

static void print_ipa_hbac_rule(struct sss_domain_info *domain,
                                struct ldb_message *rule_msg)
{
    struct ldb_message_element *el;

    el = ldb_msg_find_element(rule_msg, IPA_CN);
    if (el == NULL || el->num_values < 1) {
        DEBUG(SSSDBG_MINOR_FAILURE, "A rule with no name\n");
        return;
    }

    PRINT("Rule name: %1$s\n", el->values[0].data);

    print_member_attr(domain,
                      rule_msg,
                      IPA_MEMBER_USER,
                      "groups",
                      _("Member users"),
                      _("Member groups"));
    print_category(domain,
                   rule_msg,
                   IPA_USER_CATEGORY,
                   _("User category"));

    print_member_attr(domain,
                      rule_msg,
                      IPA_MEMBER_SERVICE,
                      "hbacservicegroups",
                      _("Member services"),
                      _("Member service groups"));
    print_category(domain,
                   rule_msg,
                   IPA_SERVICE_CATEGORY,
                   _("Service category"));

    PRINT("\n");
}

static errno_t refresh_hbac_rules(struct sss_tool_ctx *tool_ctx,
                                  struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_sync_connection *conn;
    const char *path;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    path = sbus_opath_compose(tmp_ctx, IFP_PATH_DOMAINS, domain->name);
    if (path == NULL) {
        PRINT("Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    conn = sbus_sync_connect_system(tmp_ctx, NULL);
    if (conn == NULL) {
        ERROR("Unable to connect to system bus!\n");
        ret = EIO;
        goto done;
    }

    ret = sbus_call_ifp_domain_RefreshAccessRules(conn, IFP_BUS, path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to refresh HBAC rules [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sssctl_ipa_access_report(struct sss_tool_ctx *tool_ctx,
                                        struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *filter = NULL;
    errno_t ret;
    const char *attrs[] = {
        OBJECTCLASS,
        IPA_CN,
        IPA_MEMBER_USER,
        IPA_USER_CATEGORY,
        IPA_MEMBER_SERVICE,
        IPA_SERVICE_CATEGORY,
        IPA_MEMBER_HOST,
        IPA_HOST_CATEGORY,
        NULL,
    };
    size_t rule_count;
    struct ldb_message **msgs = NULL;

    /* Run the pam account phase to make sure the rules are fetched by SSSD */
    ret = refresh_hbac_rules(tool_ctx, domain);
    if (ret != EOK) {
        ERROR("Unable to refresh HBAC rules, using cached content\n");
        /* Non-fatal */
    }

    tmp_ctx = talloc_new(tool_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx, "(objectClass=%s)", IPA_HBAC_RULE);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              HBAC_RULES_SUBDIR, attrs,
                              &rule_count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up HBAC rules\n");
        goto done;
    }

    if (ret == ENOENT) {
        PRINT("No cached rules. All users will be denied access\n");
        ret = EOK;
        goto done;
    }

    PRINT("%1$zu rules cached\n\n", rule_count);

    for (size_t i = 0; i < rule_count; i++) {
        print_ipa_hbac_rule(domain, msgs[i]);
    }

    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

sssctl_dom_access_reporter_fn get_report_fn(const char *provider)
{
    if (strcmp(provider, "ipa") == 0) {
        return sssctl_ipa_access_report;
    }

    return NULL;
}

errno_t sssctl_access_report(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt)
{
    errno_t ret;
    const char *domname = NULL;
    sssctl_dom_access_reporter_fn reporter;
    struct sss_domain_info *dom;

    ret = sss_tool_popt_ex(cmdline, NULL, SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, "DOMAIN", _("Specify domain name."),
                           SSS_TOOL_OPT_REQUIRED, &domname, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        goto done;
    }

    dom = find_domain_by_name(tool_ctx->domains, domname, true);
    if (dom == NULL) {
        ERROR("Cannot find domain %1$s\n", domname);
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    reporter = get_report_fn(dom->provider);
    if (reporter == NULL) {
        ERROR("Access report not implemented for domains of type %1$s\n",
              dom->provider);
        goto done;
    }

    ret = reporter(tool_ctx, dom);

done:
    free(discard_const(domname));

    return ret;
}
