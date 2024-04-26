/*
    SSSD

    IPA Provider Common Functions

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <netdb.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <ldb.h>

#include "db/sysdb_selinux.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_dyndns.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/be_dyndns.h"
#include "util/sss_krb5.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"

#include "providers/ipa/ipa_opts.h"
#include "providers/data_provider/dp_private.h"

int ipa_get_options(TALLOC_CTX *memctx,
                    struct confdb_ctx *cdb,
                    const char *conf_path,
                    struct sss_domain_info *dom,
                    struct ipa_options **_opts)
{
    struct ipa_options *opts;
    char *domain;
    char *server;
    char *realm;
    char *ipa_hostname;
    int ret;
    char hostname[HOST_NAME_MAX + 1];

    opts = talloc_zero(memctx, struct ipa_options);
    if (!opts) return ENOMEM;

    ret = dp_get_options(opts, cdb, conf_path,
                         ipa_basic_opts,
                         IPA_OPTS_BASIC,
                         &opts->basic);
    if (ret != EOK) {
        goto done;
    }

    domain = dp_opt_get_string(opts->basic, IPA_DOMAIN);
    if (!domain) {
        ret = dp_opt_set_string(opts->basic, IPA_DOMAIN, dom->name);
        if (ret != EOK) {
            goto done;
        }
        domain = dom->name;
    }

    server = dp_opt_get_string(opts->basic, IPA_SERVER);
    if (!server) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No ipa server set, will use service discovery!\n");
    }

    ipa_hostname = dp_opt_get_string(opts->basic, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        ret = gethostname(hostname, sizeof(hostname));
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "gethostname failed [%d][%s].\n", ret,
                      strerror(ret));
            goto done;
        }
        hostname[HOST_NAME_MAX] = '\0';
        DEBUG(SSSDBG_TRACE_ALL, "Setting ipa_hostname to [%s].\n", hostname);
        ret = dp_opt_set_string(opts->basic, IPA_HOSTNAME, hostname);
        if (ret != EOK) {
            goto done;
        }
    }

    /* First check whether the realm has been manually specified */
    realm = dp_opt_get_string(opts->basic, IPA_KRB5_REALM);
    if (!realm) {
        /* No explicit krb5_realm, use the IPA domain, transform to upper-case */
        realm = get_uppercase_realm(opts, domain);
        if (!realm) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(opts->basic, IPA_KRB5_REALM,
                                realm);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;
    *_opts = opts;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }
    return ret;
}

static errno_t ipa_parse_search_base(TALLOC_CTX *mem_ctx,
                                     struct ldb_context *ldb,
                                     struct dp_option *opts, int class,
                                     struct sdap_search_base ***_search_bases)
{
    const char *class_name;
    char *unparsed_base;

    *_search_bases = NULL;

    switch (class) {
    case IPA_HBAC_SEARCH_BASE:
        class_name = "IPA_HBAC";
        break;
    case IPA_SELINUX_SEARCH_BASE:
        class_name = "IPA_SELINUX";
        break;
    case IPA_SUBDOMAINS_SEARCH_BASE:
        class_name = "IPA_SUBDOMAINS";
        break;
    case IPA_MASTER_DOMAIN_SEARCH_BASE:
        class_name = "IPA_MASTER_DOMAIN";
        break;
    case IPA_RANGES_SEARCH_BASE:
        class_name = "IPA_RANGES";
        break;
    case IPA_VIEWS_SEARCH_BASE:
        class_name = "IPA_VIEWS";
        break;
    case IPA_DESKPROFILE_SEARCH_BASE:
        class_name = "IPA_DESKPROFILE";
        break;
    case IPA_SUBID_RANGES_SEARCH_BASE:
        class_name = "IPA_SUBID_RANGES";
        break;
    default:
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Unknown search base type: [%d]\n", class);
        class_name = "UNKNOWN";
        /* Non-fatal */
        break;
    }

    unparsed_base = dp_opt_get_string(opts, class);
    if (!unparsed_base || unparsed_base[0] == '\0') return ENOENT;

    return common_parse_search_base(mem_ctx, unparsed_base, ldb,
                                    class_name, NULL,
                                    _search_bases);
}

int ipa_get_id_options(struct ipa_options *ipa_opts,
                       struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct data_provider *dp,
                       struct sdap_options **_opts)
{
    TALLOC_CTX *tmpctx;
    char *basedn;
    char *realm;
    char *value;
    int ret;
    int i;
    bool server_mode;
    struct ldb_context *ldb;

    ldb = sysdb_ctx_get_ldb(dp->be_ctx->domain->sysdb);

    tmpctx = talloc_new(ipa_opts);
    if (!tmpctx) {
        return ENOMEM;
    }

    ipa_opts->id = talloc_zero(ipa_opts, struct sdap_options);
    if (!ipa_opts->id) {
        ret = ENOMEM;
        goto done;
    }
    ipa_opts->id->dp = dp;

    ret = sdap_domain_add(ipa_opts->id,
                          ipa_opts->id_ctx->sdap_id_ctx->be->domain,
                          NULL);
    if (ret != EOK) {
        goto done;
    }

    /* get sdap options */
    ret = dp_get_options(ipa_opts->id, cdb, conf_path,
                         ipa_def_ldap_opts,
                         SDAP_OPTS_BASIC,
                         &ipa_opts->id->basic);
    if (ret != EOK) {
        goto done;
    }

    /* sssd-ipa can't use simple bind, ignore option that potentially can be set
     * for sssd-ldap in the same domain
     */
    ret = dp_opt_set_string(ipa_opts->id->basic,
                            SDAP_DEFAULT_AUTHTOK_TYPE, NULL);
    if (ret != EOK) {
        goto done;
    }

    ret = domain_to_basedn(tmpctx,
                           dp_opt_get_string(ipa_opts->basic, IPA_KRB5_REALM),
                           &basedn);
    if (ret != EOK) {
        goto done;
    }

    if (NULL == dp_opt_get_string(ipa_opts->id->basic, SDAP_SEARCH_BASE)) {
        /* FIXME: get values by querying IPA */
        /* set search base */
        value = talloc_asprintf(tmpctx, "cn=accounts,%s", basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic, SDAP_SEARCH_BASE));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ldb, ipa_opts->id->basic,
                                 SDAP_SEARCH_BASE,
                                 &ipa_opts->id->sdom->search_bases);
    if (ret != EOK) goto done;

    /* set krb realm */
    if (NULL == dp_opt_get_string(ipa_opts->id->basic, SDAP_KRB5_REALM)) {
        realm = dp_opt_get_string(ipa_opts->basic, IPA_KRB5_REALM);
        value = talloc_strdup(tmpctx, realm);
        if (value == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_KRB5_REALM, value);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_KRB5_REALM].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic, SDAP_KRB5_REALM));
    }

    ret = sdap_set_sasl_options(ipa_opts->id,
                                dp_opt_get_string(ipa_opts->basic,
                                                  IPA_HOSTNAME),
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_KRB5_REALM),
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_KRB5_KEYTAB));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set the SASL-related options\n");
        goto done;
    }

    /* fix schema to IPAv1 for now */
    ipa_opts->id->schema_type = SDAP_SCHEMA_IPA_V1;

    /* set user/group search bases if they are not specified */
    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_USER_SEARCH_BASE)) {
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_USER_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_USER_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_USER_SEARCH_BASE));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ldb, ipa_opts->id->basic,
                                 SDAP_USER_SEARCH_BASE,
                                 &ipa_opts->id->sdom->user_search_bases);
    if (ret != EOK) goto done;

    /* In server mode we need to search both cn=accounts,$SUFFIX and
     * cn=trusts,$SUFFIX to allow trusted domain object accounts to be found.
     * If cn=trusts,$SUFFIX is missing in the user search bases, add one
     */
    server_mode = dp_opt_get_bool(ipa_opts->basic, IPA_SERVER_MODE);
    if (server_mode != false) {
        /* bases is not NULL at this point already */
        struct sdap_search_base **bases = ipa_opts->id->sdom->user_search_bases;
        struct sdap_search_base *new_base = NULL;

        for (i = 0; bases[i] != NULL; i++) {
            if (strcasestr(bases[i]->basedn, "cn=trusts,") != NULL) {
                break;
            }
        }
        if (NULL == bases[i]) {
            /* no cn=trusts in the base, add a new one */
            char *new_dn = talloc_asprintf(bases,
                                           "cn=trusts,%s",
                                           basedn);
            if (NULL == new_dn) {
                ret = ENOMEM;
                goto done;
            }

            ret = sdap_create_search_base(bases, ldb, new_dn,
                                          LDAP_SCOPE_SUBTREE,
                                          "(objectClass=ipaIDObject)",
                                          &new_base);
            if (ret != EOK) {
                goto done;
            }

            bases = talloc_realloc(ipa_opts->id,
                                   ipa_opts->id->sdom->user_search_bases,
                                   struct sdap_search_base*,
                                   i + 2);

            if (NULL == bases) {
                ret = ENOMEM;
                goto done;
            }

            bases[i] = new_base;
            bases[i+1] = NULL;
            ipa_opts->id->sdom->user_search_bases = bases;

            DEBUG(SSSDBG_TRACE_FUNC,
                  "Option %s expanded to cover cn=trusts base\n",
                  ipa_opts->id->basic[SDAP_USER_SEARCH_BASE].opt_name);
        }
    }

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_GROUP_SEARCH_BASE)) {
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_GROUP_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_GROUP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_GROUP_SEARCH_BASE));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ldb, ipa_opts->id->basic,
                                 SDAP_GROUP_SEARCH_BASE,
                                 &ipa_opts->id->sdom->group_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_NETGROUP_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=ng,cn=alt,%s", basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_NETGROUP_SEARCH_BASE,
                                value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_NETGROUP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_NETGROUP_SEARCH_BASE));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ldb, ipa_opts->id->basic,
                                 SDAP_NETGROUP_SEARCH_BASE,
                                 &ipa_opts->id->sdom->netgroup_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_HOST_SEARCH_BASE)) {

        value = dp_opt_get_string(ipa_opts->basic, IPA_HOST_SEARCH_BASE);
        if (!value) {
            value = dp_opt_get_string(ipa_opts->id->basic, SDAP_SEARCH_BASE);
        }

        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_HOST_SEARCH_BASE,
                                value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
              ipa_opts->id->basic[SDAP_HOST_SEARCH_BASE].opt_name,
              value);
    }
    ret = sdap_parse_search_base(ipa_opts->id->basic, ldb, ipa_opts->id->basic,
                                 SDAP_HOST_SEARCH_BASE,
                                 &ipa_opts->id->sdom->host_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_HBAC_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=hbac,%s", basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->basic, IPA_HBAC_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->basic[IPA_HBAC_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_HBAC_SEARCH_BASE));
    }
    ret = ipa_parse_search_base(ipa_opts->basic, ldb, ipa_opts->basic,
                                IPA_HBAC_SEARCH_BASE,
                                &ipa_opts->hbac_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_SELINUX_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=selinux,%s", basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->basic, IPA_SELINUX_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
                  ipa_opts->basic[IPA_SELINUX_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_SELINUX_SEARCH_BASE));
    }
    ret = ipa_parse_search_base(ipa_opts->basic, ldb, ipa_opts->basic,
                                IPA_SELINUX_SEARCH_BASE,
                                &ipa_opts->selinux_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_DESKPROFILE_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=desktop-profile,%s", basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->basic, IPA_DESKPROFILE_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->basic[IPA_DESKPROFILE_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_DESKPROFILE_SEARCH_BASE));
    }
    ret = ipa_parse_search_base(ipa_opts->basic, ldb, ipa_opts->basic,
                                IPA_DESKPROFILE_SEARCH_BASE,
                                &ipa_opts->deskprofile_search_bases);
    if (ret != EOK) goto done;

#ifdef BUILD_SUBID
    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_SUBID_RANGES_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=subids,%s",
                                ipa_opts->id->sdom->search_bases[0]->basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->basic, IPA_SUBID_RANGES_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->basic[IPA_SUBID_RANGES_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_SUBID_RANGES_SEARCH_BASE));
    }
    ret = ipa_parse_search_base(ipa_opts->basic, ldb, ipa_opts->basic,
                                IPA_SUBID_RANGES_SEARCH_BASE,
                                &ipa_opts->id->sdom->subid_ranges_search_bases);
    if (ret != EOK) goto done;

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_subid_map,
                       SDAP_OPTS_SUBID_RANGE,
                       &ipa_opts->id->subid_map);
    if (ret != EOK) {
        goto done;
    }
#endif

    value = dp_opt_get_string(ipa_opts->id->basic, SDAP_DEREF);
    if (value != NULL) {
        ret = deref_string_to_val(value, &i);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to verify ldap_deref option.\n");
            goto done;
        }
    }

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_SERVICE_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=ipservices,%s",
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (!value) {
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_SERVICE_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_SERVICE_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_SERVICE_SEARCH_BASE));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ldb, ipa_opts->id->basic,
                                 SDAP_SERVICE_SEARCH_BASE,
                                 &ipa_opts->id->sdom->service_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_SUBDOMAINS_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=trusts,%s", basedn);
        if (value == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->basic, IPA_SUBDOMAINS_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
                  ipa_opts->basic[IPA_SUBDOMAINS_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_SUBDOMAINS_SEARCH_BASE));
    }
    ret = ipa_parse_search_base(ipa_opts, ldb, ipa_opts->basic,
                                IPA_SUBDOMAINS_SEARCH_BASE,
                                &ipa_opts->subdomains_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_MASTER_DOMAIN_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=ad,cn=etc,%s", basedn);
        if (value == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->basic, IPA_MASTER_DOMAIN_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
                  ipa_opts->basic[IPA_MASTER_DOMAIN_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_MASTER_DOMAIN_SEARCH_BASE));
    }
    ret = ipa_parse_search_base(ipa_opts, ldb, ipa_opts->basic,
                                IPA_MASTER_DOMAIN_SEARCH_BASE,
                                &ipa_opts->master_domain_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_RANGES_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=ranges,cn=etc,%s", basedn);
        if (value == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->basic, IPA_RANGES_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
                  ipa_opts->basic[IPA_RANGES_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_RANGES_SEARCH_BASE));
    }
    ret = ipa_parse_search_base(ipa_opts, ldb, ipa_opts->basic,
                                IPA_RANGES_SEARCH_BASE,
                                &ipa_opts->ranges_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_VIEWS_SEARCH_BASE)) {
        value = talloc_asprintf(tmpctx, "cn=views,cn=accounts,%s", basedn);
        if (value == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->basic, IPA_VIEWS_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
                  ipa_opts->basic[IPA_VIEWS_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_VIEWS_SEARCH_BASE));
    }
    ret = ipa_parse_search_base(ipa_opts, ldb, ipa_opts->basic,
                                IPA_VIEWS_SEARCH_BASE,
                                &ipa_opts->views_search_bases);
    if (ret != EOK) goto done;

    ret = sdap_get_map(ipa_opts->id, cdb, conf_path,
                       ipa_attr_map,
                       SDAP_AT_GENERAL,
                       &ipa_opts->id->gen_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_user_map,
                       SDAP_OPTS_USER,
                       &ipa_opts->id->user_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_extend_map_with_list(ipa_opts->id, ipa_opts->id,
                                    SDAP_USER_EXTRA_ATTRS,
                                    ipa_opts->id->user_map,
                                    SDAP_OPTS_USER,
                                    &ipa_opts->id->user_map,
                                    &ipa_opts->id->user_map_cnt);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_group_map,
                       SDAP_OPTS_GROUP,
                       &ipa_opts->id->group_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_netgroup_map,
                       IPA_OPTS_NETGROUP,
                       &ipa_opts->id->netgroup_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_host_map,
                       SDAP_OPTS_HOST,
                       &ipa_opts->id->host_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_hostgroup_map,
                       IPA_OPTS_HOSTGROUP,
                       &ipa_opts->hostgroup_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_service_map,
                       SDAP_OPTS_SERVICES,
                       &ipa_opts->id->service_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_selinux_user_map,
                       IPA_OPTS_SELINUX_USERMAP,
                       &ipa_opts->selinuxuser_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_view_map,
                       IPA_OPTS_VIEW,
                       &ipa_opts->view_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_override_map,
                       IPA_OPTS_OVERRIDE,
                       &ipa_opts->override_map);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
    *_opts = ipa_opts->id;

done:
    talloc_zfree(tmpctx);
    if (ret != EOK) {
        talloc_zfree(ipa_opts->id);
    }
    return ret;
}

int ipa_get_auth_options(struct ipa_options *ipa_opts,
                         struct confdb_ctx *cdb,
                         const char *conf_path,
                         struct dp_option **_opts)
{
    char *value;
    char *copy = NULL;
    int ret;

    ipa_opts->auth = talloc_zero(ipa_opts, struct dp_option);
    if (ipa_opts->auth == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* get krb5 options */
    ret = dp_get_options(ipa_opts, cdb, conf_path,
                         ipa_def_krb5_opts,
                         KRB5_OPTS, &ipa_opts->auth);
    if (ret != EOK) {
        goto done;
    }

    /* If there is no KDC, try the deprecated krb5_kdcip option, too */
    /* FIXME - this can be removed in a future version */
    ret = krb5_try_kdcip(cdb, conf_path, ipa_opts->auth, KRB5_KDC);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_try_kdcip failed.\n");
        goto done;
    }

    /* set krb realm */
    if (NULL == dp_opt_get_string(ipa_opts->auth, KRB5_REALM)) {
        value = dp_opt_get_string(ipa_opts->basic, IPA_KRB5_REALM);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }
        copy = talloc_strdup(ipa_opts->auth, value);
        if (copy == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->auth, KRB5_REALM, copy);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                  ipa_opts->auth[KRB5_REALM].opt_name,
                  dp_opt_get_string(ipa_opts->auth, KRB5_REALM));
    }

    /* If krb5_fast_principal was not set explicitly, default to
     * host/$client_hostname@REALM
     */
    value = dp_opt_get_string(ipa_opts->auth, KRB5_FAST_PRINCIPAL);
    if (value == NULL) {
        value = talloc_asprintf(ipa_opts->auth, "host/%s@%s",
                                    dp_opt_get_string(ipa_opts->basic,
                                                      IPA_HOSTNAME),
                                    dp_opt_get_string(ipa_opts->auth,
                                                      KRB5_REALM));
        if (value == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->auth, KRB5_FAST_PRINCIPAL,
                                value);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot set %s!\n",
                     ipa_opts->auth[KRB5_FAST_PRINCIPAL].opt_name);
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
              ipa_opts->auth[KRB5_FAST_PRINCIPAL].opt_name, value);
    }

    /* Set flag that controls whether we want to write the
     * kdcinfo files at all
     */
    ipa_opts->service->krb5_service->write_kdcinfo = \
        dp_opt_get_bool(ipa_opts->auth, KRB5_USE_KDCINFO);
    DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
          ipa_opts->auth[KRB5_USE_KDCINFO].opt_name,
          ipa_opts->service->krb5_service->write_kdcinfo ? "true" : "false");
    if (ipa_opts->service->krb5_service->write_kdcinfo) {
        sss_krb5_parse_lookahead(
            dp_opt_get_string(ipa_opts->auth, KRB5_KDCINFO_LOOKAHEAD),
            &ipa_opts->service->krb5_service->lookahead_primary,
            &ipa_opts->service->krb5_service->lookahead_backup);
    }

    *_opts = ipa_opts->auth;
    ret = EOK;

done:
    talloc_free(copy);
    if (ret != EOK) {
        talloc_zfree(ipa_opts->auth);
    }
    return ret;
}

static void ipa_resolve_callback(void *private_data, struct fo_server *server)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ipa_service *service;
    struct resolv_hostent *srvaddr;
    struct sockaddr *sockaddr;
    char *new_uri;
    const char *srv_name;
    socklen_t sockaddr_len;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed\n");
        return;
    }

    service = talloc_get_type(private_data, struct ipa_service);
    if (!service) {
        DEBUG(SSSDBG_CRIT_FAILURE, "FATAL: Bad private_data\n");
        talloc_free(tmp_ctx);
        return;
    }

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No hostent available for server (%s)\n",
                  fo_get_server_str_name(server));
        talloc_free(tmp_ctx);
        return;
    }

    sockaddr = resolv_get_sockaddr_address(tmp_ctx, srvaddr, LDAP_PORT, &sockaddr_len);
    if (sockaddr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "resolv_get_sockaddr_address failed.\n");
        talloc_free(tmp_ctx);
        return;
    }

    srv_name = fo_get_server_name(server);
    if (srv_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not get server host name\n");
        talloc_free(tmp_ctx);
        return;
    }

    new_uri = talloc_asprintf(service, "ldap://%s", srv_name);
    if (!new_uri) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy URI ...\n");
        talloc_free(tmp_ctx);
        return;
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Constructed uri '%s'\n", new_uri);

    /* free old one and replace with new one */
    talloc_zfree(service->sdap->uri);
    service->sdap->uri = new_uri;
    talloc_zfree(service->sdap->sockaddr);
    service->sdap->sockaddr = talloc_steal(service, sockaddr);
    service->sdap->sockaddr_len = sockaddr_len;

    if (service->krb5_service->write_kdcinfo) {
        ret = write_krb5info_file_from_fo_server(service->krb5_service,
                                                 server,
                                                 true,
                                                 SSS_KRB5KDC_FO_SRV,
                                                 NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "write to %s/kdcinfo.%s failed, authentication might fail.\n",
                  PUBCONF_PATH, service->krb5_service->realm);
        }
    }

    talloc_free(tmp_ctx);
}

static errno_t _ipa_servers_init(struct be_ctx *ctx,
                                 const char *fo_service,
                                 struct ipa_service *service,
                                 struct ipa_options *options,
                                 const char *servers,
                                 bool primary)
{
    TALLOC_CTX *tmp_ctx;
    char **list = NULL;
    char *ipa_domain;
    int ret = 0;
    int i;
    int j;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* split server parm into a list */
    ret = split_on_separator(tmp_ctx, servers, ',', true, true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse server list!\n");
        goto done;
    }

    for (j = 0; list[j]; j++) {
        if (resolv_is_address(list[j])) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "ipa_server [%s] is detected as IP address, "
                  "this can cause GSSAPI problems\n", list[j]);
        }
    }

    /* now for each one add a new server to the failover service */
    for (i = 0; list[i]; i++) {

        talloc_steal(service, list[i]);

        if (be_fo_is_srv_identifier(list[i])) {
            if (!primary) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to add server [%s] to failover service: "
                       "SRV resolution only allowed for primary servers!\n",
                       list[i]);
                continue;
            }

            ipa_domain = dp_opt_get_string(options->basic, IPA_DOMAIN);
            ret = be_fo_add_srv_server(ctx, fo_service, "ldap", ipa_domain,
                                       BE_FO_PROTO_TCP, false, NULL);
            if (ret) {
                DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add server\n");
                goto done;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "Added service lookup for service [%s]n",
                                     fo_service);
            continue;
        }

        /* It could be ipv6 address in square brackets. Remove
         * the brackets if needed. */
        ret = remove_ipv6_brackets(list[i]);
        if (ret != EOK) {
            goto done;
        }

        ret = be_fo_add_server(ctx, fo_service, list[i], 0, NULL, primary);
        if (ret && ret != EEXIST) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add server\n");
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Added Server %s\n", list[i]);
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static inline errno_t
ipa_primary_servers_init(struct be_ctx *ctx, const char *fo_service,
                         struct ipa_service *service, struct ipa_options *options,
                         const char *servers)
{
    return _ipa_servers_init(ctx, fo_service, service, options, servers, true);
}

static inline errno_t
ipa_backup_servers_init(struct be_ctx *ctx, const char *fo_service,
                        struct ipa_service *service, struct ipa_options *options,
                        const char *servers)
{
    return _ipa_servers_init(ctx, fo_service, service, options, servers, false);
}

static int ipa_user_data_cmp(void *ud1, void *ud2)
{
    return strcasecmp((char*) ud1, (char*) ud2);
}

int ipa_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                     const char *primary_servers,
                     const char *backup_servers,
                     const char *realm,
                     const char *ipa_service,
                     struct ipa_options *options,
                     struct ipa_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct ipa_service *service;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    service = talloc_zero(tmp_ctx, struct ipa_service);
    if (!service) {
        ret = ENOMEM;
        goto done;
    }
    service->sdap = talloc_zero(service, struct sdap_service);
    if (!service->sdap) {
        ret = ENOMEM;
        goto done;
    }

    service->krb5_service = krb5_service_new(service, ctx,
                                             ipa_service, realm,
                                             true,   /* The configured value */
                                             0,      /* will be set later when */
                                             0);     /* the auth provider is set up */

    if (!service->krb5_service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(ctx, ipa_service, ipa_user_data_cmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create failover service!\n");
        goto done;
    }

    service->sdap->name = talloc_strdup(service, ipa_service);
    if (!service->sdap->name) {
        ret = ENOMEM;
        goto done;
    }

    service->sdap->kinit_service_name = service->krb5_service->name;

    if (!primary_servers) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No primary servers defined, using service discovery\n");
        primary_servers = BE_SRV_IDENTIFIER;
    }

    ret = ipa_primary_servers_init(ctx, ipa_service, service, options, primary_servers);
    if (ret != EOK) {
        goto done;
    }

    if (backup_servers) {
        ret = ipa_backup_servers_init(ctx, ipa_service, service, options, backup_servers);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = be_fo_service_add_callback(memctx, ctx, ipa_service,
                                     ipa_resolve_callback, service);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to add failover callback!\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_service = talloc_steal(memctx, service);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

int ipa_get_autofs_options(struct ipa_options *ipa_opts,
                           struct ldb_context *ldb,
                           struct confdb_ctx *cdb,
                           const char *conf_path,
                           struct sdap_options **_opts)
{
    TALLOC_CTX *tmp_ctx;
    char *basedn;
    char *autofs_base;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = domain_to_basedn(tmp_ctx,
                           dp_opt_get_string(ipa_opts->basic, IPA_KRB5_REALM),
                           &basedn);
    if (ret != EOK) {
        goto done;
    }

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_AUTOFS_SEARCH_BASE)) {

        autofs_base = talloc_asprintf(tmp_ctx, "cn=%s,cn=automount,%s",
                                dp_opt_get_string(ipa_opts->basic,
                                                  IPA_AUTOMOUNT_LOCATION),
                                basedn);
        if (!autofs_base) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_AUTOFS_SEARCH_BASE,
                                autofs_base);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Option %s set to %s\n",
              ipa_opts->id->basic[SDAP_AUTOFS_SEARCH_BASE].opt_name,
              dp_opt_get_string(ipa_opts->id->basic,
                                SDAP_AUTOFS_SEARCH_BASE));
    }

    ret = sdap_parse_search_base(ipa_opts->id, ldb, ipa_opts->id->basic,
                                 SDAP_AUTOFS_SEARCH_BASE,
                                 &ipa_opts->id->sdom->autofs_search_bases);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not parse autofs search base\n");
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id, cdb, conf_path,
                       ipa_autofs_mobject_map,
                       SDAP_OPTS_AUTOFS_MAP,
                       &ipa_opts->id->autofs_mobject_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not get autofs map object attribute map\n");
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id, cdb, conf_path,
                       ipa_autofs_entry_map,
                       SDAP_OPTS_AUTOFS_ENTRY,
                       &ipa_opts->id->autofs_entry_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not get autofs entry object attribute map\n");
        goto done;
    }

    *_opts = ipa_opts->id;
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t ipa_get_dyndns_options(struct be_ctx *be_ctx,
                               struct ipa_options *ctx)
{
    errno_t ret;
    char *val;
    bool update;
    int ttl;

    ret = be_nsupdate_init(ctx, be_ctx, ipa_dyndns_opts, &ctx->dyndns_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot initialize IPA dyndns opts [%d]: %s\n",
               ret, sss_strerror(ret));
        return ret;
    }

    if (ctx->basic == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "IPA basic options not (yet) "
              "initialized, cannot copy legacy options\n");
        return EOK;
    }

    /* Reuse legacy option values */
    ret = confdb_get_string(be_ctx->cdb, ctx, be_ctx->conf_path,
                            "ipa_dyndns_update", NULL, &val);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get the value of %s\n",
              "ipa_dyndns_update");
        /* Not fatal */
    } else if (ret == EOK && val) {
        if (strcasecmp(val, "FALSE") == 0) {
            update = false;
        } else if (strcasecmp(val, "TRUE") == 0) {
            update = true;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "ipa_dyndns_update value is not a boolean!\n");
            talloc_free(val);
            return EINVAL;
        }

        DEBUG(SSSDBG_MINOR_FAILURE, "Deprecation warning: The option %s is "
              "deprecated and should not be used in favor of %s\n",
              "ipa_dyndns_update", "dyndns_update");

        ret = dp_opt_set_bool(ctx->dyndns_ctx->opts,
                              DP_OPT_DYNDNS_UPDATE, update);
        talloc_free(val);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set option value\n");
            return ret;
        }
    }

    ret = confdb_get_int(be_ctx->cdb, be_ctx->conf_path,
                         "ipa_dyndns_ttl", -1, &ttl);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get the value of %s\n",
              "ipa_dyndns_ttl");
        /* Not fatal */
    } else if (ret == EOK && ttl != -1) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Deprecation warning: The option %s is "
              "deprecated and should not be used in favor of %s\n",
              "ipa_dyndns_ttl", "dyndns_ttl");

        ret = dp_opt_set_int(ctx->dyndns_ctx->opts, DP_OPT_DYNDNS_TTL, ttl);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set option value\n");
            return ret;
        }
    }

    /* Reuse legacy option values */
    ret = confdb_get_string(be_ctx->cdb, ctx, be_ctx->conf_path,
                            "ipa_dyndns_iface", NULL, &val);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get the value of %s\n",
              "ipa_dyndns_iface");
        /* Not fatal */
    } else if (ret == EOK && val) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Deprecation warning: The option %s is "
              "deprecated and should not be used in favor of %s\n",
              "ipa_dyndns_iface", "dyndns_iface");

        ret = dp_opt_set_string(ctx->dyndns_ctx->opts,
                                DP_OPT_DYNDNS_IFACE, val);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set option value\n");
            return ret;
        }
    }

    return EOK;
}

errno_t ipa_get_host_attrs(struct dp_option *ipa_options,
                           size_t host_count,
                           struct sysdb_attrs **hosts,
                           struct sysdb_attrs **_ipa_host)
{
    const char *ipa_hostname;
    const char *hostname;
    errno_t ret;

    *_ipa_host = NULL;
    ipa_hostname = dp_opt_get_cstring(ipa_options, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing ipa_hostname, this should never happen.\n");
        ret = EINVAL;
        goto done;
    }

    for (size_t i = 0; i < host_count; i++) {
        ret = sysdb_attrs_get_string(hosts[i], SYSDB_FQDN, &hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not locate IPA host\n");
            goto done;
        }

        if (strcasecmp(hostname, ipa_hostname) == 0) {
            *_ipa_host = hosts[i];
            break;
        }
    }

    if (*_ipa_host == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not locate IPA host\n");
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    return ret;
}
