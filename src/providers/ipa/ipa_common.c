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

#include "db/sysdb_selinux.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ldap/sdap_async_private.h"
#include "util/sss_krb5.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"

#include "providers/ipa/ipa_opts.h"

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
    int i;
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
        DEBUG(1, ("No ipa server set, will use service discovery!\n"));
    }

    ipa_hostname = dp_opt_get_string(opts->basic, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        ret = gethostname(hostname, HOST_NAME_MAX);
        if (ret != EOK) {
            DEBUG(1, ("gethostname failed [%d][%s].\n", errno,
                      strerror(errno)));
            ret = errno;
            goto done;
        }
        hostname[HOST_NAME_MAX] = '\0';
        DEBUG(9, ("Setting ipa_hostname to [%s].\n", hostname));
        ret = dp_opt_set_string(opts->basic, IPA_HOSTNAME, hostname);
        if (ret != EOK) {
            goto done;
        }
    }

    /* First check whether the realm has been manually specified */
    realm = dp_opt_get_string(opts->basic, IPA_KRB5_REALM);
    if (!realm) {
        /* No explicit krb5_realm, use the IPA domain */
        realm = talloc_strdup(opts, domain);
        if (!realm) {
            ret = ENOMEM;
            goto done;
        }

        /* Use the upper-case IPA domain for the kerberos realm */
        for (i = 0; realm[i]; i++) {
            realm[i] = toupper(realm[i]);
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
    case IPA_HOST_SEARCH_BASE:
        class_name = "IPA_HOST";
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
    default:
        DEBUG(SSSDBG_CONF_SETTINGS,
              ("Unknown search base type: [%d]\n", class));
        class_name = "UNKNOWN";
        /* Non-fatal */
        break;
    }

    unparsed_base = dp_opt_get_string(opts, class);
    if (!unparsed_base || unparsed_base[0] == '\0') return ENOENT;

    return common_parse_search_base(mem_ctx, unparsed_base,
                                    class_name, NULL,
                                    _search_bases);
}

int ipa_get_id_options(struct ipa_options *ipa_opts,
                       struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct sdap_options **_opts)
{
    TALLOC_CTX *tmpctx;
    char *primary;
    char *basedn;
    char *realm;
    char *value;
    char *desired_realm;
    char *desired_primary;
    bool primary_requested = true;
    bool realm_requested = true;
    int ret;
    int i;

    tmpctx = talloc_new(ipa_opts);
    if (!tmpctx) {
        return ENOMEM;
    }

    ipa_opts->id = talloc_zero(ipa_opts, struct sdap_options);
    if (!ipa_opts->id) {
        ret = ENOMEM;
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

        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic, SDAP_SEARCH_BASE)));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ipa_opts->id->basic,
                                 SDAP_SEARCH_BASE,
                                 &ipa_opts->id->search_bases);
    if (ret != EOK) goto done;

    /* set krb realm */
    if (NULL == dp_opt_get_string(ipa_opts->id->basic, SDAP_KRB5_REALM)) {
        realm = dp_opt_get_string(ipa_opts->basic, IPA_KRB5_REALM);
        value = talloc_strdup(tmpctx, realm);
        if (value == NULL) {
            DEBUG(1, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_KRB5_REALM, value);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_KRB5_REALM].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic, SDAP_KRB5_REALM)));
    }

    /* Configuration of SASL auth ID and realm */
    desired_primary = dp_opt_get_string(ipa_opts->id->basic, SDAP_SASL_AUTHID);
    if (!desired_primary) {
        primary_requested = false;
        desired_primary = dp_opt_get_string(ipa_opts->id->basic, IPA_HOSTNAME);
    }
    desired_realm = dp_opt_get_string(ipa_opts->id->basic, SDAP_SASL_REALM);
    if (!desired_realm) {
        realm_requested = false;
        desired_realm = dp_opt_get_string(ipa_opts->id->basic, SDAP_KRB5_REALM);
    }

    ret = select_principal_from_keytab(tmpctx,
                                       desired_primary, desired_realm,
                                       dp_opt_get_string(ipa_opts->id->basic,
                                                         SDAP_KRB5_KEYTAB),
                                       NULL, &primary, &realm);
    if (ret != EOK) {
        goto done;
    }

    if ((primary_requested && strcmp(desired_primary, primary) != 0) ||
        (realm_requested && strcmp(desired_realm, realm) != 0)) {
        DEBUG(1, ("Configured SASL auth ID/realm not found in keytab.\n"));
        ret = ENOENT;
        goto done;
    }

    ret = dp_opt_set_string(ipa_opts->id->basic,
                            SDAP_SASL_AUTHID, primary);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(6, ("Option %s set to %s\n",
              ipa_opts->id->basic[SDAP_SASL_AUTHID].opt_name,
              dp_opt_get_string(ipa_opts->id->basic, SDAP_SASL_AUTHID)));

    ret = dp_opt_set_string(ipa_opts->id->basic,
                            SDAP_SASL_REALM, realm);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(6, ("Option %s set to %s\n",
              ipa_opts->id->basic[SDAP_SASL_REALM].opt_name,
              dp_opt_get_string(ipa_opts->id->basic, SDAP_SASL_REALM)));

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

        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_USER_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_USER_SEARCH_BASE)));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ipa_opts->id->basic,
                                 SDAP_USER_SEARCH_BASE,
                                 &ipa_opts->id->user_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_GROUP_SEARCH_BASE)) {
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_GROUP_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }

        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_GROUP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_GROUP_SEARCH_BASE)));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ipa_opts->id->basic,
                                 SDAP_GROUP_SEARCH_BASE,
                                 &ipa_opts->id->group_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_SUDO_SEARCH_BASE)) {
#if 0
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_SUDO_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }
#else
        /* We don't yet have support for the representation
         * of sudo in IPA. For now, we need to point at the
         * compat tree
         */
        value = talloc_asprintf(tmpctx, "ou=SUDOers,%s", basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_SUDO_SEARCH_BASE,
                                 value);
        if (ret != EOK) {
            goto done;
        }
#endif

        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_SUDO_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_SUDO_SEARCH_BASE)));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ipa_opts->id->basic,
                                 SDAP_SUDO_SEARCH_BASE,
                                 &ipa_opts->id->sudo_search_bases);
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

        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_NETGROUP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_NETGROUP_SEARCH_BASE)));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ipa_opts->id->basic,
                                 SDAP_NETGROUP_SEARCH_BASE,
                                 &ipa_opts->id->netgroup_search_bases);
    if (ret != EOK) goto done;

    if (NULL == dp_opt_get_string(ipa_opts->basic,
                                  IPA_HOST_SEARCH_BASE)) {
        ret = dp_opt_set_string(ipa_opts->basic, IPA_HOST_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, ("Option %s set to %s\n",
                  ipa_opts->basic[IPA_HOST_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_HOST_SEARCH_BASE)));
    }
    ret = ipa_parse_search_base(ipa_opts->basic, ipa_opts->basic,
                                IPA_HOST_SEARCH_BASE,
                                &ipa_opts->host_search_bases);
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

        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->basic[IPA_HBAC_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_HBAC_SEARCH_BASE)));
    }
    ret = ipa_parse_search_base(ipa_opts->basic, ipa_opts->basic,
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

        DEBUG(SSSDBG_CONF_SETTINGS, ("Option %s set to %s\n",
                  ipa_opts->basic[IPA_SELINUX_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_SELINUX_SEARCH_BASE)));
    }
    ret = ipa_parse_search_base(ipa_opts->basic, ipa_opts->basic,
                                IPA_SELINUX_SEARCH_BASE,
                                &ipa_opts->selinux_search_bases);
    if (ret != EOK) goto done;

    value = dp_opt_get_string(ipa_opts->id->basic, SDAP_DEREF);
    if (value != NULL) {
        ret = deref_string_to_val(value, &i);
        if (ret != EOK) {
            DEBUG(1, ("Failed to verify ldap_deref option.\n"));
            goto done;
        }
    }

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_SERVICE_SEARCH_BASE)) {
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_SERVICE_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }

        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_GROUP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_GROUP_SEARCH_BASE)));
    }
    ret = sdap_parse_search_base(ipa_opts->id, ipa_opts->id->basic,
                                 SDAP_SERVICE_SEARCH_BASE,
                                 &ipa_opts->id->service_search_bases);
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

        DEBUG(SSSDBG_CONF_SETTINGS, ("Option %s set to %s\n",
                  ipa_opts->basic[IPA_SUBDOMAINS_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_SUBDOMAINS_SEARCH_BASE)));
    }
    ret = ipa_parse_search_base(ipa_opts, ipa_opts->basic,
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

        DEBUG(SSSDBG_CONF_SETTINGS, ("Option %s set to %s\n",
                  ipa_opts->basic[IPA_MASTER_DOMAIN_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_MASTER_DOMAIN_SEARCH_BASE)));
    }
    ret = ipa_parse_search_base(ipa_opts, ipa_opts->basic,
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

        DEBUG(SSSDBG_CONF_SETTINGS, ("Option %s set to %s\n",
                  ipa_opts->basic[IPA_RANGES_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->basic,
                                    IPA_RANGES_SEARCH_BASE)));
    }
    ret = ipa_parse_search_base(ipa_opts, ipa_opts->basic,
                                IPA_RANGES_SEARCH_BASE,
                                &ipa_opts->ranges_search_bases);
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
                       IPA_OPTS_HOST,
                       &ipa_opts->host_map);
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
        DEBUG(1, ("sss_krb5_try_kdcip failed.\n"));
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
            DEBUG(1, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->auth, KRB5_REALM, copy);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->auth[KRB5_REALM].opt_name,
                  dp_opt_get_string(ipa_opts->auth, KRB5_REALM)));
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
    struct sockaddr_storage *sockaddr;
    char *address;
    const char *safe_address;
    char *new_uri;
    const char *srv_name;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed\n"));
        return;
    }

    service = talloc_get_type(private_data, struct ipa_service);
    if (!service) {
        DEBUG(1, ("FATAL: Bad private_data\n"));
        talloc_free(tmp_ctx);
        return;
    }

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(1, ("FATAL: No hostent available for server (%s)\n",
                  fo_get_server_str_name(server)));
        talloc_free(tmp_ctx);
        return;
    }

    sockaddr = resolv_get_sockaddr_address(tmp_ctx, srvaddr, LDAP_PORT);
    if (sockaddr == NULL) {
        DEBUG(1, ("resolv_get_sockaddr_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    address = resolv_get_string_address(tmp_ctx, srvaddr);
    if (address == NULL) {
        DEBUG(1, ("resolv_get_string_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    srv_name = fo_get_server_name(server);
    if (srv_name == NULL) {
        DEBUG(1, ("Could not get server host name\n"));
        talloc_free(tmp_ctx);
        return;
    }

    new_uri = talloc_asprintf(service, "ldap://%s", srv_name);
    if (!new_uri) {
        DEBUG(2, ("Failed to copy URI ...\n"));
        talloc_free(tmp_ctx);
        return;
    }
    DEBUG(6, ("Constructed uri '%s'\n", new_uri));

    /* free old one and replace with new one */
    talloc_zfree(service->sdap->uri);
    service->sdap->uri = new_uri;
    talloc_zfree(service->sdap->sockaddr);
    service->sdap->sockaddr = talloc_steal(service, sockaddr);

    safe_address = sss_escape_ip_address(tmp_ctx,
                                         srvaddr->family,
                                         address);
    if (safe_address == NULL) {
        DEBUG(1, ("sss_escape_ip_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    ret = write_krb5info_file(service->krb5_service->realm, safe_address,
                              SSS_KRB5KDC_FO_SRV);
    if (ret != EOK) {
        DEBUG(2, ("write_krb5info_file failed, authentication might fail.\n"));
    }

    talloc_free(tmp_ctx);
}

errno_t ipa_servers_init(struct be_ctx *ctx,
                         struct ipa_service *service,
                         struct ipa_options *options,
                         const char *servers,
                         bool primary)
{
    TALLOC_CTX *tmp_ctx;
    char **list = NULL;
    char *ipa_domain;
    int ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* split server parm into a list */
    ret = split_on_separator(tmp_ctx, servers, ',', true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to parse server list!\n"));
        goto done;
    }

    /* now for each one add a new server to the failover service */
    for (i = 0; list[i]; i++) {

        talloc_steal(service, list[i]);

        if (be_fo_is_srv_identifier(list[i])) {
            ipa_domain = dp_opt_get_string(options->basic, IPA_DOMAIN);
            ret = be_fo_add_srv_server(ctx, "IPA", "ldap", ipa_domain,
                                       BE_FO_PROTO_TCP, false, NULL);
            if (ret) {
                DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add server\n"));
                goto done;
            }

            DEBUG(SSSDBG_TRACE_FUNC, ("Added service lookup for service IPA\n"));
            continue;
        }

        ret = be_fo_add_server(ctx, "IPA", list[i], 0, NULL, primary);
        if (ret && ret != EEXIST) {
            DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add server\n"));
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, ("Added Server %s\n", list[i]));
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

int ipa_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                     const char *primary_servers,
                     const char *backup_servers,
                     struct ipa_options *options,
                     struct ipa_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct ipa_service *service;
    char *realm;
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
    service->krb5_service = talloc_zero(service, struct krb5_service);
    if (!service->krb5_service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(ctx, "IPA");
    if (ret != EOK) {
        DEBUG(1, ("Failed to create failover service!\n"));
        goto done;
    }

    service->sdap->name = talloc_strdup(service, "IPA");
    if (!service->sdap->name) {
        ret = ENOMEM;
        goto done;
    }

    service->krb5_service->name = talloc_strdup(service, "IPA");
    if (!service->krb5_service->name) {
        ret = ENOMEM;
        goto done;
    }
    service->sdap->kinit_service_name = service->krb5_service->name;

    realm = dp_opt_get_string(options->basic, IPA_KRB5_REALM);
    if (!realm) {
        DEBUG(1, ("No Kerberos realm set\n"));
        ret = EINVAL;
        goto done;
    }
    service->krb5_service->realm =
        talloc_strdup(service->krb5_service, realm);
    if (!service->krb5_service->realm) {
        ret = ENOMEM;
        goto done;
    }

    if (!primary_servers) {
        if (backup_servers) {
            DEBUG(SSSDBG_CONF_SETTINGS, ("Missing primary IPA server but "
                                         "backup server given - using it as primary!\n"));
            primary_servers = backup_servers;
            backup_servers = NULL;
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS, ("Missing primary and backup IPA "
                                         "servers - using service discovery!\n"));
            primary_servers = BE_SRV_IDENTIFIER;
        }
    }

    ret = ipa_servers_init(ctx, service, options, primary_servers, true);
    if (ret != EOK) {
        goto done;
    }

    if (backup_servers) {
        ret = ipa_servers_init(ctx, service, options, backup_servers, false);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = be_fo_service_add_callback(memctx, ctx, "IPA",
                                     ipa_resolve_callback, service);
    if (ret != EOK) {
        DEBUG(1, ("Failed to add failover callback!\n"));
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

        DEBUG(SSSDBG_TRACE_LIBS, ("Option %s set to %s\n",
              ipa_opts->id->basic[SDAP_AUTOFS_SEARCH_BASE].opt_name,
              dp_opt_get_string(ipa_opts->id->basic,
                                SDAP_AUTOFS_SEARCH_BASE)));
    }

    ret = sdap_parse_search_base(ipa_opts->id, ipa_opts->id->basic,
                                 SDAP_AUTOFS_SEARCH_BASE,
                                 &ipa_opts->id->autofs_search_bases);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not parse autofs search base\n"));
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id, cdb, conf_path,
                       ipa_autofs_mobject_map,
                       SDAP_OPTS_AUTOFS_MAP,
                       &ipa_opts->id->autofs_mobject_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not get autofs map object attribute map\n"));
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id, cdb, conf_path,
                       ipa_autofs_entry_map,
                       SDAP_OPTS_AUTOFS_ENTRY,
                       &ipa_opts->id->autofs_entry_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not get autofs entry object attribute map\n"));
        goto done;
    }

    *_opts = ipa_opts->id;
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}
