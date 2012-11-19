/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "providers/ad/ad_common.h"
#include "providers/ad/ad_opts.h"

errno_t
ad_get_common_options(TALLOC_CTX *mem_ctx,
                      struct confdb_ctx *cdb,
                      const char *conf_path,
                      struct sss_domain_info *dom,
                      struct ad_options **_opts)
{
    errno_t ret;
    int gret;
    struct ad_options *opts = NULL;
    char *domain;
    char *server;
    char *realm;
    char *ad_hostname;
    char hostname[HOST_NAME_MAX + 1];

    opts = talloc_zero(mem_ctx, struct ad_options);
    if (!opts) return ENOMEM;

    ret = dp_get_options(opts, cdb, conf_path,
                         ad_basic_opts,
                         AD_OPTS_BASIC,
                         &opts->basic);
    if (ret != EOK) {
        goto done;
    }

    /* If the AD domain name wasn't explicitly set, assume that it
     * matches the SSSD domain name
     */
    domain = dp_opt_get_string(opts->basic, AD_DOMAIN);
    if (!domain) {
        ret = dp_opt_set_string(opts->basic, AD_DOMAIN, dom->name);
        if (ret != EOK) {
            goto done;
        }
        domain = dom->name;
    }

    /* Did we get an explicit server name, or are we discovering it? */
    server = dp_opt_get_string(opts->basic, AD_SERVER);
    if (!server) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              ("No AD server set, will use service discovery!\n"));
    }

    /* Set the machine's hostname to the local host name if it
     * wasn't explicitly specified.
     */
    ad_hostname = dp_opt_get_string(opts->basic, AD_HOSTNAME);
    if (ad_hostname == NULL) {
        gret = gethostname(hostname, HOST_NAME_MAX);
        if (gret != 0) {
            ret = errno;
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("gethostname failed [%s].\n",
                   strerror(ret)));
            goto done;
        }
        hostname[HOST_NAME_MAX] = '\0';
        DEBUG(SSSDBG_CONF_SETTINGS,
              ("Setting ad_hostname to [%s].\n", hostname));
        ret = dp_opt_set_string(opts->basic, AD_HOSTNAME, hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("Setting ad_hostname failed [%s].\n",
                   strerror(ret)));
            goto done;
        }
    }


    /* Always use the upper-case AD domain for the kerberos realm */
    realm = get_uppercase_realm(opts, domain);
    if (!realm) {
        ret = ENOMEM;
        goto done;
    }

    ret = dp_opt_set_string(opts->basic, AD_KRB5_REALM, realm);
    if (ret != EOK) {
        goto done;
    }

    /* Active Directory is always case-insensitive */
    dom->case_sensitive = false;

    /* Set this in the confdb so that the responders pick it
     * up when they start up.
     */
    ret = confdb_set_bool(cdb, conf_path, "case_sensitive",
                          dom->case_sensitive);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not set domain case-sensitive: [%s]\n",
               strerror(ret)));
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          ("Setting domain case-insensitive\n"));

    ret = EOK;
    *_opts = opts;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }
    return ret;
}

static void
ad_resolve_callback(void *private_data, struct fo_server *server);

static errno_t
ad_servers_init(TALLOC_CTX *mem_ctx,
                struct be_ctx *bectx,
                const char *servers,
                struct ad_options *options,
                bool primary)
{
    size_t i;
    errno_t ret = 0;
    char **list;
    char *ad_domain;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Split the server list */
    ret = split_on_separator(tmp_ctx, servers, ',', true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to parse server list!\n"));
        goto done;
    }

    ad_domain = dp_opt_get_string(options->basic, AD_DOMAIN);

    /* Add each of these servers to the failover service */
    for (i = 0; list[i]; i++) {
        if (be_fo_is_srv_identifier(list[i])) {
            if (!primary) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Failed to add server [%s] to failover service: "
                       "SRV resolution only allowed for primary servers!\n",
                       list[i]));
                continue;
            }

            ret = be_fo_add_srv_server(bectx, AD_SERVICE_NAME, "ldap",
                                       ad_domain, BE_FO_PROTO_TCP,
                                       false, NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      ("Failed to add service discovery to failover: [%s]",
                       strerror(ret)));
                goto done;
            }

            DEBUG(SSSDBG_CONF_SETTINGS, ("Added service discovery for AD\n"));
            continue;
        }

        /* It could be ipv6 address in square brackets. Remove
         * the brackets if needed. */
        ret = remove_ipv6_brackets(list[i]);
        if (ret != EOK) {
            goto done;
        }

        ret = be_fo_add_server(bectx, AD_SERVICE_NAME, list[i], 0, NULL, primary);
        if (ret && ret != EEXIST) {
            DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add server\n"));
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, ("Added failover server %s\n", list[i]));
    }
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int ad_user_data_cmp(void *ud1, void *ud2)
{
    return strcasecmp((char*) ud1, (char*) ud2);
}

errno_t
ad_failover_init(TALLOC_CTX *mem_ctx, struct be_ctx *bectx,
                 const char *primary_servers,
                 const char *backup_servers,
                 struct ad_options *options,
                 struct ad_service **_service)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ad_service *service;
    char *realm;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    service = talloc_zero(tmp_ctx, struct ad_service);
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

    ret = be_fo_add_service(bectx, AD_SERVICE_NAME, ad_user_data_cmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to create failover service!\n"));
        goto done;
    }

    service->sdap->name = talloc_strdup(service, AD_SERVICE_NAME);
    if (!service->sdap->name) {
        ret = ENOMEM;
        goto done;
    }

    service->krb5_service->name = talloc_strdup(service, AD_SERVICE_NAME);
    if (!service->krb5_service->name) {
        ret = ENOMEM;
        goto done;
    }
    service->sdap->kinit_service_name = service->krb5_service->name;

    realm = dp_opt_get_string(options->basic, AD_KRB5_REALM);
    if (!realm) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No Kerberos realm set\n"));
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
        DEBUG(SSSDBG_CONF_SETTINGS,
              ("No primary servers defined, using service discovery\n"));
        primary_servers = BE_SRV_IDENTIFIER;
    }

    ret = ad_servers_init(mem_ctx, bectx, primary_servers, options, true);
    if (ret != EOK) {
        goto done;
    }

    if (backup_servers) {
        ret = ad_servers_init(mem_ctx, bectx, backup_servers, options, false);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = be_fo_service_add_callback(mem_ctx, bectx, AD_SERVICE_NAME,
                                     ad_resolve_callback, service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Failed to add failover callback! [%s]\n", strerror(ret)));
        goto done;
    }

    *_service = talloc_steal(mem_ctx, service);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void
ad_resolve_callback(void *private_data, struct fo_server *server)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ad_service *service;
    struct resolv_hostent *srvaddr;
    struct sockaddr_storage *sockaddr;
    char *address;
    const char *safe_address;
    char *new_uri;
    const char *srv_name;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
        return;
    }

    service = talloc_get_type(private_data, struct ad_service);
    if (!service) {
        ret = EINVAL;
        goto done;
    }

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("No hostent available for server (%s)\n",
               fo_get_server_str_name(server)));
        ret = EINVAL;
        goto done;
    }

    sockaddr = resolv_get_sockaddr_address(tmp_ctx, srvaddr, LDAP_PORT);
    if (sockaddr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("resolv_get_sockaddr_address failed.\n"));
        ret = EIO;
        goto done;
    }

    address = resolv_get_string_address(tmp_ctx, srvaddr);
    if (address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("resolv_get_string_address failed.\n"));
        ret = EIO;
        goto done;
    }

    srv_name = fo_get_server_name(server);
    if (srv_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not get server host name\n"));
        ret = EINVAL;
        goto done;
    }

    new_uri = talloc_asprintf(service, "ldap://%s", srv_name);
    if (!new_uri) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to copy URI\n"));
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_CONF_SETTINGS, ("Constructed uri '%s'\n", new_uri));

    /* free old one and replace with new one */
    talloc_zfree(service->sdap->uri);
    service->sdap->uri = new_uri;
    talloc_zfree(service->sdap->sockaddr);
    service->sdap->sockaddr = talloc_steal(service, sockaddr);

    safe_address = sss_escape_ip_address(tmp_ctx,
                                         srvaddr->family,
                                         address);
    if (safe_address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sss_escape_ip_address failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = write_krb5info_file(service->krb5_service->realm, safe_address,
                              SSS_KRB5KDC_FO_SRV);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("write_krb5info_file failed, authentication might fail.\n"));
    }

    ret = EOK;
done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error: [%s]\n", strerror(ret)));
    }
    talloc_free(tmp_ctx);
    return;
}

errno_t
ad_set_search_bases(struct sdap_options *id_opts);

errno_t
ad_get_id_options(struct ad_options *ad_opts,
                   struct confdb_ctx *cdb,
                   const char *conf_path,
                   struct sdap_options **_opts)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct sdap_options *id_opts;
    char *krb5_realm;
    char *keytab_path;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    id_opts = talloc_zero(tmp_ctx, struct sdap_options);
    if (!id_opts) {
        ret = ENOMEM;
        goto done;
    }

    ret = dp_get_options(id_opts, cdb, conf_path,
                         ad_def_ldap_opts,
                         SDAP_OPTS_BASIC,
                         &id_opts->basic);
    if (ret != EOK) {
        goto done;
    }

    /* Set up search bases if they were assigned explicitly */
    ret = ad_set_search_bases(id_opts);
    if (ret != EOK) goto done;

    /* We only support Kerberos password policy with AD, so
     * force that on.
     */
    ret = dp_opt_set_string(id_opts->basic,
                            SDAP_PWD_POLICY,
                            PWD_POL_OPT_MIT);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Could not set password policy\n"));
        goto done;
    }

    /* Set the Kerberos Realm for GSSAPI */
    krb5_realm = dp_opt_get_string(ad_opts->basic, AD_KRB5_REALM);
    if (!krb5_realm) {
        /* Should be impossible, this is set in ad_get_common_options() */
        DEBUG(SSSDBG_FATAL_FAILURE, ("No Kerberos realm\n"));
        ret = EINVAL;
        goto done;
    }

    ret = dp_opt_set_string(id_opts->basic, SDAP_KRB5_REALM, krb5_realm);
    if (ret != EOK) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS,
          ("Option %s set to %s\n",
           id_opts->basic[SDAP_KRB5_REALM].opt_name,
           krb5_realm));

    keytab_path = dp_opt_get_string(ad_opts->basic, AD_KEYTAB);
    if (keytab_path) {
        ret = dp_opt_set_string(id_opts->basic, SDAP_KRB5_KEYTAB,
                                keytab_path);
        if (ret != EOK) goto done;
        DEBUG(SSSDBG_CONF_SETTINGS,
              ("Option %s set to %s\n",
               id_opts->basic[SDAP_KRB5_KEYTAB].opt_name,
               keytab_path));
    }

    ret = sdap_set_sasl_options(id_opts,
                                dp_opt_get_string(ad_opts->basic,
                                                  AD_HOSTNAME),
                                dp_opt_get_string(ad_opts->basic,
                                                  AD_KRB5_REALM),
                                keytab_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot set the SASL-related options\n"));
        goto done;
    }

    /* fix schema to AD  */
    id_opts->schema_type = SDAP_SCHEMA_AD;

    /* Get sdap option maps */

    /* General Attribute Map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_2008r2_attr_map,
                       SDAP_AT_GENERAL,
                       &id_opts->gen_map);
    if (ret != EOK) {
        goto done;
    }

    /* User map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_2008r2_user_map,
                       SDAP_OPTS_USER,
                       &id_opts->user_map);
    if (ret != EOK) {
        goto done;
    }

    /* Group map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_2008r2_group_map,
                       SDAP_OPTS_GROUP,
                       &id_opts->group_map);
    if (ret != EOK) {
        goto done;
    }

    /* Netgroup map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_netgroup_map,
                       SDAP_OPTS_NETGROUP,
                       &id_opts->netgroup_map);
    if (ret != EOK) {
        goto done;
    }

    /* Services map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_service_map,
                       SDAP_OPTS_SERVICES,
                       &id_opts->service_map);
    if (ret != EOK) {
        goto done;
    }

    ad_opts->id = talloc_steal(ad_opts, id_opts);
    *_opts = id_opts;
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ad_set_search_bases(struct sdap_options *id_opts)
{
    errno_t ret;
    char *default_search_base;
    size_t o;
    const int search_base_options[] = { SDAP_USER_SEARCH_BASE,
                                        SDAP_GROUP_SEARCH_BASE,
                                        SDAP_NETGROUP_SEARCH_BASE,
                                        SDAP_SERVICE_SEARCH_BASE,
                                        -1 };

    /* AD servers provide defaultNamingContext, so we will
     * rely on that to specify the search base unless it has
     * been specifically overridden.
     */

    default_search_base =
            dp_opt_get_string(id_opts->basic, SDAP_SEARCH_BASE);

    if (default_search_base) {
        /* set search bases if they are not */
        for (o = 0; search_base_options[o] != -1; o++) {
            if (NULL == dp_opt_get_string(id_opts->basic,
                                          search_base_options[o])) {
                ret = dp_opt_set_string(id_opts->basic,
                                        search_base_options[o],
                                        default_search_base);
                if (ret != EOK) {
                    goto done;
                }
                DEBUG(SSSDBG_CONF_SETTINGS,
                      ("Option %s set to %s\n",
                       id_opts->basic[search_base_options[o]].opt_name,
                       dp_opt_get_string(id_opts->basic,
                                         search_base_options[o])));
            }
        }
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS,
              ("Search base not set. SSSD will attempt to discover it later, "
               "when connecting to the LDAP server.\n"));
    }

    /* Default search */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_SEARCH_BASE,
                                 &id_opts->search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* User search */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_USER_SEARCH_BASE,
                                 &id_opts->user_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Group search base */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_GROUP_SEARCH_BASE,
                                 &id_opts->group_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Netgroup search */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_NETGROUP_SEARCH_BASE,
                                 &id_opts->netgroup_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Service search */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_SERVICE_SEARCH_BASE,
                                 &id_opts->service_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    ret = EOK;
done:
    return ret;
}

errno_t
ad_get_auth_options(TALLOC_CTX *mem_ctx,
                    struct ad_options *ad_opts,
                    struct be_ctx *bectx,
                    struct dp_option **_opts)
{
    errno_t ret;
    struct dp_option *krb5_options;
    const char *ad_servers;
    const char *krb5_realm;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Get krb5 options */
    ret = dp_get_options(tmp_ctx, bectx->cdb, bectx->conf_path,
                         ad_def_krb5_opts, KRB5_OPTS,
                         &krb5_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not read Kerberos options from the configuration\n"));
        goto done;
    }

    ad_servers = dp_opt_get_string(ad_opts->basic, AD_SERVER);

    /* Force the krb5_servers to match the ad_servers */
    ret = dp_opt_set_string(krb5_options, KRB5_KDC, ad_servers);
    if (ret != EOK) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS,
          ("Option %s set to %s\n",
           krb5_options[KRB5_KDC].opt_name,
           ad_servers));

    /* Set krb5 realm */
    /* Set the Kerberos Realm for GSSAPI */
    krb5_realm = dp_opt_get_string(ad_opts->basic, AD_KRB5_REALM);
    if (!krb5_realm) {
        /* Should be impossible, this is set in ad_get_common_options() */
        DEBUG(SSSDBG_FATAL_FAILURE, ("No Kerberos realm\n"));
        ret = EINVAL;
        goto done;
    }

    /* Force the kerberos realm to match the AD_KRB5_REALM (which may have
     * been upper-cased in ad_common_options()
     */
    ret = dp_opt_set_string(krb5_options, KRB5_REALM, krb5_realm);
    if (ret != EOK) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS,
          ("Option %s set to %s\n",
           krb5_options[KRB5_REALM].opt_name,
           krb5_realm));

    *_opts = talloc_steal(mem_ctx, krb5_options);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
