/*
    SSSD

    LDAP Provider Common Functions

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2008-2010 Red Hat

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

#include "providers/ldap/ldap_common.h"
#include "providers/fail_over.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/krb5/krb5_common.h"
#include "db/sysdb_sudo.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"

#include "util/sss_krb5.h"
#include "util/crypto/sss_crypto.h"

#include "providers/ldap/sdap_idmap.h"

errno_t ldap_id_setup_tasks(struct sdap_id_ctx *ctx)
{
    return sdap_id_setup_tasks(ctx->be, ctx, ctx->opts->sdom,
                               ldap_id_enumeration_send,
                               ldap_id_enumeration_recv,
                               ctx);
}

errno_t sdap_id_setup_tasks(struct be_ctx *be_ctx,
                            struct sdap_id_ctx *ctx,
                            struct sdap_domain *sdom,
                            be_ptask_send_t send_fn,
                            be_ptask_recv_t recv_fn,
                            void *pvt)
{
    int ret;

    /* set up enumeration task */
    if (sdom->dom->enumerate) {
        DEBUG(SSSDBG_TRACE_FUNC, "Setting up enumeration for %s\n",
                                  sdom->dom->name);
        ret = ldap_id_setup_enumeration(be_ctx, ctx, sdom,
                                        send_fn, recv_fn, pvt);
    } else {
        /* the enumeration task, runs the cleanup process by itself,
         * but if enumeration is not running we need to schedule it */
        DEBUG(SSSDBG_TRACE_FUNC, "Setting up cleanup task for %s\n",
                                  sdom->dom->name);
        ret = ldap_id_setup_cleanup(ctx, sdom);
    }

    return ret;
}

static void sdap_uri_callback(void *private_data, struct fo_server *server)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sdap_service *service;
    struct resolv_hostent *srvaddr;
    struct sockaddr *sockaddr;
    const char *tmp;
    const char *srv_name;
    char *new_uri;
    socklen_t sockaddr_len;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed\n");
        return;
    }

    service = talloc_get_type(private_data, struct sdap_service);
    if (!service) {
        talloc_free(tmp_ctx);
        return;
    }

    tmp = (const char *)fo_get_server_user_data(server);

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "FATAL: No hostent available for server (%s)\n",
                  fo_get_server_str_name(server));
        talloc_free(tmp_ctx);
        return;
    }

    sockaddr = resolv_get_sockaddr_address(tmp_ctx, srvaddr,
                                           fo_get_server_port(server),
                                           &sockaddr_len);
    if (sockaddr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "resolv_get_sockaddr_address failed.\n");
        talloc_free(tmp_ctx);
        return;
    }

    if (fo_is_srv_lookup(server)) {
        if (!tmp) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknown service, using ldap\n");
            tmp = SSS_LDAP_SRV_NAME;
        }

        srv_name = fo_get_server_name(server);
        if (srv_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not get server host name\n");
            talloc_free(tmp_ctx);
            return;
        }

        new_uri = talloc_asprintf(service, "%s://%s:%d",
                                  tmp, srv_name,
                                  fo_get_server_port(server));
    } else {
        new_uri = talloc_strdup(service, tmp);
    }

    if (!new_uri) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy URI ...\n");
        talloc_free(tmp_ctx);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Constructed uri '%s'\n", new_uri);

    /* free old one and replace with new one */
    talloc_zfree(service->uri);
    service->uri = new_uri;
    talloc_zfree(service->sockaddr);
    service->sockaddr = talloc_steal(service, sockaddr);
    service->sockaddr_len = sockaddr_len;
    talloc_free(tmp_ctx);
}

errno_t sdap_select_principal_from_keytab_sync(TALLOC_CTX *mem_ctx,
                                               const char *princ_str,
                                               const char *realm_str,
                                               const char *keytab_name,
                                               char **sasl_primary,
                                               char **sasl_realm);

errno_t
sdap_set_sasl_options(struct sdap_options *id_opts,
                      char *default_primary,
                      char *default_realm,
                      const char *keytab_path)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *sasl_primary;
    char *desired_primary;
    char *primary_realm;
    char *sasl_realm;
    char *desired_realm;
    bool primary_requested = true;
    bool realm_requested = true;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Configuration of SASL auth ID and realm */
    desired_primary = dp_opt_get_string(id_opts->basic, SDAP_SASL_AUTHID);
    if (!desired_primary) {
        primary_requested = false;
        desired_primary = default_primary;
    }

    if ((primary_realm = strchr(desired_primary, '@'))) {
        *primary_realm = '\0';
        desired_realm = primary_realm+1;
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "authid contains realm [%s]\n", desired_realm);
    } else {
        desired_realm = dp_opt_get_string(id_opts->basic, SDAP_SASL_REALM);
        if (!desired_realm) {
            realm_requested = false;
            desired_realm = default_realm;
        }
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Will look for %s@%s in %s\n",
          desired_primary, desired_realm,
          keytab_path ? keytab_path : "default keytab");

    ret = sdap_select_principal_from_keytab_sync(tmp_ctx,
                                                 desired_primary, desired_realm,
                                                 keytab_path,
                                                 &sasl_primary, &sasl_realm);
    if (ret != EOK) {
        goto done;
    }

    if (primary_requested && strcmp(desired_primary, sasl_primary) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
               "Configured SASL auth ID not found in keytab. "
                "Requested %s, found %s\n", desired_primary, sasl_primary);
    }

    if (realm_requested && strcmp(desired_realm, sasl_realm) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
               "Configured SASL realm not found in keytab. "
                "Requested %s, found %s\n", desired_realm, sasl_realm);
    }

    ret = dp_opt_set_string(id_opts->basic,
                            SDAP_SASL_AUTHID, sasl_primary);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
          id_opts->basic[SDAP_SASL_AUTHID].opt_name,
          dp_opt_get_string(id_opts->basic, SDAP_SASL_AUTHID));

    ret = dp_opt_set_string(id_opts->basic,
                            SDAP_SASL_REALM, sasl_realm);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
          id_opts->basic[SDAP_SASL_REALM].opt_name,
          dp_opt_get_string(id_opts->basic, SDAP_SASL_REALM));

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static const char *
sdap_gssapi_get_default_realm(TALLOC_CTX *mem_ctx)
{
    char *krb5_realm = NULL;
    const char *realm = NULL;
    krb5_error_code krberr;
    krb5_context context = NULL;

    krberr = sss_krb5_init_context(&context);
    if (krberr) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to init kerberos context\n");
        goto done;
    }

    krberr = krb5_get_default_realm(context, &krb5_realm);
    if (krberr) {
        const char *__err_msg = sss_krb5_get_error_message(context, krberr);
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get default realm name: %s\n",
              __err_msg);
        sss_krb5_free_error_message(context, __err_msg);
        goto done;
    }

    realm = talloc_strdup(mem_ctx, krb5_realm);
    krb5_free_default_realm(context, krb5_realm);
    if (!realm) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Will use default realm %s\n", realm);
done:
    if (context) krb5_free_context(context);
    return realm;
}

const char *sdap_gssapi_realm(struct dp_option *opts)
{
    const char *realm;

    realm = dp_opt_get_cstring(opts, SDAP_SASL_REALM);
    if (!realm) {
        realm = dp_opt_get_cstring(opts, SDAP_KRB5_REALM);
    }

    return realm;
}

int sdap_gssapi_init(TALLOC_CTX *mem_ctx,
                     struct dp_option *opts,
                     struct be_ctx *bectx,
                     struct sdap_service *sdap_service,
                     struct krb5_service **krb5_service)
{
    int ret;
    const char *krb5_servers;
    const char *krb5_backup_servers;
    const char *krb5_realm;
    const char *krb5_opt_realm;
    struct krb5_service *service = NULL;
    TALLOC_CTX *tmp_ctx;
    size_t n_lookahead_primary;
    size_t n_lookahead_backup;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    krb5_servers = dp_opt_get_string(opts, SDAP_KRB5_KDC);
    krb5_backup_servers = dp_opt_get_string(opts, SDAP_KRB5_BACKUP_KDC);

    krb5_opt_realm = sdap_gssapi_realm(opts);
    if (krb5_opt_realm == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Missing krb5_realm option, will use libkrb default\n");
        krb5_realm = sdap_gssapi_get_default_realm(tmp_ctx);
        if (krb5_realm == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Cannot determine the Kerberos realm, aborting\n");
            ret = EIO;
            goto done;
        }
    } else {
        krb5_realm = talloc_strdup(tmp_ctx, krb5_opt_realm);
        if (krb5_realm == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    sss_krb5_parse_lookahead(
        dp_opt_get_string(opts, SDAP_KRB5_KDCINFO_LOOKAHEAD),
        &n_lookahead_primary,
        &n_lookahead_backup);

    ret = krb5_service_init(mem_ctx, bectx,
                            SSS_KRB5KDC_FO_SRV, krb5_servers,
                            krb5_backup_servers, krb5_realm,
                            dp_opt_get_bool(opts,
                                            SDAP_KRB5_USE_KDCINFO),
                            n_lookahead_primary,
                            n_lookahead_backup,
                            &service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to init KRB5 failover service!\n");
        goto done;
    }

    sdap_service->kinit_service_name = talloc_strdup(sdap_service,
                                                     service->name);
    if (sdap_service->kinit_service_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
    *krb5_service = service;
done:
    talloc_free(tmp_ctx);
    if (ret != EOK) talloc_free(service);
    return ret;
}

static errno_t _sdap_urls_init(struct be_ctx *ctx,
                               struct sdap_service *service,
                               const char *service_name,
                               const char *dns_service_name,
                               const char *urls,
                               bool primary)
{
    TALLOC_CTX *tmp_ctx;
    char *srv_user_data;
    char **list = NULL;
    LDAPURLDesc *lud;
    errno_t ret = 0;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }


    /* split server parm into a list */
    ret = split_on_separator(tmp_ctx, urls, ',', true, true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse server list!\n");
        goto done;
    }

    /* now for each URI add a new server to the failover service */
    for (i = 0; list[i]; i++) {
        if (be_fo_is_srv_identifier(list[i])) {
            if (!primary) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to add server [%s] to failover service: "
                       "SRV resolution only allowed for primary servers!\n",
                       list[i]);
                continue;
            }

            if (!dns_service_name) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Missing DNS service name for service [%s].\n",
                          service_name);
                ret = EINVAL;
                goto done;
            }
            srv_user_data = talloc_strdup(service, dns_service_name);
            if (!srv_user_data) {
                ret = ENOMEM;
                goto done;
            }

            ret = be_fo_add_srv_server(ctx, service_name,
                                       dns_service_name, NULL,
                                       BE_FO_PROTO_TCP, false, srv_user_data);
            if (ret) {
                DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add server\n");
                goto done;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "Added service lookup\n");
            continue;
        }

        ret = ldap_url_parse(list[i], &lud);
        if (ret != LDAP_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to parse ldap URI (%s)!\n", list[i]);
            ret = EINVAL;
            goto done;
        }

        if (lud->lud_host == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "The LDAP URI (%s) did not contain a host name\n",
                      list[i]);
            ldap_free_urldesc(lud);
            continue;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Added URI %s\n", list[i]);

        talloc_steal(service, list[i]);

        /* It could be ipv6 address in square brackets. Remove
         * the brackets if needed. */
        ret = remove_ipv6_brackets(lud->lud_host);
        if (ret != EOK) {
            goto done;
        }

        ret = be_fo_add_server(ctx, service->name, lud->lud_host,
                               lud->lud_port, list[i], primary);
        ldap_free_urldesc(lud);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}


static inline errno_t
sdap_primary_urls_init(struct be_ctx *ctx, struct sdap_service *service,
                       const char *service_name, const char *dns_service_name,
                       const char *urls)
{
    return _sdap_urls_init(ctx, service, service_name,
                           dns_service_name, urls, true);
}

static inline errno_t
sdap_backup_urls_init(struct be_ctx *ctx, struct sdap_service *service,
                      const char *service_name, const char *dns_service_name,
                      const char *urls)
{
    return _sdap_urls_init(ctx, service, service_name,
                           dns_service_name, urls, false);
}

static int ldap_user_data_cmp(void *ud1, void *ud2)
{
    return strcasecmp((char*) ud1, (char*) ud2);
}

void sdap_service_reset_fo(struct be_ctx *ctx,
                           struct sdap_service *service)
{
    if (service == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "NULL service\n");
        return;
    }

    be_fo_reset_svc(ctx, service->name);
}

int sdap_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name, const char *dns_service_name,
                      const char *urls, const char *backup_urls,
                      struct sdap_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct sdap_service *service;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    service = talloc_zero(tmp_ctx, struct sdap_service);
    if (!service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(ctx, service_name, ldap_user_data_cmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create failover service!\n");
        goto done;
    }

    service->name = talloc_strdup(service, service_name);
    if (!service->name) {
        ret = ENOMEM;
        goto done;
    }

    if (!urls) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No primary servers defined, using service discovery\n");
        urls = BE_SRV_IDENTIFIER;
    }

    ret = sdap_primary_urls_init(ctx, service, service_name, dns_service_name,
                                 urls);
    if (ret != EOK) {
        goto done;
    }

    if (backup_urls) {
        ret = sdap_backup_urls_init(ctx, service, service_name,
                                    dns_service_name, backup_urls);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = be_fo_service_add_callback(memctx, ctx, service->name,
                                     sdap_uri_callback, service);
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

errno_t string_to_shadowpw_days(const char *s, long *d)
{
    long l;
    char *endptr;
    int ret;

    if (s == NULL || *s == '\0') {
        *d = -1;
        return EOK;
    }

    errno = 0;
    l = strtol(s, &endptr, 10);
    if (errno != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "strtol failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    if (*endptr != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Input string [%s] is invalid.\n", s);
        return EINVAL;
    }

    if (l < -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Input string contains not allowed negative value [%ld].\n",
               l);
        return EINVAL;
    }

    *d = l;

    return EOK;
}

errno_t get_sysdb_attr_name(TALLOC_CTX *mem_ctx,
                            struct sdap_attr_map *map,
                            size_t map_size,
                            const char *ldap_name,
                            char **sysdb_name)
{
    size_t i;

    for (i = 0; i < map_size; i++) {
        /* Skip map entries with no name (may depend on
         * schema selected)
         */
        if (!map[i].name) continue;

        /* Check if it is a mapped attribute */
        if(strcasecmp(ldap_name, map[i].name) == 0) break;
    }

    if (i < map_size) {
        /* We found a mapped name, return that */
        *sysdb_name = talloc_strdup(mem_ctx, map[i].sys_name);
    } else {
        /* Not mapped, use the same name */
        *sysdb_name = talloc_strdup(mem_ctx, ldap_name);
    }

    if (!*sysdb_name) {
        return ENOMEM;
    }

    return EOK;
}

errno_t list_missing_attrs(TALLOC_CTX *mem_ctx,
                           struct sdap_attr_map *map,
                           size_t map_size,
                           struct sysdb_attrs *recvd_attrs,
                           char ***missing_attrs)
{
    errno_t ret;
    size_t attr_count = 0;
    size_t i, j, k;
    char **missing = NULL;
    const char **expected_attrs;
    char *sysdb_name;
    TALLOC_CTX *tmp_ctx;

    if (!recvd_attrs || !missing_attrs) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = build_attrs_from_map(tmp_ctx, map, map_size, NULL,
                               &expected_attrs, &attr_count);
    if (ret != EOK) {
        goto done;
    }

    /* Allocate the maximum possible values for missing_attrs, to
     * be on the safe side
     */
    missing = talloc_array(tmp_ctx, char *, attr_count + 2);
    if (!missing) {
        ret = ENOMEM;
        goto done;
    }

    k = 0;
    /* Check for each expected attribute */
    for (i = 0; i < attr_count; i++) {
        ret = get_sysdb_attr_name(tmp_ctx, map, map_size,
                                  expected_attrs[i],
                                  &sysdb_name);
        if (ret != EOK) {
            goto done;
        }

        /* objectClass is a special-case and we need to
         * check for it explicitly.
         */
        if (strcasecmp(sysdb_name, "objectClass") == 0) {
            talloc_free(sysdb_name);
            continue;
        }

        /* GECOS is another special case. Its value can come
         * either from the 'gecos' attribute or the 'cn'
         * attribute. It's best if we just never remove it.
         */
        if (strcasecmp(sysdb_name, SYSDB_GECOS) == 0) {
            talloc_free(sysdb_name);
            continue;
        }

        for (j = 0; j < recvd_attrs->num; j++) {
            /* Check whether this expected attribute appeared in the
             * received attributes and had a non-zero number of
             * values.
             */
            if ((strcasecmp(recvd_attrs->a[j].name, sysdb_name) == 0) &&
                (recvd_attrs->a[j].num_values > 0)) {
                break;
            }
        }

        if (j < recvd_attrs->num) {
            /* Attribute was found, therefore not missing */
            talloc_free(sysdb_name);
        } else {
            /* Attribute could not be found. Add to the missing list */
            missing[k] = talloc_steal(missing, sysdb_name);
            k++;

            /* Remove originalMemberOf as well if MemberOf is missing */
            if (strcmp(sysdb_name, SYSDB_MEMBEROF) == 0) {
                missing[k] = talloc_strdup(missing, SYSDB_ORIG_MEMBEROF);
                k++;
            }
        }
    }

    if (k == 0) {
        *missing_attrs = NULL;
    } else {
        /* Terminate the list */
        missing[k] = NULL;
        *missing_attrs = talloc_steal(mem_ctx, missing);
    }
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

bool sdap_is_secure_uri(const char *uri)
{
    /* LDAPS URI's are secure channels */
    if (strncasecmp(uri, LDAP_SSL_URI, strlen(LDAP_SSL_URI)) == 0) {
        return true;
    }
    return false;
}

char *sdap_get_access_filter(TALLOC_CTX *mem_ctx,
                             const char *base_filter)
{
    char *filter = NULL;

    if (base_filter == NULL) return NULL;

    if (base_filter[0] == '(') {
        /* This filter is wrapped in parentheses.
         * Pass it as-is to the openldap libraries.
         */
        filter = talloc_strdup(mem_ctx, base_filter);
    } else {
        filter = talloc_asprintf(mem_ctx, "(%s)", base_filter);
    }

    return filter;
}

errno_t
sdap_attrs_get_sid_str(TALLOC_CTX *mem_ctx,
                       struct sdap_idmap_ctx *idmap_ctx,
                       struct sysdb_attrs *sysdb_attrs,
                       const char *sid_attr,
                       char **_sid_str)
{
    errno_t ret;
    enum idmap_error_code err;
    struct ldb_message_element *el;
    char *sid_str;

    ret = sysdb_attrs_get_el(sysdb_attrs, sid_attr, &el);
    if (ret != EOK || el->num_values != 1) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "No [%s] attribute. [%d][%s]\n",
               sid_attr, el->num_values, strerror(ret));
        return ENOENT;
    }

    if (el->values[0].length > 2 &&
        el->values[0].data[0] == 'S' &&
        el->values[0].data[1] == '-') {
        sid_str = talloc_strndup(mem_ctx, (char *) el->values[0].data,
                                 el->values[0].length);
        if (sid_str == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            return ENOMEM;
        }
    } else {
        err = sss_idmap_bin_sid_to_sid(idmap_ctx->map,
                                       el->values[0].data,
                                       el->values[0].length,
                                       &sid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not convert SID: [%s]\n",
                   idmap_error_string(err));
            return EIO;
        }
    }

    *_sid_str = talloc_steal(mem_ctx, sid_str);

    return EOK;
}

struct sdap_id_conn_ctx *
sdap_id_ctx_conn_add(struct sdap_id_ctx *id_ctx,
                     struct sdap_service *sdap_service)
{
    struct sdap_id_conn_ctx *conn;
    errno_t ret;

    conn = talloc_zero(id_ctx, struct sdap_id_conn_ctx);
    if (conn == NULL) {
        return NULL;
    }
    conn->service = talloc_steal(conn, sdap_service);
    conn->id_ctx = id_ctx;

    /* Create a connection cache */
    ret = sdap_id_conn_cache_create(conn, conn, &conn->conn_cache);
    if (ret != EOK) {
        talloc_free(conn);
        return NULL;
    }
    DLIST_ADD_END(id_ctx->conn, conn, struct sdap_id_conn_ctx *);

    return conn;
}

static int sdap_id_ctx_destructor(struct sdap_id_ctx *id_ctx)
{
    be_ptask_destroy(&id_ctx->task);
    return 0;
}

struct sdap_id_ctx *
sdap_id_ctx_new(TALLOC_CTX *mem_ctx, struct be_ctx *bectx,
                struct sdap_service *sdap_service)
{
    struct sdap_id_ctx *sdap_ctx;

    sdap_ctx = talloc_zero(mem_ctx, struct sdap_id_ctx);
    if (sdap_ctx == NULL) {
        return NULL;
    }
    talloc_set_destructor(sdap_ctx, sdap_id_ctx_destructor);

    sdap_ctx->be = bectx;

    /* There should be at least one connection context */
    sdap_ctx->conn = sdap_id_ctx_conn_add(sdap_ctx, sdap_service);
    if (sdap_ctx->conn == NULL) {
        talloc_free(sdap_ctx);
        return NULL;
    }

    return sdap_ctx;
}

errno_t
sdap_resolver_ctx_new(TALLOC_CTX *mem_ctx,
                      struct sdap_id_ctx *id_ctx,
                      struct sdap_resolver_ctx **out_ctx)
{
    struct sdap_resolver_ctx *sdap_ctx;

    sdap_ctx = talloc_zero(mem_ctx, struct sdap_resolver_ctx);
    if (sdap_ctx == NULL) {
        return ENOMEM;
    }
    sdap_ctx->id_ctx = id_ctx;

    *out_ctx = sdap_ctx;

    return EOK;
}
