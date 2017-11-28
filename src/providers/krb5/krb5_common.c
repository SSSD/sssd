/*
    SSSD

    Kerberos Provider Common Functions

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2008-2009 Red Hat

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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "providers/backend.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_opts.h"
#include "providers/krb5/krb5_utils.h"

#ifdef HAVE_KRB5_CC_COLLECTION
/* krb5 profile functions */
#include <profile.h>
#endif

static errno_t check_lifetime(TALLOC_CTX *mem_ctx, struct dp_option *opts,
                              const int opt_id, char **lifetime_str)
{
    int ret;
    char *str = NULL;
    krb5_deltat lifetime;

    str = dp_opt_get_string(opts, opt_id);
    if (str == NULL || *str == '\0') {
        DEBUG(SSSDBG_FUNC_DATA, "No lifetime configured.\n");
        *lifetime_str = NULL;
        return EOK;
    }

    if (isdigit(str[strlen(str)-1])) {
        str = talloc_asprintf(mem_ctx, "%ss", str);
        if (str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(opts, opt_id, str);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
            goto done;
        }
    } else {
        str = talloc_strdup(mem_ctx, str);
        if (str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = krb5_string_to_deltat(str, &lifetime);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid value [%s] for a lifetime.\n", str);
        ret = EINVAL;
        goto done;
    }

    *lifetime_str = str;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(str);
    }

    return ret;
}

#ifdef HAVE_KRB5_CC_COLLECTION
/* source default_ccache_name from krb5.conf */
static errno_t sss_get_system_ccname_template(TALLOC_CTX *mem_ctx,
                                              char **ccname)
{
    krb5_context ctx;
    profile_t p;
    char *value = NULL;
    long ret;

    *ccname = NULL;

    ret = sss_krb5_init_context(&ctx);
    if (ret) return ret;

    ret = krb5_get_profile(ctx, &p);
    if (ret) goto done;

    ret = profile_get_string(p, "libdefaults", "default_ccache_name",
                             NULL, NULL, &value);
    profile_release(p);
    if (ret) goto done;

    if (!value) {
        ret = ERR_NOT_FOUND;
        goto done;
    }

    *ccname = talloc_strdup(mem_ctx, value);
    if (*ccname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    krb5_free_context(ctx);
    free(value);
    return ret;
}
#else
static errno_t sss_get_system_ccname_template(TALLOC_CTX *mem_ctx,
                                              char **ccname)
{
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Your kerberos library does not support the default_ccache_name "
           "option or the profile library. Please use krb5_ccname_template "
           "in sssd.conf if you want to change the default\n");
    *ccname = NULL;
    return ERR_NOT_FOUND;
}
#endif

static void sss_check_cc_template(const char *cc_template)
{
    size_t template_len;

    template_len = strlen(cc_template);
    if (template_len >= 6 &&
        strcmp(cc_template + (template_len - 6), "XXXXXX") != 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "ccache file name template [%s] doesn't "
                   "contain randomizing characters (XXXXXX), file might not "
                   "be rewritable\n", cc_template);
    }
}

errno_t sss_krb5_check_options(struct dp_option *opts,
                               struct sss_domain_info *dom,
                               struct krb5_ctx *krb5_ctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;
    const char *realm;
    const char *dummy;
    char *ccname;

    if (opts == NULL || dom == NULL || krb5_ctx == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    realm = dp_opt_get_cstring(opts, KRB5_REALM);
    if (realm == NULL) {
        ret = dp_opt_set_string(opts, KRB5_REALM, dom->name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
            goto done;
        }
        realm = dom->name;
    }

    krb5_ctx->realm = talloc_strdup(krb5_ctx, realm);
    if (krb5_ctx->realm == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set realm, krb5_child might not work as expected.\n");
    }

    ret = check_lifetime(krb5_ctx, opts, KRB5_RENEWABLE_LIFETIME,
                         &krb5_ctx->rlife_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to check value of krb5_renewable_lifetime. [%d][%s]\n",
                  ret, strerror(ret));
        goto done;
    }

    ret = check_lifetime(krb5_ctx, opts, KRB5_LIFETIME,
                         &krb5_ctx->lifetime_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to check value of krb5_lifetime. [%d][%s]\n",
                  ret, strerror(ret));
        goto done;
    }

    krb5_ctx->use_fast_str = dp_opt_get_cstring(opts, KRB5_USE_FAST);
    if (krb5_ctx->use_fast_str != NULL) {
        ret = check_fast(krb5_ctx->use_fast_str, &krb5_ctx->use_fast);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "check_fast failed.\n");
            goto done;
        }

        if (krb5_ctx->use_fast) {
            krb5_ctx->fast_principal = dp_opt_get_cstring(opts,
                                                          KRB5_FAST_PRINCIPAL);
        }
    }

    /* In contrast to MIT KDCs AD does not automatically canonicalize the
     * enterprise principal in an AS request but requires the canonicalize
     * flags to be set. To be on the safe side we always enable
     * canonicalization if enterprise principals are used. */
    krb5_ctx->canonicalize = false;
    if (dp_opt_get_bool(opts, KRB5_CANONICALIZE)
            || dp_opt_get_bool(opts, KRB5_USE_ENTERPRISE_PRINCIPAL)) {
        krb5_ctx->canonicalize = true;
    }

    dummy = dp_opt_get_cstring(opts, KRB5_KDC);
    if (dummy == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "No KDC explicitly configured, using defaults.\n");
    }

    dummy = dp_opt_get_cstring(opts, KRB5_KPASSWD);
    if (dummy == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "No kpasswd server explicitly configured, "
                                     "using the KDC or defaults.\n");
    }

    ccname = dp_opt_get_string(opts, KRB5_CCNAME_TMPL);
    if (ccname != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "The credential ccache name template has been explicitly set "
               "in sssd.conf, it is recommended to set default_ccache_name "
               "in krb5.conf instead so that a system default is used\n");
        ccname = talloc_strdup(tmp_ctx, ccname);
        if (!ccname) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        ret = sss_get_system_ccname_template(tmp_ctx, &ccname);
        if (ret && ret != ERR_NOT_FOUND) {
            goto done;
        }
        if (ret == ERR_NOT_FOUND) {
            /* Use fallback default */
            ccname = talloc_strdup(tmp_ctx, DEFAULT_CCNAME_TEMPLATE);
            if (!ccname) {
                ret = ENOMEM;
                goto done;
            }
        }

        /* set back in opts */
        ret = dp_opt_set_string(opts, KRB5_CCNAME_TMPL, ccname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
            goto done;
        }
    }

    if ((ccname[0] == '/') || (strncmp(ccname, "FILE:", 5) == 0)) {
        DEBUG(SSSDBG_CONF_SETTINGS, "ccache is of type FILE\n");
        /* warn if the file type (which is usally created in a sticky bit
         * laden directory) does not have randomizing chracters */
        sss_check_cc_template(ccname);

        if (ccname[0] == '/') {
            /* /path/to/cc  prepend FILE: */
            DEBUG(SSSDBG_CONF_SETTINGS, "The ccname template was "
              "missing an explicit type, but is an absolute "
              "path specifier. Assuming FILE:\n");

            ccname = talloc_asprintf(tmp_ctx, "FILE:%s", ccname);
            if (!ccname) {
                ret = ENOMEM;
                goto done;
            }

            ret = dp_opt_set_string(opts, KRB5_CCNAME_TMPL, ccname);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
                goto done;
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t krb5_try_kdcip(struct confdb_ctx *cdb, const char *conf_path,
                       struct dp_option *opts, int opt_id)
{
    char *krb5_servers = NULL;
    errno_t ret;

    krb5_servers = dp_opt_get_string(opts, opt_id);
    if (krb5_servers == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No KDC found in configuration, trying legacy option\n");
        ret = confdb_get_string(cdb, NULL, conf_path,
                                "krb5_kdcip", NULL, &krb5_servers);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "confdb_get_string failed.\n");
            return ret;
        }

        if (krb5_servers != NULL)
        {
            ret = dp_opt_set_string(opts, opt_id, krb5_servers);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
                talloc_free(krb5_servers);
                return ret;
            }

            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Set krb5 server [%s] based on legacy krb5_kdcip option\n",
                   krb5_servers);
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Your configuration uses the deprecated option "
                   "'krb5_kdcip' to specify the KDC. Please change the "
                   "configuration to use the 'krb5_server' option "
                   "instead.\n");
            talloc_free(krb5_servers);
        }
    }

    return EOK;
}

errno_t sss_krb5_get_options(TALLOC_CTX *memctx, struct confdb_ctx *cdb,
                             const char *conf_path, struct dp_option **_opts)
{
    int ret;
    struct dp_option *opts;

    ret = dp_get_options(memctx, cdb, conf_path, default_krb5_opts,
                         KRB5_OPTS, &opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_get_options failed.\n");
        goto done;
    }

    /* If there is no KDC, try the deprecated krb5_kdcip option, too */
    /* FIXME - this can be removed in a future version */
    ret = krb5_try_kdcip(cdb, conf_path, opts, KRB5_KDC);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_try_kdcip failed.\n");
        goto done;
    }

    *_opts = opts;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }

    return ret;
}

errno_t write_krb5info_file(const char *realm, const char *server,
                            const char *service)
{
    int ret;
    int fd = -1;
    char *tmp_name = NULL;
    char *krb5info_name = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *name_tmpl = NULL;
    size_t server_len;
    ssize_t written;

    if (realm == NULL || *realm == '\0' || server == NULL || *server == '\0' ||
        service == NULL || *service == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing or empty realm, server or service.\n");
        return EINVAL;
    }

    if (sss_krb5_realm_has_proxy(realm)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "KDC Proxy available for realm [%s], no kdcinfo file created.\n",
              realm);
        return EOK;
    }

    if (strcmp(service, SSS_KRB5KDC_FO_SRV) == 0) {
        name_tmpl = KDCINFO_TMPL;
    } else if (strcmp(service, SSS_KRB5KPASSWD_FO_SRV) == 0) {
        name_tmpl = KPASSWDINFO_TMPL;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported service [%s].\n", service);
        return EINVAL;
    }

    server_len = strlen(server);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    tmp_name = talloc_asprintf(tmp_ctx, PUBCONF_PATH"/.krb5info_dummy_XXXXXX");
    if (tmp_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    krb5info_name = talloc_asprintf(tmp_ctx, name_tmpl, realm);
    if (krb5info_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    fd = sss_unique_file(tmp_ctx, tmp_name, &ret);
    if (fd == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_unique_file failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    errno = 0;
    written = sss_atomic_write_s(fd, discard_const(server), server_len);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "write failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    if (written != server_len) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Write error, wrote [%zd] bytes, expected [%zu]\n",
               written, server_len);
        ret = EIO;
        goto done;
    }

    ret = fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fchmod failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = close(fd);
    fd = -1;
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "close failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = rename(tmp_name, krb5info_name);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "rename failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    if (fd != -1) {
        close(fd);
    }

    talloc_free(tmp_ctx);
    return ret;
}

static void krb5_resolve_callback(void *private_data, struct fo_server *server)
{
    struct krb5_service *krb5_service;
    struct resolv_hostent *srvaddr;
    char *address;
    char *safe_address;
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed\n");
        return;
    }

    krb5_service = talloc_get_type(private_data, struct krb5_service);
    if (!krb5_service) {
        DEBUG(SSSDBG_CRIT_FAILURE, "FATAL: Bad private_data\n");
        talloc_free(tmp_ctx);
        return;
    }

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "FATAL: No hostent available for server (%s)\n",
                  fo_get_server_str_name(server));
        talloc_free(tmp_ctx);
        return;
    }

    address = resolv_get_string_address(tmp_ctx, srvaddr);
    if (address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "resolv_get_string_address failed.\n");
        talloc_free(tmp_ctx);
        return;
    }

    safe_address = sss_escape_ip_address(tmp_ctx,
                                         srvaddr->family,
                                         address);
    if (safe_address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_escape_ip_address failed.\n");
        talloc_free(tmp_ctx);
        return;
    }

    if (krb5_service->write_kdcinfo) {
        safe_address = talloc_asprintf_append(safe_address, ":%d",
                                            fo_get_server_port(server));
        if (safe_address == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf_append failed.\n");
            talloc_free(tmp_ctx);
            return;
        }

        ret = write_krb5info_file(krb5_service->realm, safe_address,
                                  krb5_service->name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "write_krb5info_file failed, authentication might fail.\n");
        }
    }

    talloc_free(tmp_ctx);
    return;
}

static errno_t _krb5_servers_init(struct be_ctx *ctx,
                                  struct krb5_service *service,
                                  const char *service_name,
                                  const char *servers,
                                  bool primary)
{
    TALLOC_CTX *tmp_ctx;
    char **list = NULL;
    errno_t ret = 0;
    int i;
    char *port_str;
    long port;
    char *server_spec;
    char *endptr;
    struct servent *servent;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = split_on_separator(tmp_ctx, servers, ',', true, true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse server list!\n");
        goto done;
    }

    for (i = 0; list[i]; i++) {
        talloc_steal(service, list[i]);
        server_spec = talloc_strdup(service, list[i]);
        if (!server_spec) {
            ret = ENOMEM;
            goto done;
        }

        if (be_fo_is_srv_identifier(server_spec)) {
            if (!primary) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to add server [%s] to failover service: "
                       "SRV resolution only allowed for primary servers!\n",
                       list[i]);
                continue;
            }

            ret = be_fo_add_srv_server(ctx, service_name, service_name, NULL,
                                       BE_FO_PROTO_UDP, true, NULL);
            if (ret) {
                DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add server\n");
                goto done;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "Added service lookup\n");
            continue;
        }

        /* Do not try to get port number if last character is ']' */
        if (server_spec[strlen(server_spec) - 1] != ']') {
            port_str = strrchr(server_spec, ':');
        } else {
            port_str = NULL;
        }

        if (port_str == NULL) {
            port = 0;
        } else {
            *port_str = '\0';
            ++port_str;
            if (isdigit(*port_str)) {
                errno = 0;
                port = strtol(port_str, &endptr, 10);
                if (errno != 0) {
                    ret = errno;
                    DEBUG(SSSDBG_CRIT_FAILURE, "strtol failed on [%s]: [%d][%s].\n", port_str,
                              ret, strerror(ret));
                    goto done;
                }
                if (*endptr != '\0') {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Found additional characters [%s] in port number "
                              "[%s].\n", endptr, port_str);
                    ret = EINVAL;
                    goto done;
                }

                if (port < 1 || port > 65535) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Illegal port number [%ld].\n", port);
                    ret = EINVAL;
                    goto done;
                }
            } else if (isalpha(*port_str)) {
                servent = getservbyname(port_str, NULL);
                if (servent == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "getservbyname cannot find service [%s].\n",
                              port_str);
                    ret = EINVAL;
                    goto done;
                }

                port = servent->s_port;
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported port specifier in [%s].\n", list[i]);
                ret = EINVAL;
                goto done;
            }
        }

        /* It could be ipv6 address in square brackets. Remove
         * the brackets if needed. */
        ret = remove_ipv6_brackets(server_spec);
        if (ret != EOK) {
            goto done;
        }

        ret = be_fo_add_server(ctx, service_name, server_spec, (int) port,
                               list[i], primary);
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
krb5_primary_servers_init(struct be_ctx *ctx, struct krb5_service *service,
                          const char *service_name, const char *servers)
{
    return _krb5_servers_init(ctx, service, service_name, servers, true);
}

static inline errno_t
krb5_backup_servers_init(struct be_ctx *ctx, struct krb5_service *service,
                         const char *service_name, const char *servers)
{
    return _krb5_servers_init(ctx, service, service_name, servers, false);
}

static int krb5_user_data_cmp(void *ud1, void *ud2)
{
    return strcasecmp((char*) ud1, (char*) ud2);
}

int krb5_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name,
                      const char *primary_servers,
                      const char *backup_servers,
                      const char *realm,
                      bool use_kdcinfo,
                      struct krb5_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct krb5_service *service;
    int ret;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    service = talloc_zero(tmp_ctx, struct krb5_service);
    if (!service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(ctx, service_name, krb5_user_data_cmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create failover service!\n");
        goto done;
    }

    service->name = talloc_strdup(service, service_name);
    if (!service->name) {
        ret = ENOMEM;
        goto done;
    }

    service->realm = talloc_strdup(service, realm);
    if (!service->realm) {
        ret = ENOMEM;
        goto done;
    }

    service->write_kdcinfo = use_kdcinfo;

    if (!primary_servers) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No primary servers defined, using service discovery\n");
        primary_servers = BE_SRV_IDENTIFIER;
    }

    ret = krb5_primary_servers_init(ctx, service, service_name, primary_servers);
    if (ret != EOK) {
        goto done;
    }

    if (backup_servers) {
        ret = krb5_backup_servers_init(ctx, service, service_name,
                                       backup_servers);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = be_fo_service_add_callback(memctx, ctx, service_name,
                                     krb5_resolve_callback, service);
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


errno_t remove_krb5_info_files(TALLOC_CTX *mem_ctx, const char *realm)
{
    int ret;
    errno_t err;
    char *file;

    file = talloc_asprintf(mem_ctx, KDCINFO_TMPL, realm);
    if(file == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        return ENOMEM;
    }

    errno = 0;
    ret = unlink(file);
    if (ret == -1) {
        err = errno;
        DEBUG(SSSDBG_FUNC_DATA, "Could not remove [%s], [%d][%s]\n", file,
                  err, strerror(err));
    }

    file = talloc_asprintf(mem_ctx, KPASSWDINFO_TMPL, realm);
    if(file == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        return ENOMEM;
    }

    errno = 0;
    ret = unlink(file);
    if (ret == -1) {
        err = errno;
        DEBUG(SSSDBG_FUNC_DATA, "Could not remove [%s], [%d][%s]\n", file,
                  err, strerror(err));
    }

    return EOK;
}

void remove_krb5_info_files_callback(void *pvt)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct remove_info_files_ctx *ctx = talloc_get_type(pvt,
                                                  struct remove_info_files_ctx);

    ret = be_fo_run_callbacks_at_next_request(ctx->be_ctx,
                                              ctx->kdc_service_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "be_fo_run_callbacks_at_next_request failed, "
                  "krb5 info files will not be removed, because "
                  "it is unclear if they will be recreated properly.\n");
        return;
    }
    if (ctx->kpasswd_service_name != NULL) {
        ret = be_fo_run_callbacks_at_next_request(ctx->be_ctx,
                                            ctx->kpasswd_service_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "be_fo_run_callbacks_at_next_request failed, "
                      "krb5 info files will not be removed, because "
                      "it is unclear if they will be recreated properly.\n");
            return;
        }
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "talloc_new failed, cannot remove krb5 info files.\n");
        return;
    }

    ret = remove_krb5_info_files(tmp_ctx, ctx->realm);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "remove_krb5_info_files failed.\n");
    }

    talloc_zfree(tmp_ctx);
}

void krb5_finalize(struct tevent_context *ev,
                   struct tevent_signal *se,
                   int signum,
                   int count,
                   void *siginfo,
                   void *private_data)
{
    char *realm = (char *)private_data;
    int ret;

    ret = remove_krb5_info_files(se, realm);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "remove_krb5_info_files failed.\n");
    }

    orderly_shutdown(0);
}

errno_t krb5_install_offline_callback(struct be_ctx *be_ctx,
                                      struct krb5_ctx *krb5_ctx)
{
    int ret;
    struct remove_info_files_ctx *ctx;
    const char *krb5_realm;

    if (krb5_ctx->service == NULL || krb5_ctx->service->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing KDC service name!\n");
        return EINVAL;
    }

    ctx = talloc_zero(krb5_ctx, struct remove_info_files_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zfree failed.\n");
        return ENOMEM;
    }

    krb5_realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
    if (krb5_realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing krb5_realm option!\n");
        ret = EINVAL;
        goto done;
    }

    ctx->realm = talloc_strdup(ctx, krb5_realm);
    if (ctx->realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed!\n");
        ret = ENOMEM;
        goto done;
    }

    ctx->be_ctx = be_ctx;
    ctx->kdc_service_name = krb5_ctx->service->name;
    if (krb5_ctx->kpasswd_service == NULL) {
        ctx->kpasswd_service_name =NULL;
    } else {
        ctx->kpasswd_service_name = krb5_ctx->kpasswd_service->name;
    }

    ret = be_add_offline_cb(ctx, be_ctx, remove_krb5_info_files_callback, ctx,
                            NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_add_offline_cb failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(ctx);
    }

    return ret;
}

errno_t krb5_install_sigterm_handler(struct tevent_context *ev,
                                     struct krb5_ctx *krb5_ctx)
{
    const char *krb5_realm;
    char *sig_realm;
    struct tevent_signal *sige;

    BlockSignals(false, SIGTERM);

    krb5_realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
    if (krb5_realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing krb5_realm option!\n");
        return EINVAL;
    }

    sig_realm = talloc_strdup(krb5_ctx, krb5_realm);
    if (sig_realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed!\n");
        return ENOMEM;
    }

    sige = tevent_add_signal(ev, krb5_ctx, SIGTERM, SA_SIGINFO, krb5_finalize,
                             sig_realm);
    if (sige == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_signal failed.\n");
        talloc_free(sig_realm);
        return ENOMEM;
    }
    talloc_steal(sige, sig_realm);

    return EOK;
}

errno_t krb5_get_simple_upn(TALLOC_CTX *mem_ctx, struct krb5_ctx *krb5_ctx,
                            struct sss_domain_info *dom, const char *username,
                            const char *user_dom, char **_upn)
{
    const char *realm = NULL;
    char *uc_dom = NULL;
    char *upn;
    char *name;
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (user_dom != NULL && dom->name != NULL &&
        strcasecmp(dom->name, user_dom) != 0) {
        uc_dom = get_uppercase_realm(tmp_ctx, user_dom);
        if (uc_dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "get_uppercase_realm failed.\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
        if (realm == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Missing Kerberos realm.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    /* The internal username is qualified, but we are only interested in
     * the name part
     */
    ret = sss_parse_internal_fqname(tmp_ctx, username, &name, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not parse [%s] into name and "
              "domain components, login might fail\n", username);
        upn = talloc_strdup(tmp_ctx, username);
    } else {
        /* NOTE: this is a hack, works only in some environments */
        upn = talloc_asprintf(tmp_ctx, "%s@%s",
                              name, realm != NULL ? realm : uc_dom);
    }

    if (upn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Using simple UPN [%s].\n", upn);
    *_upn = talloc_steal(mem_ctx, upn);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t compare_principal_realm(const char *upn, const char *realm,
                                bool *different_realm)
{
    char *at_sign;

    if (upn == NULL || realm == NULL || different_realm == NULL ||
        *upn == '\0' || *realm == '\0') {
        return EINVAL;
    }

    at_sign = strchr(upn, '@');

    if (at_sign == NULL) {
        return EINVAL;
    }

    if (strcmp(realm, at_sign + 1) == 0) {
        *different_realm = false;
    } else {
        *different_realm = true;
    }

    return EOK;
}
