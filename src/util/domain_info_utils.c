/*
    Authors:
        Sumit Bose <sbose@redhat.com>

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
#include <utime.h>

#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "util/util.h"

struct sss_domain_info *get_domains_head(struct sss_domain_info *domain)
{
    struct sss_domain_info *dom = NULL;

    /* get to the top level domain */
    for (dom = domain; dom->parent != NULL; dom = dom->parent);

    return dom;
}

struct sss_domain_info *get_next_domain(struct sss_domain_info *domain,
                                        uint32_t gnd_flags)
{
    struct sss_domain_info *dom;
    bool descend = gnd_flags & (SSS_GND_DESCEND | SSS_GND_SUBDOMAINS);
    bool include_disabled = gnd_flags & SSS_GND_INCLUDE_DISABLED;
    bool only_subdomains = gnd_flags & SSS_GND_SUBDOMAINS;

    dom = domain;
    while (dom) {
        if (descend && dom->subdomains) {
            dom = dom->subdomains;
        } else if (dom->next && only_subdomains && IS_SUBDOMAIN(dom)) {
            dom = dom->next;
        } else if (dom->next && !only_subdomains) {
            dom = dom->next;
        } else if (descend && !only_subdomains && IS_SUBDOMAIN(dom)
                            && dom->parent->next) {
            dom = dom->parent->next;
        } else {
            dom = NULL;
        }

        if (dom) {
            if (sss_domain_get_state(dom) == DOM_DISABLED
                    && !include_disabled) {
                continue;
            } else {
                /* Next domain found. */
                break;
            }
        }
    }

    return dom;
}

bool subdomain_enumerates(struct sss_domain_info *parent,
                          const char *sd_name)
{
    if (parent->sd_enumerate == NULL
            || parent->sd_enumerate[0] == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Subdomain_enumerate not set\n");
        return false;
    }

    if (strcasecmp(parent->sd_enumerate[0], "all") == 0) {
        return true;
    } else if (strcasecmp(parent->sd_enumerate[0], "none") == 0) {
        return false;
    } else {
        for (int i=0; parent->sd_enumerate[i]; i++) {
            if (strcasecmp(parent->sd_enumerate[i], sd_name) == 0) {
                return true;
            }
        }
    }

    return false;
}

struct sss_domain_info *find_domain_by_name_ex(struct sss_domain_info *domain,
                                                const char *name,
                                                bool match_any,
                                                uint32_t gnd_flags)
{
    struct sss_domain_info *dom = domain;

    if (name == NULL) {
        return NULL;
    }

    if (!(gnd_flags & SSS_GND_INCLUDE_DISABLED)) {
        while (dom && sss_domain_get_state(dom) == DOM_DISABLED) {
            dom = get_next_domain(dom, gnd_flags);
        }
    }

    while (dom) {
        if (strcasecmp(dom->name, name) == 0 ||
            ((match_any == true) && (dom->flat_name != NULL) &&
             (strcasecmp(dom->flat_name, name) == 0))) {
            return dom;
        }
        dom = get_next_domain(dom, gnd_flags);
    }

    return NULL;
}

struct sss_domain_info *find_domain_by_name(struct sss_domain_info *domain,
                                            const char *name,
                                            bool match_any)
{
    return find_domain_by_name_ex(domain, name, match_any, SSS_GND_DESCEND);
}

struct sss_domain_info *find_domain_by_sid(struct sss_domain_info *domain,
                                              const char *sid)
{
    struct sss_domain_info *dom = domain;
    size_t sid_len;
    size_t dom_sid_len;

    if (sid == NULL) {
        return NULL;
    }

    sid_len = strlen(sid);

    while (dom && sss_domain_get_state(dom) == DOM_DISABLED) {
        dom = get_next_domain(dom, SSS_GND_DESCEND);
    }

    while (dom) {
        if (dom->domain_id != NULL) {
            dom_sid_len = strlen(dom->domain_id);

            if (strncasecmp(dom->domain_id, sid, dom_sid_len) == 0) {
                if (dom_sid_len == sid_len) {
                    /* sid is domain sid */
                    return dom;
                }

                /* sid is object sid, check if domain sid is align with
                 * sid first subauthority component */
                if (sid[dom_sid_len] == '-') {
                    return dom;
                }
            }
        }

        dom = get_next_domain(dom, SSS_GND_DESCEND);
    }

    return NULL;
}

struct sss_domain_info*
sss_get_domain_by_sid_ldap_fallback(struct sss_domain_info *domain,
                                    const char* sid)
{
    /* LDAP provider doesn't know about sub-domains and hence can only
     * have one configured domain
     */
    if (strcmp(domain->provider, "ldap") == 0) {
        return domain;
    } else {
        return find_domain_by_sid(get_domains_head(domain), sid);
    }
}

struct sss_domain_info *
find_domain_by_object_name_ex(struct sss_domain_info *domain,
                              const char *object_name, bool strict,
                              uint32_t gnd_flags)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *dom = NULL;
    char *domainname = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, object_name,
                                    NULL, &domainname);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to parse name '%s' [%d]: %s\n",
                                    object_name, ret, sss_strerror(ret));
        goto done;
    }

    if (domainname == NULL) {
        if (strict) {
            dom = NULL;
        } else {
            dom = domain;
        }
    } else {
        dom = find_domain_by_name_ex(domain, domainname, true, gnd_flags);
    }

done:
    talloc_free(tmp_ctx);
    return dom;
}

struct sss_domain_info *
find_domain_by_object_name(struct sss_domain_info *domain,
                           const char *object_name)
{
    return find_domain_by_object_name_ex(domain, object_name, false,
                                         SSS_GND_DESCEND);
}

errno_t sssd_domain_init(TALLOC_CTX *mem_ctx,
                         struct confdb_ctx *cdb,
                         const char *domain_name,
                         const char *db_path,
                         struct sss_domain_info **_domain)
{
    int ret;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;

    ret = confdb_get_domain(cdb, domain_name, &dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Error retrieving domain configuration.\n");
        return ret;
    }

    if (dom->sysdb != NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Sysdb context already initialized.\n");
        return EEXIST;
    }

    ret = sysdb_domain_init(mem_ctx, dom, db_path, &sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Error opening cache database.\n");
        return ret;
    }

    dom->sysdb = talloc_steal(dom, sysdb);

    *_domain = dom;

    return EOK;
}

static void
sss_krb5_touch_config(void)
{
    const char *config = NULL;
    errno_t ret;

    config = getenv("KRB5_CONFIG");
    if (config == NULL) {
        config = KRB5_CONF_PATH;
    }

    ret = utime(config, NULL);
    if (ret == -1) {
        ret = errno;
        DEBUG(ret == EPERM ? SSSDBG_MINOR_FAILURE : SSSDBG_CRIT_FAILURE,
              "Unable to change mtime of \"%s\" [%d]: %s\n",
              config, ret, strerror(ret));
    }
}

errno_t sss_get_domain_mappings_content(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domain,
                                        char **content)
{
    int ret;
    char *o = NULL;
    struct sss_domain_info *dom;
    struct sss_domain_info *parent_dom;
    char *uc_parent = NULL;
    char *uc_forest = NULL;
    char *parent_capaths = NULL;
    bool capaths_started = false;

    if (domain == NULL || content == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing parameter.\n");
        return EINVAL;
    }

    o = talloc_strdup(mem_ctx, "[domain_realm]\n");
    if (o == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Start with the parent domain */
    if (domain->realm != NULL) {
        o = talloc_asprintf_append(o, ".%s = %s\n%s = %s\n",
                                  domain->name, domain->realm, domain->name,
                                  domain->realm);
        if (o == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf_append failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }
    /* This loops skips the starting parent and starts right with the first
     * subdomain, if any. */
    for (dom = get_next_domain(domain, SSS_GND_DESCEND);
                dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
                dom = get_next_domain(dom, 0)) {
        if (dom->realm != NULL) {
            o = talloc_asprintf_append(o, ".%s = %s\n%s = %s\n",
                                   dom->name, dom->realm, dom->name, dom->realm);
            if (o == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf_append failed.\n");
                ret = ENOMEM;
                goto done;
            }
        }
    }

    parent_dom = domain;
    uc_parent = get_uppercase_realm(mem_ctx, parent_dom->name);
    if (uc_parent == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "get_uppercase_realm failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (dom = get_next_domain(domain, SSS_GND_DESCEND);
            dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
            dom = get_next_domain(dom, 0)) {

        if (dom->forest == NULL) {
            continue;
        }

        talloc_free(uc_forest);
        uc_forest = get_uppercase_realm(mem_ctx, dom->forest);
        if (uc_forest == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "get_uppercase_realm failed.\n");
            ret = ENOMEM;
            goto done;
        }

        if (!capaths_started) {
            o = talloc_asprintf_append(o, "[capaths]\n");
            if (o == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf_append failed.\n");
                ret = ENOMEM;
                goto done;
            }
            capaths_started = true;
        }

        o = talloc_asprintf_append(o, "%s = {\n  %s = %s\n}\n",
                                   dom->realm, uc_parent, uc_forest);
        if (o == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf_append failed.\n");
            ret = ENOMEM;
            goto done;
        }

        if (parent_capaths == NULL) {
            parent_capaths = talloc_asprintf(mem_ctx, "  %s = %s\n", dom->realm,
                                                                     uc_forest);
        } else {
            parent_capaths = talloc_asprintf_append(parent_capaths,
                                                    "  %s = %s\n", dom->realm,
                                                    uc_forest);
        }
        if (parent_capaths == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc_asprintf/talloc_asprintf_append failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (parent_capaths != NULL) {
        o = talloc_asprintf_append(o, "%s = {\n%s}\n", uc_parent,
                                                       parent_capaths);
        if (o == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf_append failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(parent_capaths);
    talloc_free(uc_parent);
    talloc_free(uc_forest);

    if (ret == EOK) {
        *content = o;
    } else {
        talloc_free(o);
    }

    return ret;
}

errno_t
sss_write_domain_mappings(struct sss_domain_info *domain)
{
    errno_t ret;
    errno_t err;
    TALLOC_CTX *tmp_ctx;
    const char *mapping_file;
    char *sanitized_domain;
    char *tmp_file = NULL;
    int fd = -1;
    mode_t old_mode;
    FILE *fstream = NULL;
    int i;
    char *content = NULL;

    if (domain == NULL || domain->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No domain name provided\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sss_get_domain_mappings_content(tmp_ctx, domain, &content);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_get_domain_mappings_content failed.\n");
        goto done;
    }

    sanitized_domain = talloc_strdup(tmp_ctx, domain->name);
    if (sanitized_domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
        return ENOMEM;
    }

    /* only alpha-numeric chars, dashes and underscores are allowed in
     * krb5 include directory */
    for (i = 0; sanitized_domain[i] != '\0'; i++) {
        if (!isalnum(sanitized_domain[i])
                && sanitized_domain[i] != '-' && sanitized_domain[i] != '_') {
            sanitized_domain[i] = '_';
        }
    }

    mapping_file = talloc_asprintf(tmp_ctx, "%s/domain_realm_%s",
                                   KRB5_MAPPING_DIR, sanitized_domain);
    if (!mapping_file) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Mapping file for domain [%s] is [%s]\n",
                             domain->name, mapping_file);

    tmp_file = get_hidden_tmp_path(tmp_ctx, mapping_file);
    if (tmp_file == NULL) {
        ret = ENOMEM;
        goto done;
    }

    old_mode = umask(SSS_DFL_UMASK);
    fd = mkstemp(tmp_file);
    umask(old_mode);
    if (fd < 0) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "creating the temp file [%s] for domain-realm mappings "
              "failed [%d]: %s\n", tmp_file, ret, strerror(ret));
        talloc_zfree(tmp_ctx);
        goto done;
    }

    fstream = fdopen(fd, "a");
    if (!fstream) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, "fdopen failed [%d]: %s\n",
                                  ret, strerror(ret));
        ret = close(fd);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                "fclose failed [%d][%s].\n", ret, strerror(ret));
            /* Nothing to do here, just report the failure */
        }
        ret = EIO;
        goto done;
    }

    ret = fprintf(fstream, "%s", content);
    if (ret < 0) {
        DEBUG(SSSDBG_OP_FAILURE, "fprintf failed\n");
        ret = EIO;
        goto done;
    }

    ret = fclose(fstream);
    fstream = NULL;
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fclose failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = rename(tmp_file, mapping_file);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "rename failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    talloc_zfree(tmp_file);

    ret = chmod(mapping_file, 0644);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fchmod failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    if (ret == EOK) {
        sss_krb5_touch_config();
    }

    if (fstream) {
        err = fclose(fstream);
        if (err != 0) {
            err = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                "fclose failed [%d][%s].\n", err, strerror(err));
            /* Nothing to do here, just report the failure */
        }
    }

    if (tmp_file) {
        err = unlink(tmp_file);
        if (err < 0) {
            err = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not remove file [%s]: [%d]: %s\n",
                  tmp_file, err, strerror(err));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

/* Save domain names, do not descend. */
errno_t get_dom_names(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *start_dom,
                      char ***_dom_names,
                      int *_dom_names_count)
{
    struct sss_domain_info *dom;
    TALLOC_CTX *tmp_ctx;
    char **dom_names;
    size_t count, i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* get count of domains*/
    count = 0;
    dom = start_dom;
    while (dom) {
        count++;
        dom = get_next_domain(dom, 0);
    }

    dom_names = talloc_array(tmp_ctx, char*, count);
    if (dom_names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* copy names */
    i = 0;
    dom = start_dom;
    while (dom) {
        dom_names[i] = talloc_strdup(dom_names, dom->name);
        if (dom_names[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        dom = get_next_domain(dom, 0);
        i++;
    }

    if (_dom_names != NULL ) {
        *_dom_names = talloc_steal(mem_ctx, dom_names);
    }

    if (_dom_names_count != NULL ) {
        *_dom_names_count =  count;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

char *get_hidden_tmp_path(TALLOC_CTX *mem_ctx, const char *path)
{
    const char *s;

    if (path == NULL) {
        return NULL;
    }

    s = strrchr(path, '/');
    if (s == NULL) {
        /* No path, just file name */
        return talloc_asprintf(mem_ctx, ".%sXXXXXX", path);
    } else if ( *(s + 1) == '\0') {
        /* '/' is the last character, there is no filename */
        DEBUG(SSSDBG_OP_FAILURE, "Missing file name in [%s].\n", path);
        return NULL;
    }

    return talloc_asprintf(mem_ctx, "%.*s.%sXXXXXX", (int)(s - path + 1),
                                                     path, s+1);
}

static errno_t sss_write_krb5_snippet_common(const char *file_name,
                                             const char *content)
{
    int ret;
    errno_t err;
    TALLOC_CTX *tmp_ctx = NULL;
    char *tmp_file = NULL;
    int fd = -1;
    mode_t old_mode;
    ssize_t written;
    size_t size;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    tmp_file = get_hidden_tmp_path(tmp_ctx, file_name);
    if (tmp_file == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    old_mode = umask(SSS_DFL_UMASK);
    fd = mkstemp(tmp_file);
    umask(old_mode);
    if (fd < 0) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, "creating the temp file [%s] for "
                                 "krb5 config snippet failed [%d]: %s\n",
                                 tmp_file, ret, strerror(ret));
        talloc_zfree(tmp_ctx);
        goto done;
    }

    size = strlen(content);
    written = sss_atomic_write_s(fd, discard_const(content), size);
    close(fd);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "write failed [%d][%s]\n", ret, sss_strerror(ret));
        goto done;
    }

    if (written != size) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Wrote %zd bytes expected %zu\n", written, size);
        ret = EIO;
        goto done;
    }

    ret = chmod(tmp_file, 0644);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "chmod failed [%d][%s].\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = rename(tmp_file, file_name);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "rename failed [%d][%s].\n", ret, sss_strerror(ret));
        goto done;
    }
    tmp_file = NULL;

done:
    if (tmp_file != NULL) {
        err = unlink(tmp_file);
        if (err == -1) {
            err = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not remove file [%s]: [%d]: %s\n",
                  tmp_file, err, sss_strerror(err));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

#define LOCALAUTH_PLUGIN_CONFIG \
"[plugins]\n" \
" localauth = {\n" \
"  module = sssd:"APP_MODULES_PATH"/sssd_krb5_localauth_plugin.so\n" \
" }\n"

static errno_t sss_write_krb5_localauth_snippet(const char *path)
{
#ifdef HAVE_KRB5_LOCALAUTH_PLUGIN
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *file_name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    file_name = talloc_asprintf(tmp_ctx, "%s/localauth_plugin", path);
    if (file_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "File for localauth plugin configuration is [%s]\n",
                             file_name);

    ret = sss_write_krb5_snippet_common(file_name, LOCALAUTH_PLUGIN_CONFIG);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_write_krb5_snippet_common failed.\n");
        goto done;
    }

done:

    talloc_free(tmp_ctx);
    return ret;

#else
    DEBUG(SSSDBG_TRACE_ALL, "Kerberos localauth plugin not available.\n");
    return EOK;
#endif
}

static errno_t sss_write_krb5_libdefaults_snippet(const char *path,
                                                  bool canonicalize,
                                                  bool udp_limit)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *file_name;
    char *file_contents;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    file_name = talloc_asprintf(tmp_ctx, "%s/krb5_libdefaults", path);
    if (file_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "File for KRB5 libdefaults configuration is [%s]\n",
                             file_name);

    file_contents = talloc_strdup(tmp_ctx, "[libdefaults]\n");
    if (file_contents == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "talloc_asprintf failed while creating the content\n");
        ret = ENOMEM;
        goto done;
    }

    if (canonicalize == true) {
        file_contents = talloc_asprintf_append(file_contents,
                                               " canonicalize = true\n");
        if (file_contents == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc_asprintf failed while appending to the content\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (udp_limit == true) {
        file_contents = talloc_asprintf_append(file_contents,
                                               " udp_preference_limit = 0\n");
        if (file_contents == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc_asprintf failed while appending to the content\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sss_write_krb5_snippet_common(file_name, file_contents);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_write_krb5_snippet_common failed.\n");
        goto done;
    }

done:

    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_write_krb5_conf_snippet(const char *path, bool canonicalize,
                                    bool udp_limit)
{
    errno_t ret;

    if (path != NULL && (*path == '\0' || strcasecmp(path, "none") == 0)) {
        DEBUG(SSSDBG_TRACE_FUNC, "Empty path, nothing to do.\n");
        return EOK;
    }

    if (path == NULL || *path != '/') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid or missing path [%s]-\n",
                                    path == NULL ? "missing" : path);
        return EINVAL;
    }

    ret = sss_write_krb5_localauth_snippet(path);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_write_krb5_localauth_snippet failed.\n");
        goto done;
    }

    ret = sss_write_krb5_libdefaults_snippet(path, canonicalize, udp_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_write_krb5_libdefaults_snippet failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        sss_krb5_touch_config();
    }

    return ret;
}

static const char *domain_state_str(struct sss_domain_info *dom)
{
    switch (dom->state) {
    case DOM_ACTIVE:
        return "Active";
    case DOM_DISABLED:
        return "Disabled";
    case DOM_INACTIVE:
        return "Inactive";
#ifdef BUILD_FILES_PROVIDER
    case DOM_INCONSISTENT:
        return "Inconsistent";
#endif /* BUILD_FILES_PROVIDER */
    }
    return "Unknown";
}

enum sss_domain_state sss_domain_get_state(struct sss_domain_info *dom)
{
    DEBUG(SSSDBG_TRACE_LIBS,
          "Domain %s is %s\n", dom->name, domain_state_str(dom));
    return dom->state;
}

void sss_domain_set_state(struct sss_domain_info *dom,
                          enum sss_domain_state state)
{
    dom->state = state;
    DEBUG(SSSDBG_TRACE_LIBS,
          "Domain %s is %s\n", dom->name, domain_state_str(dom));
}

#ifdef BUILD_FILES_PROVIDER
bool sss_domain_fallback_to_nss(struct sss_domain_info *dom)
{
    return dom->fallback_to_nss;
}
#endif

bool sss_domain_is_forest_root(struct sss_domain_info *dom)
{
    return (dom->forest_root == dom);
}

char *subdomain_create_conf_path_from_str(TALLOC_CTX *mem_ctx,
                                          const char *parent_name,
                                          const char *subdom_name)
{
    return talloc_asprintf(mem_ctx, CONFDB_DOMAIN_PATH_TMPL "/%s",
                           parent_name, subdom_name);
}

char *subdomain_create_conf_path(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *subdomain)
{
    if (!IS_SUBDOMAIN(subdomain)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "The domain \"%s\" is not a subdomain.\n",
              subdomain->name);
        return NULL;
    }

    return subdomain_create_conf_path_from_str(mem_ctx,
                                               subdomain->parent->name,
                                               subdomain->name);
}

const char *sss_domain_type_str(struct sss_domain_info *dom)
{
    if (dom == NULL) {
        return "BUG: Invalid domain";
    }
    switch (dom->type) {
    case DOM_TYPE_POSIX:
        return "POSIX";
    case DOM_TYPE_APPLICATION:
        return "Application";
    }
    return "Unknown";
}

void sss_domain_info_set_output_fqnames(struct sss_domain_info *domain,
                                        bool output_fqnames)
{
    domain->output_fqnames = output_fqnames;
}

bool sss_domain_info_get_output_fqnames(struct sss_domain_info *domain)
{
    return domain->output_fqnames;
}

bool sss_domain_is_mpg(struct sss_domain_info *domain)
{
    return domain->mpg_mode == MPG_ENABLED;
}

bool sss_domain_is_hybrid(struct sss_domain_info *domain)
{
    return domain->mpg_mode == MPG_HYBRID;
}

enum sss_domain_mpg_mode get_domain_mpg_mode(struct sss_domain_info *domain)
{
    return domain->mpg_mode;
}

const char *str_domain_mpg_mode(enum sss_domain_mpg_mode mpg_mode)
{
    switch (mpg_mode) {
    case MPG_ENABLED:
        return "true";
    case MPG_DISABLED:
        return "false";
    case MPG_HYBRID:
        return "hybrid";
    case MPG_DEFAULT:
        return "default";
    }

    return NULL;
}

enum sss_domain_mpg_mode str_to_domain_mpg_mode(const char *str_mpg_mode)
{
    if (strcasecmp(str_mpg_mode, "FALSE") == 0) {
        return MPG_DISABLED;
    } else if (strcasecmp(str_mpg_mode, "TRUE") == 0) {
        return MPG_ENABLED;
    } else if (strcasecmp(str_mpg_mode, "HYBRID") == 0) {
        return MPG_HYBRID;
    } else if (strcasecmp(str_mpg_mode, "DEFAULT") == 0) {
        return MPG_DEFAULT;
    }


    DEBUG(SSSDBG_MINOR_FAILURE,
          "Invalid value for %s\n, assuming disabled",
          SYSDB_SUBDOMAIN_MPG);
    return MPG_DISABLED;
}
