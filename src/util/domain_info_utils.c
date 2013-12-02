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

#include <utime.h>

#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "util/util.h"

/* the directory domain - realm mappings are written to */
#define KRB5_MAPPING_DIR PUBCONF_PATH"/krb5.include.d"

struct sss_domain_info *get_domains_head(struct sss_domain_info *domain)
{
    struct sss_domain_info *dom = NULL;

    /* get to the top level domain */
    for (dom = domain; dom->parent != NULL; dom = dom->parent);

    /* proceed to the list head */
    for (; dom->prev != NULL; dom = dom->prev);

    return dom;
}

struct sss_domain_info *get_next_domain(struct sss_domain_info *domain,
                                        bool descend)
{
    struct sss_domain_info *dom;

    dom = domain;
    while (dom) {
        if (descend && dom->subdomains) {
            dom = dom->subdomains;
        } else if (dom->next) {
            dom = dom->next;
        } else if (descend && IS_SUBDOMAIN(dom) && dom->parent->next) {
            dom = dom->parent->next;
        } else {
            dom = NULL;
        }
        if (dom && !dom->disabled) break;
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

struct sss_domain_info *find_subdomain_by_name(struct sss_domain_info *domain,
                                               const char *name,
                                               bool match_any)
{
    struct sss_domain_info *dom = domain;

    if (name == NULL) {
        return NULL;
    }

    while (dom && dom->disabled) {
        dom = get_next_domain(dom, true);
    }
    while (dom) {
        if (strcasecmp(dom->name, name) == 0 ||
            ((match_any == true) && (dom->flat_name != NULL) &&
             (strcasecmp(dom->flat_name, name) == 0))) {
            return dom;
        }
        dom = get_next_domain(dom, true);
    }

    return NULL;
}

struct sss_domain_info *find_subdomain_by_sid(struct sss_domain_info *domain,
                                              const char *sid)
{
    struct sss_domain_info *dom = domain;
    size_t sid_len;
    size_t dom_sid_len;

    if (sid == NULL) {
        return NULL;
    }

    sid_len = strlen(sid);

    while (dom && dom->disabled) {
        dom = get_next_domain(dom, true);
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

        dom = get_next_domain(dom, true);
    }

    return NULL;
}

struct sss_domain_info *
find_subdomain_by_object_name(struct sss_domain_info *domain,
                              const char *object_name)
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

    ret = sss_parse_name(tmp_ctx, domain->names, object_name,
                         &domainname, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse name '%s' [%d]: %s\n",
                                    object_name, ret, sss_strerror(ret));
        goto done;
    }

    if (domainname == NULL) {
        dom = domain;
    } else {
        dom = find_subdomain_by_name(domain, domainname, true);
    }

done:
    talloc_free(tmp_ctx);
    return dom;
}

struct sss_domain_info *new_subdomain(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *parent,
                                      const char *name,
                                      const char *realm,
                                      const char *flat_name,
                                      const char *id,
                                      bool mpg,
                                      bool enumerate,
                                      const char *forest)
{
    struct sss_domain_info *dom;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Creating [%s] as subdomain of [%s]!\n", name, parent->name);

    dom = talloc_zero(mem_ctx, struct sss_domain_info);
    if (dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return NULL;
    }

    dom->parent = parent;
    dom->name = talloc_strdup(dom, name);
    if (dom->name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy domain name.\n");
        goto fail;
    }

    dom->provider = talloc_strdup(dom, parent->provider);
    if (dom->provider == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy provider name.\n");
        goto fail;
    }

    dom->conn_name = talloc_strdup(dom, parent->conn_name);
    if (dom->conn_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy connection name.\n");
        goto fail;
    }

    if (realm != NULL) {
        dom->realm = talloc_strdup(dom, realm);
        if (dom->realm == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy realm name.\n");
            goto fail;
        }
    }

    if (flat_name != NULL) {
        dom->flat_name = talloc_strdup(dom, flat_name);
        if (dom->flat_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy flat name.\n");
            goto fail;
        }
    }

    if (id != NULL) {
        dom->domain_id = talloc_strdup(dom, id);
        if (dom->domain_id == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy id.\n");
            goto fail;
        }
    }

    if (forest != NULL) {
        dom->forest = talloc_strdup(dom, forest);
        if (dom->forest == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy forest.\n");
            goto fail;
        }
    }

    dom->enumerate = enumerate;
    dom->fqnames = true;
    dom->mpg = mpg;
    /* If the parent domain explicitly limits ID ranges, the subdomain
     * should honour the limits as well.
     */
    dom->id_min = parent->id_min ? parent->id_min : 0;
    dom->id_max = parent->id_max ? parent->id_max : 0xffffffff;
    dom->pwd_expiration_warning = parent->pwd_expiration_warning;
    dom->cache_credentials = parent->cache_credentials;
    dom->case_sensitive = false;
    dom->user_timeout = parent->user_timeout;
    dom->group_timeout = parent->group_timeout;
    dom->netgroup_timeout = parent->netgroup_timeout;
    dom->service_timeout = parent->service_timeout;
    dom->names = parent->names;

    dom->override_homedir = parent->override_homedir;
    dom->fallback_homedir = parent->fallback_homedir;
    dom->subdomain_homedir = parent->subdomain_homedir;
    dom->override_shell = parent->override_shell;
    dom->default_shell = parent->default_shell;
    dom->homedir_substr = parent->homedir_substr;

    if (parent->sysdb == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing sysdb context in parent domain.\n");
        goto fail;
    }
    dom->sysdb = parent->sysdb;

    return dom;

fail:
    talloc_free(dom);
    return NULL;
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

static errno_t
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to change mtime of \"%s\" "
                                    "[%d]: %s\n", config, ret, strerror(ret));
        return ret;
    }

    return EOK;
}

errno_t
sss_write_domain_mappings(struct sss_domain_info *domain, bool add_capaths)
{
    struct sss_domain_info *dom;
    struct sss_domain_info *parent_dom;
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
    bool capaths_started;
    char *uc_forest;
    char *uc_parent;

    if (domain == NULL || domain->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No domain name provided\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

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

    tmp_file = talloc_asprintf(tmp_ctx, "%sXXXXXX", mapping_file);
    if (tmp_file == NULL) {
        ret = ENOMEM;
        goto done;
    }

    old_mode = umask(077);
    fd = mkstemp(tmp_file);
    umask(old_mode);
    if (fd < 0) {
        DEBUG(SSSDBG_OP_FAILURE, "creating the temp file [%s] for domain-realm "
                                  "mappings failed.", tmp_file);
        ret = EIO;
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

    ret = fprintf(fstream, "[domain_realm]\n");
    if (ret < 0) {
        DEBUG(SSSDBG_OP_FAILURE, "fprintf failed\n");
        ret = EIO;
        goto done;
    }

    for (dom = get_next_domain(domain, true);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, false)) {
        ret = fprintf(fstream, ".%s = %s\n%s = %s\n",
                               dom->name, dom->realm, dom->name, dom->realm);
        if (ret < 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "fprintf failed\n");
            goto done;
        }
    }

    if (add_capaths) {
        capaths_started = false;
        parent_dom = domain;
        uc_parent = get_uppercase_realm(tmp_ctx, parent_dom->name);
        if (uc_parent == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "get_uppercase_realm failed.\n");
            ret = ENOMEM;
            goto done;
        }

        for (dom = get_next_domain(domain, true);
             dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
             dom = get_next_domain(dom, false)) {

            if (dom->forest == NULL) {
                continue;
            }

            uc_forest = get_uppercase_realm(tmp_ctx, dom->forest);
            if (uc_forest == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "get_uppercase_realm failed.\n");
                ret = ENOMEM;
                goto done;
            }

            if (!capaths_started) {
                ret = fprintf(fstream, "[capaths]\n");
                if (ret < 0) {
                    DEBUG(SSSDBG_OP_FAILURE, "fprintf failed\n");
                    ret = EIO;
                    goto done;
                }
                capaths_started = true;
            }

            ret = fprintf(fstream, "%s = {\n  %s = %s\n}\n%s = {\n  %s = %s\n}\n",
                                   dom->realm, uc_parent, uc_forest,
                                   uc_parent, dom->realm, uc_forest);
            if (ret < 0) {
                DEBUG(SSSDBG_CRIT_FAILURE, "fprintf failed\n");
                goto done;
            }
        }
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
    err = sss_krb5_touch_config();
    if (err != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to change last modification time "
              "of krb5.conf. Created mappings may not be loaded.\n");
        /* Ignore */
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
                  "Could not remove file [%s]: [%d]: %s",
                   tmp_file, err, strerror(err));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}
