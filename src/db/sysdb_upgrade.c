/*
    SSSD

    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2008-2011 Simo Sorce <ssorce@redhat.com>
    Copyright (C) 2008-2011 Stephen Gallagher

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

#include "util/util.h"
#include "db/sysdb_private.h"
#include "db/sysdb_autofs.h"
#include "db/sysdb_iphosts.h"
#include "db/sysdb_ipnetworks.h"

struct upgrade_ctx {
    struct ldb_context *ldb;
    const char *new_version;
};

static errno_t commence_upgrade(TALLOC_CTX *mem_ctx, struct ldb_context *ldb,
                                const char *new_ver, struct upgrade_ctx **_ctx)
{
    struct upgrade_ctx *ctx;
    int ret;

    DEBUG(SSSDBG_IMPORTANT_INFO, "UPGRADING DB TO VERSION %s\n", new_ver);

    ctx = talloc(mem_ctx, struct upgrade_ctx);
    if (!ctx) {
        return ENOMEM;
    }

    ctx->ldb = ldb;
    ctx->new_version = new_ver;

    ret = ldb_transaction_start(ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    } else {
        *_ctx = ctx;
    }
    return ret;
}

static errno_t update_version(struct upgrade_ctx *ctx)
{
    struct ldb_message *msg = NULL;
    errno_t ret;

    msg = ldb_msg_new(ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(msg, ctx->ldb, SYSDB_BASE);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "version", ctx->new_version);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);
    return ret;
}

static int finish_upgrade(int ret, struct upgrade_ctx **ctx, const char **ver)
{
    int lret;

    if (ret == EOK) {
        lret = ldb_transaction_commit((*ctx)->ldb);
        ret = sysdb_error_to_errno(lret);
        if (ret == EOK) {
            *ver = (*ctx)->new_version;
        }
    }

    if (ret != EOK) {
        lret = ldb_transaction_cancel((*ctx)->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not cancel transaction! [%s]\n",
                   ldb_strerror(lret));
            /* Do not overwrite ret here, we want to return
             * the original failure, not the failure of the
             * transaction cancellation.
             */
        }
    }

    talloc_zfree(*ctx);
    return ret;
}

int sysdb_upgrade_16(struct sysdb_ctx *sysdb, const char **ver)
{
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;
    errno_t ret;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_17, &ctx);
    if (ret) {
        return ret;
    }

    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* add index for objectSIDString */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", "objectSIDString");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

static char *object_domain_from_dn(TALLOC_CTX *mem_ctx,
                                   struct ldb_dn *dn,
                                   unsigned domain_index)
{
    const struct ldb_val *val;

    val = ldb_dn_get_component_val(dn, domain_index);
    if (val == NULL) {
        return NULL;
    }
    return talloc_strdup(mem_ctx, (const char *) val->data);
}

static char *object_domain(TALLOC_CTX *mem_ctx,
                           struct ldb_context *ldb,
                           struct ldb_message *msg,
                           const char *domain_attr,
                           unsigned domain_index)
{
    struct ldb_dn *dom_dn;

    if (domain_attr != NULL) {
        dom_dn = ldb_msg_find_attr_as_dn(ldb, mem_ctx, msg, domain_attr);
    } else {
        /* If no specific attribute to take the domain from is specified,
         * use the DN */
        dom_dn = msg->dn;
    }

    if (dom_dn == NULL) {
        return NULL;
    }

    return object_domain_from_dn(mem_ctx, dom_dn, domain_index);
}

/* Used for attributes like sudoUser which contain group or user name or
 * ID, depending on the value prefix */
typedef bool (*should_qualify_val_fn)(const char *val);

/* Qualifies a string attribute using domain_name. Optionally, if qfn is
 * given, only qualifies the name if qfn returns true */
static errno_t qualify_attr(struct ldb_message *msg,
                            struct ldb_message *mod_msg,
                            struct sss_names_ctx *names,
                            const char *domain_name,
                            const char *attrname,
                            should_qualify_val_fn qfn)
{
    struct ldb_message_element *el;
    struct ldb_message_element *mod_el;
    char *fqval;
    char *shortname;
    const char *rawname;
    int ret;
    struct ldb_val val;
    bool exists = false;

    el = ldb_msg_find_element(msg, attrname);
    if (el == NULL) {
        /* This entry does not have this element, fine */
        return EOK;
    }

    for (size_t c = 0; c < el->num_values; c++) {
        rawname = (const char *) el->values[c].data;

        if (qfn != NULL && qfn(rawname) == false) {
            continue;
        }

        ret = sss_parse_name(mod_msg, names, rawname, NULL, &shortname);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot parse raw attribute %s\n", rawname);
            continue;
        }

        fqval = sss_create_internal_fqname(el->values, shortname, domain_name);
        talloc_free(shortname);
        if (fqval == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot qualify %s@%s\n",
                  shortname, domain_name);
            continue;
        }


        mod_el = ldb_msg_find_element(mod_msg, attrname);
        if (mod_el != NULL) {
            val.data = (uint8_t *) fqval;
            val.length = strlen(fqval);

            if (ldb_msg_find_val(mod_el, &val) != NULL) {
                return true;
            }
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Qualified %s:%s into %s\n",
              attrname, rawname, fqval);

        if (!exists) {
            ret = ldb_msg_add_empty(mod_msg, attrname, LDB_FLAG_MOD_REPLACE, NULL);
            if (ret != LDB_SUCCESS) {
                continue;
            }

            exists = true;
        }

        ret = ldb_msg_add_steal_string(mod_msg, attrname, fqval);
        if (ret != LDB_SUCCESS) {
            continue;
        }
    }

    return EOK;
}

/* Returns a copy of old_dn_val with RDN qualified. The domain name
 * is read from the DN itself
 */
static struct ldb_dn *qualify_rdn(TALLOC_CTX *mem_ctx,
                                  struct ldb_context *ldb,
                                  struct sss_names_ctx *names,
                                  struct ldb_dn *old_dn_val)
{
    struct ldb_dn *parent_dn = NULL;
    const struct ldb_val *val = NULL;
    const char *rdn_name = NULL;
    struct ldb_dn *new_dn = NULL;
    char *fqrdn = NULL;
    char *shortname = NULL;
    char *dn_domain = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;

    rdn_name = ldb_dn_get_rdn_name(old_dn_val);
    if (rdn_name == NULL) {
        return NULL;
    }

    if (strcmp(rdn_name, SYSDB_NAME) != 0) {
        /* Only qualify DNs with name= rdn. This applies to overrideDNs mostly,
         * because those can contain either names or UUIDs
         */
        return ldb_dn_copy(mem_ctx, old_dn_val);
    }

    val = ldb_dn_get_rdn_val(old_dn_val);
    if (val == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    dn_domain = object_domain_from_dn(tmp_ctx, old_dn_val, 2);
    if (dn_domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot determine domain of %s\n",
              ldb_dn_get_linearized(old_dn_val));
        goto done;
    }

    ret = sss_parse_name(tmp_ctx, names, (const char *) val->data,
                         NULL, &shortname);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot parse raw RDN %s\n", (const char *) val->data);
        goto done;
    }

    fqrdn = sss_create_internal_fqname(tmp_ctx, shortname, dn_domain);
    if (fqrdn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot qualify %s@%s\n",
              shortname, dn_domain);
        goto done;
    }

    parent_dn = ldb_dn_get_parent(tmp_ctx, old_dn_val);
    if (parent_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get parent of %s\n",
              ldb_dn_get_linearized(old_dn_val));
        goto done;
    }

    new_dn = ldb_dn_new_fmt(mem_ctx, ldb, "%s=%s,%s",
                            rdn_name, fqrdn,
                            ldb_dn_get_linearized(parent_dn));
done:
    talloc_free(tmp_ctx);
    return new_dn;
}

static errno_t qualify_dn_attr(struct ldb_context *ldb,
                               struct ldb_message *msg,
                               struct ldb_message *mod_msg,
                               struct sss_names_ctx *names,
                               const char *attrname)
{
    struct ldb_message_element *el;
    struct ldb_message_element *mod_el;
    struct ldb_dn *attr_dn;
    struct ldb_dn *fqdn;
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;

    el = ldb_msg_find_element(msg, attrname);
    if (el == NULL || el->num_values == 0) {
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    for (size_t c = 0; c < el->num_values; c++) {
        attr_dn = ldb_dn_new(tmp_ctx, ldb, (const char *) el->values[c].data);
        if (attr_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot create DN from %s\n",
                  (const char *) el->values[c].data);
            continue;
        }

        if (!ldb_dn_validate(attr_dn)) {
            DEBUG(SSSDBG_OP_FAILURE, "DN %s does not validate\n",
                  (const char *) el->values[c].data);
            continue;
        }

        fqdn = qualify_rdn(tmp_ctx, ldb, names, attr_dn);
        if (fqdn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot qualify %s\n",
                  (const char *) el->values[c].data);
            continue;
        }

        ret = ldb_msg_add_linearized_dn(mod_msg, attrname, fqdn);
        if (ret != LDB_SUCCESS) {
            continue;
        }

        talloc_free(attr_dn);
        talloc_free(fqdn);
    }

    mod_el = ldb_msg_find_element(mod_msg, attrname);
    if (mod_el != NULL) {
        mod_el->flags = LDB_FLAG_MOD_REPLACE;
    }

    talloc_free(tmp_ctx);
    return EOK;
}

static errno_t expire_object(struct ldb_message *object,
                             struct ldb_message *mod_msg)
{
    errno_t ret;
    struct ldb_message_element *el;
    const char *attrs[] = { SYSDB_CACHE_EXPIRE,
                            SYSDB_LAST_UPDATE,
                            SYSDB_INITGR_EXPIRE,
                            NULL
    };

    for (size_t c = 0; attrs[c] != NULL; c++) {
        el = ldb_msg_find_element(object, attrs[c]);
        if (el == NULL) {
            continue;
        }

        ret = ldb_msg_add_empty(mod_msg, attrs[c], LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            return ret;
        }

        ret = ldb_msg_add_fmt(mod_msg, attrs[c], "%d", 1);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return EOK;
}

static errno_t qualify_object(TALLOC_CTX *mem_ctx,
                              struct ldb_context *ldb,
                              struct sss_names_ctx *names,
                              struct ldb_message *object,
                              bool qualify_dn,
                              const char *domain_attr,
                              unsigned domain_index,
                              const char *name_attrs[],
                              const char *dn_attrs[],
                              should_qualify_val_fn qfn)
{
    int ret;
    struct ldb_message *mod_msg = NULL;
    struct ldb_dn *new_object_dn = NULL;
    const char *dom_name;

    mod_msg = ldb_msg_new(mem_ctx);
    if (mod_msg == NULL) {
        return ENOMEM;
    }
    mod_msg->dn = object->dn;

    dom_name = object_domain(mod_msg, ldb, object, domain_attr, domain_index);
    if (dom_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot determine domain of %s\n",
              ldb_dn_get_linearized(mod_msg->dn));
        return EINVAL;
    }

    if (name_attrs != NULL) {
        for (size_t c = 0; name_attrs[c]; c++) {
            ret = qualify_attr(object, mod_msg, names,
                               dom_name, name_attrs[c], qfn);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot qualify %s of %s\n",
                      name_attrs[c], ldb_dn_get_linearized(object->dn));
                continue;
            }
        }
    }

    if (dn_attrs != NULL) {
        for (size_t c = 0; dn_attrs[c]; c++) {
            ret = qualify_dn_attr(ldb, object, mod_msg,
                                  names, dn_attrs[c]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot qualify %s of %s\n",
                      dn_attrs[c], ldb_dn_get_linearized(object->dn));
            }
        }
    }

    ret = expire_object(object, mod_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot expire %s\n", ldb_dn_get_linearized(object->dn));
    }

    /* Override objects can contain both qualified and non-qualified names.
     * Need to use permissive modification here, otherwise we might attempt
     * to store duplicate qualified names
     */
    ret = sss_ldb_modify_permissive(ldb, mod_msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot modify %s\n",  ldb_dn_get_linearized(object->dn));
        goto done;
    }

    if (qualify_dn) {
        new_object_dn = qualify_rdn(mod_msg, ldb, names, mod_msg->dn);
        if (new_object_dn == NULL) {
            ret = EIO;
            goto done;
        }

        ret = ldb_rename(ldb, object->dn, new_object_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot rename %s to %s\n",
                  ldb_dn_get_linearized(object->dn),
                  ldb_dn_get_linearized(new_object_dn));
            goto done;
        }
    }

    ret = EOK;
done:
    talloc_free(mod_msg);
    return ret;
}

static void qualify_objects(struct upgrade_ctx *ctx,
                            struct ldb_context *ldb,
                            struct sss_names_ctx *names,
                            struct ldb_dn *base_dn,
                            bool qualify_dn,
                            const char *domain_attr,
                            unsigned domain_index,
                            const char *filter,
                            const char *name_attrs[],
                            const char *dn_attrs[],
                            should_qualify_val_fn qfn)
{
    errno_t ret;
    struct ldb_result *objects = NULL;
    const char *attrs[] = { "*", NULL };

    ret = ldb_search(ldb, ctx, &objects, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, "%s", filter);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to search objects: %d\n", ret);
        return;
    }

    if (objects == NULL || objects->count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "No match for: %s\n", filter);
        return;
    }

    for (size_t c = 0; c < objects->count; c++) {
        ret = qualify_object(ctx, ldb, names, objects->msgs[c],
                             qualify_dn, domain_attr, domain_index,
                             name_attrs, dn_attrs, qfn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not qualify object %s: %d\n",
                  ldb_dn_get_linearized(objects->msgs[c]->dn), ret);
            continue;
        }
    }
    talloc_free(objects);
}

static void qualify_users(struct upgrade_ctx *ctx,
                          struct ldb_context *ldb,
                          struct sss_names_ctx *names,
                          struct ldb_dn *base_dn)
{
    /* No change needed because this version has objectclass user */
    const char *user_filter = "objectclass=user";
    const char *user_name_attrs[] = { SYSDB_NAME,
                                      SYSDB_NAME_ALIAS,
                                      SYSDB_DEFAULT_OVERRIDE_NAME,
                                      ORIGINALAD_PREFIX SYSDB_NAME,
                                      NULL
    };
    const char *user_dn_attrs[] = { SYSDB_MEMBEROF,
                                    SYSDB_OVERRIDE_DN,
                                    NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn,
                           true,        /* qualify dn */
                           NULL,        /* no special domain attr, use DN */
                           2,           /* DN's domain is third RDN from top */
                           user_filter,
                           user_name_attrs, user_dn_attrs, NULL);
}

static void qualify_groups(struct upgrade_ctx *ctx,
                           struct ldb_context *ldb,
                           struct sss_names_ctx *names,
                           struct ldb_dn *base_dn)
{
    /* No change needed because this version has objectclass group */
    const char *group_filter = "objectclass=group";
    const char *group_name_attrs[] = { SYSDB_NAME,
                                       SYSDB_NAME_ALIAS,
                                       SYSDB_DEFAULT_OVERRIDE_NAME,
                                       ORIGINALAD_PREFIX SYSDB_NAME,
                                       SYSDB_MEMBERUID,
                                       SYSDB_GHOST,
                                       NULL
    };
    const char *group_dn_attrs[] = { SYSDB_MEMBER,
                                     SYSDB_MEMBEROF,
                                     SYSDB_OVERRIDE_DN,
                                     NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn, true,
                           NULL, 2, group_filter,
                           group_name_attrs, group_dn_attrs, NULL);
}

static void qualify_user_overrides(struct upgrade_ctx *ctx,
                                   struct ldb_context *ldb,
                                   struct sss_names_ctx *names,
                                   struct ldb_dn *base_dn)
{
    const char *user_override_filter = "objectclass=userOverride";
    const char *user_ovr_name_attrs[] = { SYSDB_NAME,
                                          SYSDB_NAME_ALIAS,
                                          NULL
    };
    const char *user_ovr_dn_attrs[] = { SYSDB_OVERRIDE_OBJECT_DN,
                                        NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn,
                           /* Don't qualify RDN of override DN */
                           false,
                           /* Read domain from override DN */
                           SYSDB_OVERRIDE_OBJECT_DN,
                           2, /* Third RDN from top is domain */
                           user_override_filter, user_ovr_name_attrs,
                           user_ovr_dn_attrs, NULL);
}

static void qualify_group_overrides(struct upgrade_ctx *ctx,
                                    struct ldb_context *ldb,
                                    struct sss_names_ctx *names,
                                    struct ldb_dn *base_dn)
{
    const char *group_override_filter = "objectclass=groupOverride";
    const char *group_ovr_name_attrs[] = { SYSDB_NAME,
                                           SYSDB_NAME_ALIAS,
                                           NULL
    };
    const char *group_ovr_dn_attrs[] = { SYSDB_OVERRIDE_OBJECT_DN,
                                         NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn,
                           false, SYSDB_OVERRIDE_OBJECT_DN, 2,
                           group_override_filter, group_ovr_name_attrs,
                           group_ovr_dn_attrs, NULL);
}

static void qualify_sudo_rules(struct upgrade_ctx *ctx,
                               struct ldb_context *ldb,
                               struct sss_names_ctx *names,
                               struct ldb_dn *base_dn)
{
    const char *group_override_filter = "objectclass=sudoRule";
    const char *sudo_rule_name_attrs[] = { "sudoUser",
                                            NULL
    };

    return qualify_objects(ctx, ldb, names, base_dn,
                           false, NULL, 3,
                           group_override_filter, sudo_rule_name_attrs,
                           NULL, is_user_or_group_name);
}


int sysdb_upgrade_17(struct sysdb_ctx *sysdb,
                     struct sysdb_dom_upgrade_ctx *upgrade_ctx,
                     const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret, envret;
    struct ldb_dn *base_dn;
    struct sss_names_ctx *names = upgrade_ctx->names;

    if (names == NULL) {
        return EINVAL;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_18, &ctx);
    if (ret) {
        return ret;
    }

    /* Disable memberof plugin during this update */
    ret = setenv("SSSD_UPGRADE_DB", "1", 1);
    if (ret != 0) {
        goto done;
    }

    base_dn = ldb_dn_new_fmt(ctx, sysdb->ldb, SYSDB_BASE);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    qualify_users(ctx, sysdb->ldb, names, base_dn);
    qualify_groups(ctx, sysdb->ldb, names, base_dn);
    qualify_user_overrides(ctx, sysdb->ldb, names, base_dn);
    qualify_group_overrides(ctx, sysdb->ldb, names, base_dn);
    qualify_sudo_rules(ctx, sysdb->ldb, names, base_dn);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    envret = unsetenv("SSSD_UPGRADE_DB");
    if (envret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot unset SSSD_UPGRADE_DB, SSSD might not work correctly\n");
    }
    return ret;
}

int sysdb_upgrade_18(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;
    struct ldb_message *msg = NULL;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_19, &ctx);
    if (ret) {
        return ret;
    }

    /* Add missing indices */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_GHOST);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_UPN);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_CANONICAL_UPN);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_UUID);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_USER_EMAIL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

static errno_t add_object_category(struct ldb_context *ldb,
                                   struct upgrade_ctx *ctx)
{
    errno_t ret;
    struct ldb_result *objects = NULL;
    const char *attrs[] = { SYSDB_OBJECTCLASS, NULL };
    struct ldb_dn *base_dn;
    size_t c;
    const char *class_name;
    struct ldb_message *msg = NULL;
    struct ldb_message *del_msg = NULL;

    base_dn = ldb_dn_new(ctx, ldb, SYSDB_BASE);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed create base dn.\n");
        return ENOMEM;
    }

    ret = ldb_search(ldb, ctx, &objects, base_dn,
                     LDB_SCOPE_SUBTREE, attrs,
                     "(|("SYSDB_OBJECTCLASS"="SYSDB_USER_CLASS")"
                       "("SYSDB_OBJECTCLASS"="SYSDB_GROUP_CLASS"))");
    talloc_free(base_dn);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to search objects: %d\n", ret);
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (objects == NULL || objects->count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "No objects found, nothing to do.\n");
        ret = EOK;
        goto done;
    }

    del_msg = ldb_msg_new(ctx);
    if (del_msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_empty(del_msg, SYSDB_OBJECTCLASS, LDB_FLAG_MOD_DELETE,
                            NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Found [%d] objects.\n", objects->count);
    for (c = 0; c < objects->count; c++) {
        DEBUG(SSSDBG_TRACE_ALL, "Updating [%s].\n",
              ldb_dn_get_linearized(objects->msgs[c]->dn));

        class_name = ldb_msg_find_attr_as_string(objects->msgs[c],
                                                 SYSDB_OBJECTCLASS, NULL);
        if (class_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Searched objects by objectClass, "
                                     "but result does not have one.\n");
            ret = EINVAL;
            goto done;
        }

        talloc_free(msg);
        msg = ldb_msg_new(ctx);
        if (msg == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        msg->dn = objects->msgs[c]->dn;
        del_msg->dn = objects->msgs[c]->dn;

        ret = ldb_msg_add_empty(msg, SYSDB_OBJECTCATEGORY, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_OBJECTCATEGORY, class_name);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_string failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL, "Adding [%s] to [%s].\n", class_name,
              ldb_dn_get_linearized(objects->msgs[c]->dn));
        ret = ldb_modify(ldb, msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add objectCategory to %s: %d.\n",
                  ldb_dn_get_linearized(objects->msgs[c]->dn),
                  sysdb_error_to_errno(ret));
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_modify(ldb, del_msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to remove objectClass from %s: %d.\n",
                  ldb_dn_get_linearized(objects->msgs[c]->dn),
                  sysdb_error_to_errno(ret));
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(msg);
    talloc_free(del_msg);
    talloc_free(objects);

    return ret;
}

int sysdb_upgrade_19(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;
    struct ldb_message *msg = NULL;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_20, &ctx);
    if (ret) {
        return ret;
    }

    ret = add_object_category(sysdb->ldb, ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "add_object_category failed: %d\n", ret);
        goto done;
    }

    /* Remove @IDXONE from index */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXONE", LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_USER_MAPPED_CERT);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

int sysdb_upgrade_20(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;
    struct ldb_message *msg = NULL;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_21, &ctx);
    if (ret) {
        return ret;
    }

    /* Add missing indices */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_CCACHE_FILE);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

int sysdb_upgrade_21(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_22, &ctx);
    if (ret) {
        return ret;
    }

    /* Case insensitive search for ipHostNumber and ipNetworkNumber */
    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_IP_HOST_ATTR_ADDRESS, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_IP_HOST_ATTR_ADDRESS, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_IP_NETWORK_ATTR_NUMBER,
                            LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_IP_NETWORK_ATTR_NUMBER,
                             "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_zfree(msg);

    /* Add new indexes */
    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Add Index for ipHostNumber */
    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_IP_HOST_ATTR_ADDRESS);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_IP_NETWORK_ATTR_NUMBER);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_22(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;
    struct ldb_message *msg = NULL;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_23, &ctx);
    if (ret) {
        return ret;
    }

    /* Add missing indices */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_ORIG_AD_GID_NUMBER);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

int sysdb_upgrade_23(struct sysdb_ctx *sysdb, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;
    struct upgrade_ctx *ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_24, &ctx);
    if (ret) {
        return ret;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Case insensitive search for mail */
    ret = ldb_msg_add_empty(msg, SYSDB_USER_EMAIL, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, SYSDB_USER_EMAIL, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    /* Case insensitive search for gpoGUID */
    ret = ldb_msg_add_empty(msg, SYSDB_GPO_GUID_ATTR, LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, SYSDB_GPO_GUID_ATTR, "CASE_INSENSITIVE");
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* Add new indices */
    msg = ldb_msg_new(ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(msg, sysdb->ldb, "@INDEXLIST");
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "@IDXATTR", LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "@IDXATTR", SYSDB_GPO_GUID_ATTR);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_free(msg);

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_upgrade_24(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_25, &ctx);
    if (ret) {
        return ret;
    }

    ret = sysdb_ldb_mod_index(sysdb, SYSDB_IDX_DELETE, sysdb->ldb, "dataExpireTimestamp");
    if (ret == ENOENT) { /*nothing to delete */
        ret = EOK;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "sysdb_ldb_mod_index() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}

/*
 * Example template for future upgrades.
 * Copy and change version numbers as appropriate.
 */
#if 0

int sysdb_upgrade_13(struct sysdb_ctx *sysdb, const char **ver)
{
    struct upgrade_ctx *ctx;
    errno_t ret;

    ret = commence_upgrade(sysdb, sysdb->ldb, SYSDB_VERSION_0_14, &ctx);
    if (ret) {
        return ret;
    }

    /* DO STUFF HERE (use ctx, as the local temporary memory context) */

    /* conversion done, update version number */
    ret = update_version(ctx);

done:
    ret = finish_upgrade(ret, &ctx, ver);
    return ret;
}
#endif
