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

#include "util/util.h"
#include "util/dlinklist.h"
#include "providers/ldap/sdap_idmap.h"
#include "util/util_sss_idmap.h"

static errno_t
sdap_idmap_get_configured_external_range(struct sdap_idmap_ctx *idmap_ctx,
                                         struct sss_idmap_range *range)
{
    int int_id;
    struct sdap_id_ctx *id_ctx;
    uint32_t min;
    uint32_t max;

    if (idmap_ctx == NULL) {
        return EINVAL;
    }

    id_ctx = idmap_ctx->id_ctx;

    int_id = dp_opt_get_int(id_ctx->opts->basic, SDAP_MIN_ID);
    if (int_id < 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "ldap_min_id must be greater than 0.\n");
        return EINVAL;
    }
    min = int_id;

    int_id = dp_opt_get_int(id_ctx->opts->basic, SDAP_MAX_ID);
    if (int_id < 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "ldap_max_id must be greater than 0.\n");
        return EINVAL;
    }
    max = int_id;

    if ((min == 0 && max != 0) || (min != 0 && max == 0)) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Both ldap_min_id and ldap_max_id " \
                                     "either must be 0 (not set) " \
                                     "or positive integers.\n");
        return EINVAL;
    }

    if (min == 0 && max == 0) {
        /* ldap_min_id and ldap_max_id not set, using min_id and max_id */
        min = id_ctx->be->domain->id_min;
        max = id_ctx->be->domain->id_max;
        if (max == 0) {
            max = UINT32_MAX;
        }
    }

    range->min = min;
    range->max =max;

    return EOK;
}

static errno_t
sdap_idmap_add_configured_external_range(struct sdap_idmap_ctx *idmap_ctx)
{
    int ret;
    struct sss_idmap_range range;
    struct sdap_id_ctx *id_ctx;
    enum idmap_error_code err;

    ret = sdap_idmap_get_configured_external_range(idmap_ctx, &range);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_idmap_get_configured_external_range failed.\n");
        return ret;
    }

    id_ctx = idmap_ctx->id_ctx;

    err = sss_idmap_add_auto_domain_ex(idmap_ctx->map,
                                       id_ctx->be->domain->name,
                                       id_ctx->be->domain->domain_id, &range,
                                       NULL, 0, true, NULL, NULL);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not add domain [%s] to the map: [%d]\n",
               id_ctx->be->domain->name, err);
        return EIO;
    }

    return EOK;
}

errno_t sdap_idmap_find_new_domain(struct sdap_idmap_ctx *idmap_ctx,
                                   const char *dom_name,
                                   const char *dom_sid_str)
{
    int ret;

    ret = sdap_idmap_add_domain(idmap_ctx,
                                dom_name, dom_sid_str,
                                -1);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not add new domain [%s]\n", dom_name);
        return ret;
    }

    return EOK;
}

errno_t
sdap_idmap_init(TALLOC_CTX *mem_ctx,
                struct sdap_id_ctx *id_ctx,
                struct sdap_idmap_ctx **_idmap_ctx)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    enum idmap_error_code err;
    size_t i;
    struct ldb_result *res;
    const char *dom_name;
    const char *sid_str;
    id_t slice_num;
    id_t idmap_lower;
    id_t idmap_upper;
    id_t rangesize;
    bool autorid_mode;
    int extra_slice_init;
    struct sdap_idmap_ctx *idmap_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    idmap_ctx = talloc_zero(tmp_ctx, struct sdap_idmap_ctx);
    if (!idmap_ctx) {
        ret = ENOMEM;
        goto done;
    }
    idmap_ctx->id_ctx = id_ctx;
    idmap_ctx->find_new_domain = sdap_idmap_find_new_domain;

    idmap_lower = dp_opt_get_int(idmap_ctx->id_ctx->opts->basic,
                                 SDAP_IDMAP_LOWER);
    idmap_upper = dp_opt_get_int(idmap_ctx->id_ctx->opts->basic,
                                 SDAP_IDMAP_UPPER);
    rangesize = dp_opt_get_int(idmap_ctx->id_ctx->opts->basic,
                               SDAP_IDMAP_RANGESIZE);
    autorid_mode = dp_opt_get_bool(idmap_ctx->id_ctx->opts->basic,
                                   SDAP_IDMAP_AUTORID_COMPAT);
    extra_slice_init = dp_opt_get_int(idmap_ctx->id_ctx->opts->basic,
                                     SDAP_IDMAP_EXTRA_SLICE_INIT);

    /* Validate that the values make sense */
    if (rangesize <= 0
            || idmap_upper <= idmap_lower
            || (idmap_upper-idmap_lower) < rangesize)
    {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid settings for range selection: "
               "[%"SPRIid"][%"SPRIid"][%"SPRIid"]\n",
               idmap_lower, idmap_upper, rangesize);
        ret = EINVAL;
        goto done;
    }

    if (((idmap_upper - idmap_lower) % rangesize) != 0) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Range size does not divide evenly. Uppermost range will "
               "not be used\n");
    }

    /* Initialize the map */
    err = sss_idmap_init(sss_idmap_talloc, idmap_ctx,
                         sss_idmap_talloc_free,
                         &idmap_ctx->map);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not initialize the ID map: [%s]\n",
               idmap_error_string(err));
        if (err == IDMAP_OUT_OF_MEMORY) {
            ret = ENOMEM;
        } else {
            ret = EINVAL;
        }
        goto done;
    }

    err = sss_idmap_ctx_set_autorid(idmap_ctx->map, autorid_mode);
    err |= sss_idmap_ctx_set_lower(idmap_ctx->map, idmap_lower);
    err |= sss_idmap_ctx_set_upper(idmap_ctx->map, idmap_upper);
    err |= sss_idmap_ctx_set_rangesize(idmap_ctx->map, rangesize);
    err |= sss_idmap_ctx_set_extra_slice_init(idmap_ctx->map, extra_slice_init);
    if (err != IDMAP_SUCCESS) {
        /* This should never happen */
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_idmap_ctx corrupted\n");
        ret = EIO;
        goto done;
    }


    /* Setup range for externally managed IDs, i.e. IDs are read from the
     * ldap_user_uid_number and ldap_group_gid_number attributes. */
    if (!dp_opt_get_bool(idmap_ctx->id_ctx->opts->basic, SDAP_ID_MAPPING)) {
        ret = sdap_idmap_add_configured_external_range(idmap_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_idmap_add_configured_external_range failed.\n");
            goto done;
        }
    }

    /* Read in any existing mappings from the cache */
    ret = sysdb_idmap_get_mappings(tmp_ctx, id_ctx->be->domain, &res);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not read ID mappings from the cache: [%s]\n",
               strerror(ret));
        goto done;
    }

    if (ret == EOK) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Initializing [%d] domains for ID-mapping\n", res->count);

        for (i = 0; i < res->count; i++) {
            dom_name = ldb_msg_find_attr_as_string(res->msgs[i],
                                                   SYSDB_NAME,
                                                   NULL);
            if (!dom_name) {
                /* This should never happen */
                ret = EINVAL;
                goto done;
            }

            sid_str = ldb_msg_find_attr_as_string(res->msgs[i],
                                                  SYSDB_IDMAP_SID_ATTR,
                                                  NULL);
            if (!sid_str) {
                /* This should never happen */
                ret = EINVAL;
                goto done;
            }

            slice_num = ldb_msg_find_attr_as_int(res->msgs[i],
                                                 SYSDB_IDMAP_SLICE_ATTR,
                                                 -1);
            if (slice_num == -1) {
                /* This should never happen */
                ret = EINVAL;
                goto done;
            }

            ret = sdap_idmap_add_domain(idmap_ctx, dom_name,
                                        sid_str, slice_num);
            if (ret != EOK) {
                if (ret == EINVAL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Could not add domain [%s][%s][%"SPRIid"] "
                          "to ID map: [%s] "
                          "Unexpected ID map configuration. Check ID map related "
                          "parameters in sssd.conf and remove the sssd cache if "
                          "some of these parameters were changed recently.\n",
                          dom_name, sid_str, slice_num, strerror(ret));
                } else {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Could not add domain [%s][%s][%"SPRIid"] "
                          "to ID map: [%s]\n",
                          dom_name, sid_str, slice_num, strerror(ret));
                }

                goto done;
            }
        }
    } else {
        /* This is the first time we're setting up id-mapping
         * Store the default domain as slice 0
         */
        dom_name = dp_opt_get_string(idmap_ctx->id_ctx->opts->basic, SDAP_IDMAP_DEFAULT_DOMAIN);
        if (!dom_name) {
            /* If it's not explicitly specified, use the SSSD domain name */
            dom_name = idmap_ctx->id_ctx->be->domain->name;
            ret = dp_opt_set_string(idmap_ctx->id_ctx->opts->basic,
                                    SDAP_IDMAP_DEFAULT_DOMAIN,
                                    dom_name);
            if (ret != EOK) goto done;
        }

        sid_str = dp_opt_get_string(idmap_ctx->id_ctx->opts->basic, SDAP_IDMAP_DEFAULT_DOMAIN_SID);
        if (sid_str) {
            struct sss_domain_info *domain = idmap_ctx->id_ctx->be->domain;
            domain->domain_id = talloc_strdup(domain, sid_str);
            if (domain->domain_id == NULL) {
                ret = ENOMEM;
                goto done;
            }

            /* Set the default domain as slice 0 */
            ret = sdap_idmap_add_domain(idmap_ctx, dom_name,
                                        sid_str, 0);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not add domain [%s][%s][%u] to ID map: [%s]\n",
                       dom_name, sid_str, 0, strerror(ret));
                goto done;
            }
        } else {
            if (dp_opt_get_bool(idmap_ctx->id_ctx->opts->basic, SDAP_IDMAP_AUTORID_COMPAT)) {
                /* In autorid compatibility mode, we MUST have a slice 0 */
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "WARNING: Autorid compatibility mode selected, "
                       "but %s is not set. UID/GID values may differ "
                       "between clients.\n",
                       idmap_ctx->id_ctx->opts->basic[SDAP_IDMAP_DEFAULT_DOMAIN_SID].opt_name);
            }
            /* Otherwise, we'll just fall back to hash values as they are seen */
        }
    }

    *_idmap_ctx = talloc_steal(mem_ctx, idmap_ctx);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sdap_idmap_add_domain(struct sdap_idmap_ctx *idmap_ctx,
                      const char *dom_name,
                      const char *dom_sid,
                      id_t slice)
{
    errno_t ret;
    struct sss_idmap_range range;
    enum idmap_error_code err;
    id_t idmap_upper;
    bool external_mapping = true;

    ret = sss_idmap_ctx_get_upper(idmap_ctx->map, &idmap_upper);
    if (ret != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get upper bound of available ID range.\n");
        ret = EIO;
        goto done;
    }

    if (dp_opt_get_bool(idmap_ctx->id_ctx->opts->basic, SDAP_ID_MAPPING)) {
        external_mapping = false;
        ret = sss_idmap_calculate_range(idmap_ctx->map, dom_sid, &slice, &range);
        if (ret != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to calculate range for domain [%s]: [%d]\n", dom_name,
                   ret);
            ret = EIO;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_LIBS,
              "Adding domain [%s] as slice [%"SPRIid"]\n", dom_sid, slice);

        if (range.max > idmap_upper) {
            /* This should never happen */
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "BUG: Range maximum exceeds the global maximum: "
                   "%u > %"SPRIid"\n", range.max, idmap_upper);
            ret = EINVAL;
            goto done;
        }
    } else {
        ret = sdap_idmap_get_configured_external_range(idmap_ctx, &range);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_idmap_get_configured_external_range failed.\n");
            return ret;
        }
    }

    /* Add this domain to the map */
    err = sss_idmap_add_auto_domain_ex(idmap_ctx->map, dom_name, dom_sid,
                                       &range, NULL, 0, external_mapping,
                                       NULL, NULL);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not add domain [%s] to the map: [%d]\n",
               dom_name, err);
        ret = EIO;
        goto done;
    }

    /* If algorithmic mapping is used add this domain to the SYSDB cache so it
     * will survive reboot */
    if (!external_mapping) {
        ret = sysdb_idmap_store_mapping(idmap_ctx->id_ctx->be->domain,
                                        dom_name, dom_sid,
                                        slice);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_idmap_store_mapping failed.\n");
            goto done;
        }
    }

done:
    return ret;
}

errno_t
sdap_idmap_get_dom_sid_from_object(TALLOC_CTX *mem_ctx,
                                   const char *object_sid,
                                   char **dom_sid_str)
{
    const char *p;
    long long a;
    size_t c;
    char *endptr;

    if (object_sid == NULL
            || strncmp(object_sid, DOM_SID_PREFIX, DOM_SID_PREFIX_LEN) != 0) {
        return EINVAL;
    }

    p = object_sid + DOM_SID_PREFIX_LEN;
    c = 0;

    do {
        errno = 0;
        a = strtoull(p, &endptr, 10);
        if (errno != 0 || a > UINT32_MAX) {
            return EINVAL;
        }

        if (*endptr == '-') {
            p = endptr + 1;
        } else {
            return EINVAL;
        }
        c++;
    } while(c < 3);

    /* If we made it here, we are now one character past
     * the last hyphen in the object-sid.
     * Copy the dom-sid substring.
     */
    *dom_sid_str = talloc_strndup(mem_ctx, object_sid,
                                  (endptr-object_sid));
    if (!*dom_sid_str) return ENOMEM;

    return EOK;
}

errno_t
sdap_idmap_sid_to_unix(struct sdap_idmap_ctx *idmap_ctx,
                       const char *sid_str,
                       id_t *id)
{
    errno_t ret;
    enum idmap_error_code err;
    char *dom_sid_str = NULL;

    /* Convert the SID into a UNIX ID */
    err = sss_idmap_sid_to_unix(idmap_ctx->map,
                                sid_str,
                                (uint32_t *)id);
    switch (err) {
    case IDMAP_SUCCESS:
        break;
    case IDMAP_NO_DOMAIN:
        /* This is the first time we've seen this domain
         * Create a new domain for it. We'll use the dom-sid
         * as the domain name for now, since we don't have
         * any way to get the real name.
         */
        ret = sdap_idmap_get_dom_sid_from_object(NULL, sid_str,
                                                 &dom_sid_str);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not parse domain SID from [%s]\n", sid_str);
            goto done;
        }

        ret = idmap_ctx->find_new_domain(idmap_ctx, dom_sid_str, dom_sid_str);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not add new domain for sid [%s]\n", sid_str);
            goto done;
        }

        /* Now try converting to a UNIX ID again */
        err = sss_idmap_sid_to_unix(idmap_ctx->map,
                                    sid_str,
                                    (uint32_t *)id);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not convert objectSID [%s] to a UNIX ID\n",
                   sid_str);
            ret = EIO;
            goto done;
        }
        break;
    case IDMAP_BUILTIN_SID:
        DEBUG(SSSDBG_TRACE_FUNC,
              "Object SID [%s] is a built-in one.\n", sid_str);
        /* ENOTSUP indicates built-in SID */
        ret = ENOTSUP;
        goto done;
        break;
    case IDMAP_NO_RANGE:
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Object SID [%s] has a RID that is larger than the "
              "ldap_idmap_range_size. See the \"ID MAPPING\" section of "
              "sssd-ad(5) for an explanation of how to resolve this issue.\n",
              sid_str);
        /* Fall through intentionally */
        SSS_ATTRIBUTE_FALLTHROUGH;
    default:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not convert objectSID [%s] to a UNIX ID\n",
               sid_str);
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(dom_sid_str);
    return ret;
}

bool sdap_idmap_domain_has_algorithmic_mapping(struct sdap_idmap_ctx *ctx,
                                               const char *dom_name,
                                               const char *dom_sid)
{
    enum idmap_error_code err;
    bool has_algorithmic_mapping;
    char *new_dom_sid;
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;

    if (dp_opt_get_bool(ctx->id_ctx->opts->basic, SDAP_ID_MAPPING)
        && dp_target_enabled(ctx->id_ctx->be->provider, "ldap", DPT_ID)) {
        return true;
    }

    err = sss_idmap_domain_has_algorithmic_mapping(ctx->map, dom_sid,
                                                   &has_algorithmic_mapping);
    switch (err){
    case IDMAP_SUCCESS:
        return has_algorithmic_mapping;
    case IDMAP_SID_INVALID: /* FALLTHROUGH */
    case IDMAP_SID_UNKNOWN: /* FALLTHROUGH */
    case IDMAP_NO_DOMAIN:   /* FALLTHROUGH */
        /* continue with idmap_domain_by_name */
        break;
    default:
        return false;
    }

    err = sss_idmap_domain_by_name_has_algorithmic_mapping(ctx->map,
                                                  dom_name,
                                                  &has_algorithmic_mapping);
    if (err == IDMAP_SUCCESS) {
        return has_algorithmic_mapping;
    } else if (err != IDMAP_NAME_UNKNOWN && err != IDMAP_NO_DOMAIN) {
        return false;
    }

    /* If there is no SID, e.g. IPA without enabled trust support, we cannot
     * have algorithmic mapping */
    if (dom_sid == NULL) {
        return false;
    }

    /* This is the first time we've seen this domain
     * Create a new domain for it. We'll use the dom-sid
     * as the domain name for now, since we don't have
     * any way to get the real name.
     */

    if (is_domain_sid(dom_sid)) {
        new_dom_sid = discard_const(dom_sid);
    } else {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
            return false;
        }

        ret = sdap_idmap_get_dom_sid_from_object(tmp_ctx, dom_sid,
                                                 &new_dom_sid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not parse domain SID from [%s]\n", dom_sid);
            talloc_free(tmp_ctx);
            return false;
        }
    }

    ret = ctx->find_new_domain(ctx, dom_name, new_dom_sid);
    talloc_free(tmp_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not add new domain for sid [%s]\n", dom_sid);
        return false;
    }

    err = sss_idmap_domain_has_algorithmic_mapping(ctx->map, dom_sid,
                                                   &has_algorithmic_mapping);
    if (err == IDMAP_SUCCESS) {
        return has_algorithmic_mapping;
    }

    return false;
}
