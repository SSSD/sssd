/*
    SSSD

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2013 Red Hat

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
#include "providers/ldap/sdap_idmap.h"
#include "providers/ipa/ipa_common.h"
#include "util/util_sss_idmap.h"

static errno_t ipa_idmap_check_posix_child(struct sdap_idmap_ctx *idmap_ctx,
                                           const char *dom_name,
                                           const char *dom_sid_str,
                                           size_t range_count,
                                           struct range_info **range_list)
{
    bool has_algorithmic_mapping;
    enum idmap_error_code err;
    struct sss_domain_info *dom;
    struct sss_domain_info *forest_root;
    size_t c;
    struct sss_idmap_range range;
    struct range_info *r;
    char *range_id;
    TALLOC_CTX *tmp_ctx;
    bool found = false;
    int ret;

    err = sss_idmap_domain_has_algorithmic_mapping(idmap_ctx->map, dom_sid_str,
                                                   &has_algorithmic_mapping);
    if (err == IDMAP_SUCCESS) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Idmap of domain [%s] already known, nothing to do.\n",
                dom_sid_str);
        return EOK;
    } else {
        err = sss_idmap_domain_by_name_has_algorithmic_mapping(idmap_ctx->map,
                                                      dom_name,
                                                      &has_algorithmic_mapping);
        if (err == IDMAP_SUCCESS) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Idmap of domain [%s] already known, nothing to do.\n",
                    dom_sid_str);
            return EOK;
        }
    }
    DEBUG(SSSDBG_TRACE_ALL, "Trying to add idmap for domain [%s].\n",
                             dom_sid_str);

    if (err != IDMAP_SID_UNKNOWN && err != IDMAP_NAME_UNKNOWN) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_idmap_domain_has_algorithmic_mapping failed.\n");
        return EINVAL;
    }

    dom = find_domain_by_sid(idmap_ctx->id_ctx->be->domain, dom_sid_str);
    if (dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "find_domain_by_sid failed with SID [%s].\n", dom_sid_str);
        return EINVAL;
    }

    if (dom->forest == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No forest available for domain [%s].\n",
                                     dom_sid_str);
        return EINVAL;
    }

    forest_root = find_domain_by_name(idmap_ctx->id_ctx->be->domain,
                                      dom->forest, true);
    if (forest_root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "find_domain_by_name failed to find forest root [%s].\n",
               dom->forest);
        return ENOENT;
    }

    if (forest_root->domain_id == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Forest root [%s] does not have a SID.\n",
                                     dom->forest);
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    for (c = 0; c < range_count; c++) {
        r = range_list[c];
        if (r->trusted_dom_sid != NULL
                && strcmp(r->trusted_dom_sid, forest_root->domain_id) == 0) {

            if (r->range_type == NULL
                    || strcmp(r->range_type, IPA_RANGE_AD_TRUST_POSIX) != 0) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Forest root does not have range type [%s].\n",
                       IPA_RANGE_AD_TRUST_POSIX);
                ret = EINVAL;
                goto done;
            }

            range.min = r->base_id;
            range.max = r->base_id + r->id_range_size -1;
            range_id = talloc_asprintf(tmp_ctx, "%s-%s", dom_sid_str, r->name);
            if (range_id == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
                ret = ENOMEM;
                goto done;
            }

            err = sss_idmap_add_domain_ex(idmap_ctx->map, dom_name, dom_sid_str,
                                          &range, range_id, 0, true);
            if (err != IDMAP_SUCCESS && err != IDMAP_COLLISION) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not add range [%s] to ID map\n", range_id);
                ret = EIO;
                goto done;
            }

            found = true;
        }
    }

    if (!found) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No idrange found for forest root [%s].\n",
                                     forest_root->domain_id);
        ret = ENOENT;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t get_idmap_data_from_range(struct range_info *r, char *domain_name,
                                  char **_name, char **_sid, uint32_t *_rid,
                                  struct sss_idmap_range *_range,
                                  bool *_external_mapping)
{
    if (r->range_type == NULL) {
        /* Older IPA servers might not have the range_type attribute, but
         * only support local ranges and trusts with algorithmic mapping. */

        if (r->trusted_dom_sid == NULL && r->secondary_base_rid != 0) {
            /* local IPA domain */
            *_rid = 0;
            *_external_mapping = true;
            *_name = domain_name;
            *_sid = NULL;
        } else if (r->trusted_dom_sid != NULL
                && r->secondary_base_rid == 0) {
            /* trusted domain */
            *_rid = r->base_rid;
            *_external_mapping = false;
            *_name = r->trusted_dom_sid;
            *_sid = r->trusted_dom_sid;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot determine range type, " \
                                        "for id range [%s].\n",
                                        r->name);
            return EINVAL;
        }
    } else {
        if (strcmp(r->range_type, IPA_RANGE_LOCAL) == 0) {
            *_rid = 0;
            *_external_mapping = true;
            *_name = domain_name;
            *_sid = NULL;
        } else if (strcmp(r->range_type, IPA_RANGE_AD_TRUST_POSIX) == 0) {
            *_rid = 0;
            *_external_mapping = true;
            *_name = r->trusted_dom_sid;
            *_sid = r->trusted_dom_sid;
        } else if (strcmp(r->range_type, IPA_RANGE_AD_TRUST) == 0) {
            *_rid = r->base_rid;
            *_external_mapping = false;
            *_name = r->trusted_dom_sid;
            *_sid = r->trusted_dom_sid;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Range type [%s] of id range " \
                                        "[%s] not supported.\n", \
                                        r->range_type, r->name);
            return ERR_UNSUPPORTED_RANGE_TYPE;
        }
    }

    _range->min = r->base_id;
    _range->max = r->base_id + r->id_range_size -1;

    return EOK;
}

errno_t ipa_ranges_parse_results(TALLOC_CTX *mem_ctx,
                                 char *domain_name,
                                 size_t count,
                                 struct sysdb_attrs **reply,
                                 struct range_info ***_range_list)
{
    struct range_info **range_list = NULL;
    struct range_info *r;
    const char *value;
    size_t c;
    size_t rc = 0;
    size_t d;
    int ret;
    enum idmap_error_code err;
    char *name1;
    char *name2;
    char *sid1;
    char *sid2;
    uint32_t rid1;
    uint32_t rid2;
    struct sss_idmap_range range1;
    struct sss_idmap_range range2;
    bool mapping1;
    bool mapping2;

    range_list = talloc_array(mem_ctx, struct range_info *, count + 1);
    if (range_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    for (c = 0; c < count; c++) {
        r = talloc_zero(range_list, struct range_info);
        if (r == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        r->name = talloc_strdup(r, value);
        if (r->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_TRUSTED_DOMAIN_SID, &value);
        if (ret == EOK) {
            r->trusted_dom_sid = talloc_strdup(r, value);
            if (r->trusted_dom_sid == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_BASE_ID,
                                       &r->base_id);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_ID_RANGE_SIZE,
                                       &r->id_range_size);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_BASE_RID,
                                       &r->base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_SECONDARY_BASE_RID,
                                       &r->secondary_base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_RANGE_TYPE, &value);
        if (ret == EOK) {
            r->range_type = talloc_strdup(r, value);
            if (r->range_type == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else if (ret == ENOENT) {
            /* Older IPA servers might not have the range_type attribute, but
             * only support local ranges and trusts with algorithmic mapping. */
            if (r->trusted_dom_sid == NULL) {
                r->range_type = talloc_strdup(r, IPA_RANGE_LOCAL);
            } else {
                r->range_type = talloc_strdup(r, IPA_RANGE_AD_TRUST);
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
        if (r->range_type == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_ID_RANGE_MPG, &value);
        if (ret == EOK) {
            r->mpg_mode = str_to_domain_mpg_mode(value);
        } else if (ret == ENOENT) {
            r->mpg_mode = MPG_DEFAULT;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = get_idmap_data_from_range(r, domain_name, &name1, &sid1, &rid1,
                                        &range1, &mapping1);
        if (ret == ERR_UNSUPPORTED_RANGE_TYPE) {
            talloc_free(r);
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_idmap_data_from_range failed.\n");
            goto done;
        }
        for (d = 0; d < rc; d++) {
            ret = get_idmap_data_from_range(range_list[d], domain_name, &name2,
                                            &sid2, &rid2, &range2, &mapping2);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "get_idmap_data_from_range failed.\n");
                goto done;
            }

            err = sss_idmap_check_collision_ex(name1, sid1, &range1, rid1,
                                               r->name, mapping1,
                                               name2, sid2, &range2, rid2,
                                               range_list[d]->name, mapping2);
            if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Collision of ranges [%s] and [%s] detected.\n",
                      r->name, range_list[d]->name);
                ret = EINVAL;
                goto done;
            }
        }

        range_list[rc++] = r;
    }

    range_list[rc] = NULL;

    *_range_list = range_list;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(range_list);
    }

    return ret;
}

errno_t ipa_idmap_get_ranges_from_sysdb(struct sdap_idmap_ctx *idmap_ctx,
                                        const char *dom_name,
                                        const char *dom_sid_str,
                                        bool allow_collisions)
{
    int ret;
    size_t range_count;
    struct range_info **range_list;
    TALLOC_CTX *tmp_ctx;
    size_t c;
    enum idmap_error_code err;
    struct sss_idmap_range range;
    uint32_t rid;
    bool external_mapping;
    char *name;
    char *sid;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sysdb_get_ranges(tmp_ctx, idmap_ctx->id_ctx->be->domain->sysdb,
                           &range_count, &range_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_ranges failed.\n");
        goto done;
    }

    for (c = 0; c < range_count; c++) {
        ret = get_idmap_data_from_range(range_list[c],
                                        idmap_ctx->id_ctx->be->domain->name,
                                        &name, &sid, &rid, &range,
                                        &external_mapping);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_idmap_data_from_range failed for " \
                                     "id range [%s], skipping.\n",
                                     range_list[c]->name);
            continue;
        }

        err = sss_idmap_add_domain_ex(idmap_ctx->map, name, sid, &range,
                                      range_list[c]->name, rid,
                                      external_mapping);
        if (err != IDMAP_SUCCESS) {
            if (!allow_collisions || err != IDMAP_COLLISION) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Could not add range [%s] to ID map\n",
                                           range_list[c]->name);
                ret = EIO;
                goto done;
            }
        }
    }

    if (dom_name != NULL || dom_sid_str != NULL) {
        ret = ipa_idmap_check_posix_child(idmap_ctx, dom_name, dom_sid_str,
                                          range_count, range_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_idmap_check_posix_child failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t ipa_idmap_find_new_domain(struct sdap_idmap_ctx *idmap_ctx,
                                  const char *dom_name,
                                  const char *dom_sid_str)
{
    return ipa_idmap_get_ranges_from_sysdb(idmap_ctx, dom_name, dom_sid_str,
                                           true);
}

errno_t ipa_idmap_init(TALLOC_CTX *mem_ctx,
                       struct sdap_id_ctx *id_ctx,
                       struct sdap_idmap_ctx **_idmap_ctx)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    enum idmap_error_code err;
    struct sdap_idmap_ctx *idmap_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    idmap_ctx = talloc_zero(tmp_ctx, struct sdap_idmap_ctx);
    if (!idmap_ctx) {
        ret = ENOMEM;
        goto done;
    }
    idmap_ctx->id_ctx = id_ctx;
    idmap_ctx->find_new_domain = ipa_idmap_find_new_domain;

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

    ret = ipa_idmap_get_ranges_from_sysdb(idmap_ctx, NULL, NULL, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_idmap_get_ranges_from_sysdb failed.\n");
        goto done;
    }

    *_idmap_ctx = talloc_steal(mem_ctx, idmap_ctx);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
