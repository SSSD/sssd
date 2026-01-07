/*
    SSSD

    Data Provider Helpers

    Copyright (C) Simo Sorce <ssorce@redhat.com> 2009

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

#include "data_provider.h"

/* =Copy-Option-From-Subdomain-If-Allowed================================= */
void dp_option_inherit_match(char **inherit_opt_list,
                             int option,
                             struct dp_option *parent_opts,
                             struct dp_option *subdom_opts)
{
    bool inherit_option;

    inherit_option = string_in_list(parent_opts[option].opt_name,
                                    inherit_opt_list, false);
    if (inherit_option == false) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Option %s is not set up to be inherited\n",
              parent_opts[option].opt_name);
        return;
    }

    dp_option_inherit(option, parent_opts, subdom_opts);
}

void dp_option_inherit(int option,
                       struct dp_option *parent_opts,
                       struct dp_option *subdom_opts)
{
    errno_t ret;

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Inheriting option %s\n", parent_opts[option].opt_name);
    switch (parent_opts[option].type) {
    case DP_OPT_NUMBER:
        ret = dp_opt_set_int(subdom_opts,
                             option,
                             dp_opt_get_int(parent_opts,
                                            option));
        break;
    case DP_OPT_STRING:
        ret = dp_opt_set_string(subdom_opts,
                                option,
                                dp_opt_get_string(parent_opts,
                                                  option));
        break;
    case DP_OPT_BLOB:
        ret = dp_opt_set_blob(subdom_opts,
                              option,
                              dp_opt_get_blob(parent_opts,
                                              option));
        break;
    case DP_OPT_BOOL:
        ret = dp_opt_set_bool(subdom_opts,
                              option,
                              dp_opt_get_bool(parent_opts,
                                              option));
        break;
    default:
        ret = EINVAL;
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to inherit option %s\n", parent_opts[option].opt_name);
        /* Not fatal */
    }
}

/* =Retrieve-Options====================================================== */

static inline void log_string_option(const struct dp_option *opt)
{
    if (strcmp(opt->opt_name, CONFDB_IDP_CLIENT_SECRET) == 0) {
        /* avoid logging value of sensitive option */
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Option "CONFDB_IDP_CLIENT_SECRET" is%s set\n",
              opt->val.cstring ? "" : " not");
        return;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Option %s has%s value %s\n",
          opt->opt_name,
          opt->val.cstring ? "" : " no",
          opt->val.cstring ? opt->val.cstring : "");
}

int dp_get_options(TALLOC_CTX *memctx,
                   struct confdb_ctx *cdb,
                   const char *conf_path,
                   struct dp_option *def_opts,
                   int num_opts,
                   struct dp_option **_opts)
{
    struct dp_option *opts;
    int i, ret;

    opts = talloc_zero_array(memctx, struct dp_option, num_opts);
    if (!opts) return ENOMEM;

    for (i = 0; i < num_opts; i++) {
        char *tmp;

        opts[i].opt_name = def_opts[i].opt_name;
        opts[i].type = def_opts[i].type;
        opts[i].def_val = def_opts[i].def_val;

        switch (def_opts[i].type) {
        case DP_OPT_STRING:
            ret = confdb_get_string(cdb, opts, conf_path,
                                    opts[i].opt_name,
                                    opts[i].def_val.cstring,
                                    &opts[i].val.string);
            if (ret != EOK ||
                ((opts[i].def_val.string != NULL) &&
                 (opts[i].val.string == NULL))) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to retrieve value for option (%s)\n",
                       opts[i].opt_name);
                if (ret == EOK) ret = EINVAL;
                goto done;
            }

            log_string_option(&opts[i]);
            break;

        case DP_OPT_BLOB:
            ret = confdb_get_string(cdb, opts, conf_path,
                                    opts[i].opt_name,
                                    NULL, &tmp);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to retrieve value for option (%s)\n",
                      opts[i].opt_name);
                goto done;
            }

            if (tmp) {
                opts[i].val.blob.data = (uint8_t *)tmp;
                opts[i].val.blob.length = strlen(tmp);
            } else if (opts[i].def_val.blob.data != NULL) {
                opts[i].val.blob.data = opts[i].def_val.blob.data;
                opts[i].val.blob.length = opts[i].def_val.blob.length;
            } else {
                opts[i].val.blob.data = NULL;
                opts[i].val.blob.length = 0;
            }

            DEBUG(SSSDBG_CONF_SETTINGS, "Option %s has %s binary value.\n",
                  opts[i].opt_name, opts[i].val.blob.length?"a":"no");
            break;

        case DP_OPT_NUMBER:
            ret = confdb_get_int(cdb, conf_path,
                                 opts[i].opt_name,
                                 opts[i].def_val.number,
                                 &opts[i].val.number);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to retrieve value for option (%s)\n",
                      opts[i].opt_name);
                goto done;
            }
            DEBUG(SSSDBG_CONF_SETTINGS, "Option %s has value %d\n",
                  opts[i].opt_name, opts[i].val.number);
            break;

        case DP_OPT_BOOL:
            ret = confdb_get_bool(cdb, conf_path,
                                  opts[i].opt_name,
                                  opts[i].def_val.boolean,
                                  &opts[i].val.boolean);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to retrieve value for option (%s)\n",
                      opts[i].opt_name);
                goto done;
            }
            DEBUG(SSSDBG_CONF_SETTINGS, "Option %s is %s\n",
                  opts[i].opt_name, opts[i].val.boolean?"TRUE":"FALSE");
            break;
        }
    }

    ret = EOK;
    *_opts = opts;

done:
    if (ret != EOK) talloc_zfree(opts);
    return ret;
}

/* =Basic-Option-Helpers================================================== */
static int dp_copy_options_ex(TALLOC_CTX *memctx,
                              bool copy_values,
                              struct dp_option *src_opts,
                              int num_opts,
                              struct dp_option **_opts)
{
    struct dp_option *opts;
    int i, ret = EOK;

    opts = talloc_zero_array(memctx, struct dp_option, num_opts);
    if (!opts) return ENOMEM;

    for (i = 0; i < num_opts; i++) {
        opts[i].opt_name = src_opts[i].opt_name;
        opts[i].type = src_opts[i].type;
        opts[i].def_val = src_opts[i].def_val;
        ret = EOK;

        switch (src_opts[i].type) {
        case DP_OPT_STRING:
            if (copy_values) {
                ret = dp_opt_set_string(opts, i, src_opts[i].val.string);
            } else {
                ret = dp_opt_set_string(opts, i, src_opts[i].def_val.string);
            }
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to copy value for option (%s)\n",
                       opts[i].opt_name);
                goto done;
            }
            log_string_option(&opts[i]);
            break;

        case DP_OPT_BLOB:
            if (copy_values) {
                ret = dp_opt_set_blob(opts, i, src_opts[i].val.blob);
            } else {
                ret = dp_opt_set_blob(opts, i, src_opts[i].def_val.blob);
            }
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to copy value for option (%s)\n",
                       opts[i].opt_name);
                goto done;
            }
            DEBUG(SSSDBG_CONF_SETTINGS, "Option %s has %s binary value.\n",
                  opts[i].opt_name, opts[i].val.blob.length?"a":"no");
            break;

        case DP_OPT_NUMBER:
            if (copy_values) {
                ret = dp_opt_set_int(opts, i, src_opts[i].val.number);
            } else {
                ret = dp_opt_set_int(opts, i, src_opts[i].def_val.number);
            }
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to copy value for option (%s)\n",
                      opts[i].opt_name);
                goto done;
            }
            DEBUG(SSSDBG_CONF_SETTINGS, "Option %s has value %d\n",
                  opts[i].opt_name, opts[i].val.number);
            break;

        case DP_OPT_BOOL:
            if (copy_values) {
                ret = dp_opt_set_bool(opts, i, src_opts[i].val.boolean);
            } else {
                ret = dp_opt_set_bool(opts, i, src_opts[i].def_val.boolean);
            }
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to copy value for option (%s)\n",
                       opts[i].opt_name);
                goto done;
            }
            DEBUG(SSSDBG_CONF_SETTINGS, "Option %s is %s\n",
                  opts[i].opt_name, opts[i].val.boolean?"TRUE":"FALSE");
            break;
        }
    }

    *_opts = opts;

done:
    if (ret != EOK) talloc_zfree(opts);
    return ret;
}

int dp_copy_options(TALLOC_CTX *memctx,
                    struct dp_option *src_opts,
                    int num_opts,
                    struct dp_option **_opts)
{
    return dp_copy_options_ex(memctx, true, src_opts, num_opts, _opts);
}

int dp_copy_defaults(TALLOC_CTX *memctx,
                     struct dp_option *src_opts,
                     int num_opts,
                     struct dp_option **_opts)
{
    return dp_copy_options_ex(memctx, false, src_opts, num_opts, _opts);
}

static const char *dp_opt_type_to_string(enum dp_opt_type type)
{
    switch (type) {
    case DP_OPT_STRING:
        return "String";
    case DP_OPT_BLOB:
        return "Blob";
    case DP_OPT_NUMBER:
        return "Number";
    case DP_OPT_BOOL:
        return "Boolean";
    }
    return NULL;
}

/* Getters */
const char *_dp_opt_get_cstring(struct dp_option *opts,
                                int id, const char *location)
{
    if (opts[id].type != DP_OPT_STRING) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "[%s] Requested type 'String' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return NULL;
    }
    return opts[id].val.cstring;
}

char *_dp_opt_get_string(struct dp_option *opts,
                         int id, const char *location)
{
    if (opts[id].type != DP_OPT_STRING) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "[%s] Requested type 'String' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return NULL;
    }
    return opts[id].val.string;
}

struct dp_opt_blob _dp_opt_get_blob(struct dp_option *opts,
                                  int id, const char *location)
{
    struct dp_opt_blob null_blob = { NULL, 0 };
    if (opts[id].type != DP_OPT_BLOB) {
        DEBUG(SSSDBG_FATAL_FAILURE, "[%s] Requested type 'Blob' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return null_blob;
    }
    return opts[id].val.blob;
}

int _dp_opt_get_int(struct dp_option *opts,
                    int id, const char *location)
{
    if (opts[id].type != DP_OPT_NUMBER) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "[%s] Requested type 'Number' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return 0;
    }
    return opts[id].val.number;
}

bool _dp_opt_get_bool(struct dp_option *opts,
                      int id, const char *location)
{
    if (opts[id].type != DP_OPT_BOOL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "[%s] Requested type 'Boolean' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return false;
    }
    return opts[id].val.boolean;
}

/* Setters */
int _dp_opt_set_string(struct dp_option *opts, int id,
                       const char *s, const char *location)
{
    if (opts[id].type != DP_OPT_STRING) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "[%s] Requested type 'String' for option '%s'"
                  " but type is '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return EINVAL;
    }

    if (opts[id].val.string) {
        talloc_zfree(opts[id].val.string);
    }
    if (s) {
        opts[id].val.string = talloc_strdup(opts, s);
        if (!opts[id].val.string) {
            DEBUG(SSSDBG_FATAL_FAILURE, "talloc_strdup() failed!\n");
            return ENOMEM;
        }
    }

    return EOK;
}

int _dp_opt_set_blob(struct dp_option *opts, int id,
                     struct dp_opt_blob b, const char *location)
{
    if (opts[id].type != DP_OPT_BLOB) {
        DEBUG(SSSDBG_FATAL_FAILURE, "[%s] Requested type 'Blob' for option '%s'"
                  " but type is '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return EINVAL;
    }

    if (opts[id].val.blob.data) {
        talloc_zfree(opts[id].val.blob.data);
        opts[id].val.blob.length = 0;
    }
    if (b.data) {
        opts[id].val.blob.data = talloc_memdup(opts, b.data, b.length);
        if (!opts[id].val.blob.data) {
            DEBUG(SSSDBG_FATAL_FAILURE, "talloc_memdup() failed!\n");
            return ENOMEM;
        }
    }
    opts[id].val.blob.length = b.length;

    return EOK;
}

int _dp_opt_set_int(struct dp_option *opts, int id,
                    int i, const char *location)
{
    if (opts[id].type != DP_OPT_NUMBER) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "[%s] Requested type 'Number' for option '%s'"
                  " but type is '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return EINVAL;
    }

    opts[id].val.number = i;

    return EOK;
}

int _dp_opt_set_bool(struct dp_option *opts, int id,
                     bool b, const char *location)
{
    if (opts[id].type != DP_OPT_BOOL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "[%s] Requested type 'Boolean' for option '%s'"
                  " but type is '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type));
        return EINVAL;
    }

    opts[id].val.boolean = b;

    return EOK;
}
