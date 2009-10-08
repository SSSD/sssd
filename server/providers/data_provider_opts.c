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

/* =Retrieve-Options====================================================== */

int dp_get_options(TALLOC_CTX *memctx,
                   struct confdb_ctx *cdb,
                   const char *conf_path,
                   struct dp_option *def_opts,
                   int num_opts,
                   struct dp_option **_opts)
{
    struct dp_option *opts;
    int i, ret;

    opts = talloc_array(memctx, struct dp_option, num_opts);
    if (!opts) return ENOMEM;

    for (i = 0; i < num_opts; i++) {
        char *tmp;

        opts[i].opt_name = def_opts[i].opt_name;
        opts[i].type = def_opts[i].type;
        opts[i].def_val = def_opts[i].def_val;
        ret = EOK;

        switch (def_opts[i].type) {
        case DP_OPT_STRING:
            ret = confdb_get_string(cdb, opts, conf_path,
                                    opts[i].opt_name,
                                    opts[i].def_val.cstring,
                                    &opts[i].val.string);
            if (ret != EOK ||
                ((opts[i].def_val.string != NULL) &&
                 (opts[i].val.string == NULL))) {
                DEBUG(0, ("Failed to retrieve value for option (%s)\n",
                          opts[i].opt_name));
                if (ret == EOK) ret = EINVAL;
                goto done;
            }
            DEBUG(6, ("Option %s has value %s\n",
                  opts[i].opt_name, opts[i].val.cstring));
            break;

        case DP_OPT_BLOB:
            ret = confdb_get_string(cdb, opts, conf_path,
                                    opts[i].opt_name,
                                    NULL, &tmp);
            if (ret != EOK) {
                DEBUG(0, ("Failed to retrieve value for option (%s)\n",
                          opts[i].opt_name));
                goto done;
            }

            if (tmp) {
                opts[i].val.blob.data = (uint8_t *)tmp;
                opts[i].val.blob.length = strlen(tmp);
            } else {
                opts[i].val.blob.data = NULL;
                opts[i].val.blob.length = 0;
            }

            DEBUG(6, ("Option %s has %s value\n",
                      opts[i].opt_name,
                      opts[i].val.blob.length?"a":"no"));
            break;

        case DP_OPT_NUMBER:
            ret = confdb_get_int(cdb, opts, conf_path,
                                 opts[i].opt_name,
                                 opts[i].def_val.number,
                                 &opts[i].val.number);
            if (ret != EOK) {
                DEBUG(0, ("Failed to retrieve value for option (%s)\n",
                          opts[i].opt_name));
                goto done;
            }
            DEBUG(6, ("Option %s has value %d\n",
                  opts[i].opt_name, opts[i].val.number));
            break;

        case DP_OPT_BOOL:
            ret = confdb_get_bool(cdb, opts, conf_path,
                                  opts[i].opt_name,
                                  opts[i].def_val.boolean,
                                  &opts[i].val.boolean);
            if (ret != EOK) {
                DEBUG(0, ("Failed to retrieve value for option (%s)\n",
                          opts[i].opt_name));
                goto done;
            }
            DEBUG(6, ("Option %s is %s\n",
                      opts[i].opt_name,
                      opts[i].val.boolean?"TRUE":"FALSE"));
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

const char *_dp_opt_get_cstring(struct dp_option *opts,
                                int id, const char *location)
{
    if (opts[id].type != DP_OPT_STRING) {
        DEBUG(0, ("[%s] Requested type 'String' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type)));
        return NULL;
    }
    return opts[id].val.cstring;
}

char *_dp_opt_get_string(struct dp_option *opts,
                         int id, const char *location)
{
    if (opts[id].type != DP_OPT_STRING) {
        DEBUG(0, ("[%s] Requested type 'String' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type)));
        return NULL;
    }
    return opts[id].val.string;
}

struct dp_opt_blob _dp_opt_get_blob(struct dp_option *opts,
                                  int id, const char *location)
{
    struct dp_opt_blob null_blob = { NULL, 0 };
    if (opts[id].type != DP_OPT_BLOB) {
        DEBUG(0, ("[%s] Requested type 'Blob' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type)));
        return null_blob;
    }
    return opts[id].val.blob;
}

int _dp_opt_get_int(struct dp_option *opts,
                    int id, const char *location)
{
    if (opts[id].type != DP_OPT_NUMBER) {
        DEBUG(0, ("[%s] Requested type 'Number' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type)));
        return 0;
    }
    return opts[id].val.number;
}

bool _dp_opt_get_bool(struct dp_option *opts,
                      int id, const char *location)
{
    if (opts[id].type != DP_OPT_BOOL) {
        DEBUG(0, ("[%s] Requested type 'Boolean' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  dp_opt_type_to_string(opts[id].type)));
        return false;
    }
    return opts[id].val.boolean;
}

