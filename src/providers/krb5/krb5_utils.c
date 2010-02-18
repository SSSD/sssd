/*
    SSSD

    Kerberos 5 Backend Module -- Utilities

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <string.h>
#include <stdlib.h>

#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_auth.h"
#include "util/util.h"

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template)
{
    char *copy;
    char *p;
    char *n;
    char *result = NULL;
    const char *dummy;

    if (template == NULL) {
        DEBUG(1, ("Missing template.\n"));
        return NULL;
    }

    copy = talloc_strdup(mem_ctx, template);
    if (copy == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        return NULL;
    }

    result = talloc_strdup(mem_ctx, "");
    if (result == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        return NULL;
    }

    p = copy;
    while ( (n = strchr(p, '%')) != NULL) {
        *n = '\0';
        n++;
        if ( *n == '\0' ) {
            DEBUG(1, ("format error, single %% at the end of the template.\n"));
            return NULL;
        }

        switch( *n ) {
            case 'u':
                if (kr->pd->user == NULL) {
                    DEBUG(1, ("Cannot expand user name template "
                              "because user name is empty.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p,
                                                kr->pd->user);
                break;
            case 'U':
                if (kr->pd->pw_uid <= 0) {
                    DEBUG(1, ("Cannot expand uid template "
                              "because uid is invalid.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                kr->pd->pw_uid);
                break;
            case 'p':
                if (kr->pd->upn == NULL) {
                    DEBUG(1, ("Cannot expand user principle name template "
                              "because upn is empty.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p, kr->pd->upn);
                break;
            case '%':
                result = talloc_asprintf_append(result, "%s%%", p);
                break;
            case 'r':
                dummy = dp_opt_get_string(kr->krb5_ctx->opts, KRB5_REALM);
                if (dummy == NULL) {
                    DEBUG(1, ("Missing kerberos realm.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p, dummy);
                break;
            case 'h':
                if (kr->homedir == NULL) {
                    DEBUG(1, ("Cannot expand home directory template "
                              "because the path is not available.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p, kr->homedir);
                break;
            case 'd':
                dummy = dp_opt_get_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR);
                if (dummy == NULL) {
                    DEBUG(1, ("Missing credential cache directory.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%s", p, dummy);
                break;
            case 'P':
                if (kr->pd->cli_pid == 0) {
                    DEBUG(1, ("Cannot expand PID template "
                              "because PID is not available.\n"));
                    return NULL;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                kr->pd->cli_pid);
                break;
            default:
                DEBUG(1, ("format error, unknown template [%%%c].\n", *n));
                return NULL;
        }

        if (result == NULL) {
            DEBUG(1, ("talloc_asprintf_append failed.\n"));
            return NULL;
        }

        p = n + 1;
    }

    result = talloc_asprintf_append(result, "%s", p);

    return result;
}
