/*
   SSSD

   Utility functions related to ID information

   Copyright (C) Jan Zeleny <jzeleny@redhat.com> 2012

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
#include "util/sss_nss.h"

char *expand_homedir_template(TALLOC_CTX *mem_ctx, const char *template,
                              const char *username, uint32_t uid,
                              const char *original, const char *domain)
{
    char *copy;
    char *p;
    char *n;
    char *result = NULL;
    char *res = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *orig = NULL;

    if (template == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Missing template.\n"));
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return NULL;

    copy = talloc_strdup(tmp_ctx, template);
    if (copy == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup failed.\n"));
        goto done;
    }

    result = talloc_strdup(tmp_ctx, "");
    if (result == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup failed.\n"));
        goto done;
    }

    p = copy;
    while ( (n = strchr(p, '%')) != NULL) {
        *n = '\0';
        n++;
        if ( *n == '\0' ) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("format error, single %% at the end of "
                                        "the template.\n"));
            goto done;
        }
        switch( *n ) {
            case 'u':
                if (username == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot expand user name template "
                                                "because user name is empty.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p,
                                                username);
                break;

            case 'U':
                if (uid == 0) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot expand uid template "
                                                "because uid is invalid.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                uid);
                break;

            case 'd':
                if (domain == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot expand domain name "
                                                "template because domain name "
                                                "is empty.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p,
                                                domain);
                break;

            case 'f':
                if (domain == NULL || username == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot expand fully qualified "
                                                "name template because domain "
                                                "or user name is empty.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s@%s", p,
                                                username, domain);
                break;
            case 'o':
                if (original == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          ("Original home directory for %s is not available, "
                           "using empty string\n", username));
                    orig = "";
                } else {
                    orig = original;
                }
                result = talloc_asprintf_append(result, "%s%s", p, orig);
                break;

            case '%':
                result = talloc_asprintf_append(result, "%s%%", p);
                break;

            default:
                DEBUG(SSSDBG_CRIT_FAILURE, ("format error, unknown template "
                                            "[%%%c].\n", *n));
                goto done;
        }

        if (result == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf_append failed.\n"));
            goto done;
        }

        p = n + 1;
    }

    result = talloc_asprintf_append(result, "%s", p);
    if (result == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf_append failed.\n"));
        goto done;
    }

    res = talloc_move(mem_ctx, &result);
done:
    talloc_zfree(tmp_ctx);
    return res;
}
