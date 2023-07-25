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

char *expand_homedir_template(TALLOC_CTX *mem_ctx,
                              const char *template,
                              bool case_sensitive,
                              struct sss_nss_homedir_ctx *homedir_ctx)
{
    char *copy;
    char *p;
    char *n;
    char *result = NULL;
    char *res = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *orig = NULL;
    char *username = NULL;

    if (template == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing template.\n");
        return NULL;
    }

    if (homedir_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing home directory data.\n");
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return NULL;

    copy = talloc_strdup(tmp_ctx, template);
    if (copy == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
        goto done;
    }

    result = talloc_strdup(tmp_ctx, "");
    if (result == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
        goto done;
    }

    p = copy;
    while ( (n = strchr(p, '%')) != NULL) {
        *n = '\0';
        n++;
        if ( *n == '\0' ) {
            DEBUG(SSSDBG_CRIT_FAILURE, "format error, single %% at the end of "
                                        "the template.\n");
            goto done;
        }
        switch( *n ) {
            case 'u':
                if (homedir_ctx->username == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot expand user name template because user name "
                          "is empty.\n");
                    goto done;
                }
                username = sss_output_name(tmp_ctx, homedir_ctx->username,
                                           case_sensitive, 0);
                if (username == NULL) {
                    goto done;
                }

                result = talloc_asprintf_append(result, "%s%s", p, username);
                talloc_free(username);
                break;

            case 'l':
                if (homedir_ctx->username == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot expand first letter of user name template "
                          "because user name is empty.\n");
                    goto done;
                }
                username = sss_output_name(tmp_ctx, homedir_ctx->username,
                                           case_sensitive, 0);
                if (username == NULL) {
                    goto done;
                }

                result = talloc_asprintf_append(result, "%s%c", p, username[0]);
                talloc_free(username);
                break;

            case 'U':
                if (homedir_ctx->uid == 0) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Cannot expand uid template "
                                                "because uid is invalid.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                homedir_ctx->uid);
                break;

            case 'd':
                if (homedir_ctx->domain == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Cannot expand domain name "
                                                "template because domain name "
                                                "is empty.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p,
                                                homedir_ctx->domain);
                break;

            case 'f':
                if (homedir_ctx->domain == NULL
                        || homedir_ctx->username == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Cannot expand fully qualified "
                                                "name template because domain "
                                                "or user name is empty.\n");
                    goto done;
                }
                username = sss_output_name(tmp_ctx, homedir_ctx->username,
                                           case_sensitive, 0);
                if (username == NULL) {
                    goto done;
                }

                result = talloc_asprintf_append(result, "%s%s@%s", p,
                                                username, homedir_ctx->domain);
                talloc_free(username);
                break;

            case 'o':
            case 'h':
                if (homedir_ctx->original == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Original home directory for %s is not available, "
                           "using empty string\n", homedir_ctx->username);
                    orig = "";
                } else {
                    if (*n == 'o') {
                        orig = homedir_ctx->original;
                    } else {
                        orig = sss_tc_utf8_str_tolower(tmp_ctx,
                                                       homedir_ctx->original);
                        if (orig == NULL) {
                            DEBUG(SSSDBG_CRIT_FAILURE,
                                  "Failed to lowercase the original home "
                                  "directory.\n");
                            goto done;
                        }
                    }
                }
                result = talloc_asprintf_append(result, "%s%s", p, orig);
                break;

            case 'F':
                if (homedir_ctx->flatname == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Cannot expand domain name "
                                                "template because domain flat "
                                                "name is empty.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p,
                                                homedir_ctx->flatname);
                break;

            case 'H':
                if (homedir_ctx->config_homedir_substr == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot expand home directory substring template "
                          "substring is empty.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p,
                                           homedir_ctx->config_homedir_substr);
                break;

            case 'P':
                if (homedir_ctx->upn == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot expand user principal name template "
                          "string is empty.\n");
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p,
                                                homedir_ctx->upn);
                break;

            case '%':
                result = talloc_asprintf_append(result, "%s%%", p);
                break;

            default:
                DEBUG(SSSDBG_CRIT_FAILURE, "format error, unknown template "
                                            "[%%%c].\n", *n);
                goto done;
        }

        if (result == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf_append failed.\n");
            goto done;
        }

        p = n + 1;
    }

    result = talloc_asprintf_append(result, "%s", p);
    if (result == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf_append failed.\n");
        goto done;
    }

    res = talloc_move(mem_ctx, &result);
done:
    talloc_zfree(tmp_ctx);
    return res;
}
