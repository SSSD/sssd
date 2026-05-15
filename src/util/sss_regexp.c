/*
    SSSD

    Authors:
        Tomas Halman <thalman@redhat.com>

    Copyright (C) 2019 Red Hat

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

#include "util/sss_regexp.h"
#include <string.h>
#include "util/util_errors.h"
#include "util/debug.h"

#define SSS_REGEXP_OVEC_SIZE 30
#define SSS_REGEXP_ERR_MSG_SIZE 120 /* 120 is recomended by pcre2 doc */

#ifndef EOK
#define EOK 0
#endif

/*
 * sss_regexp with pcre2
 */
struct _sss_regexp_t {
    pcre2_code *re;
    pcre2_match_data *match_data;
    char *matched_string;
};

static int sss_regexp_pcre2_destroy(sss_regexp_t *self)
{
    if (self->re) {
        pcre2_code_free(self->re);
    }
    if (self->match_data) {
        pcre2_match_data_free(self->match_data);
    }
    if (self->matched_string) {
        pcre2_substring_free((PCRE2_UCHAR *)self->matched_string);
    }
    return 0;
}

static int sss_regexp_pcre2_compile(sss_regexp_t *self,
                             const char *pattern,
                             int options)
{
    int errorcode;
    unsigned char errormsg[SSS_REGEXP_ERR_MSG_SIZE];
    size_t erroroffset;

    self->re = pcre2_compile((PCRE2_SPTR)pattern,
                             strlen(pattern),
                             options,
                             &errorcode,
                             &erroroffset,
                             NULL);
    if (self->re == NULL) {
        pcre2_get_error_message(errorcode,
                                errormsg,
                                SSS_REGEXP_ERR_MSG_SIZE);
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid Regular Expression pattern "
              "at position %zu. (Error: %d [%s])\n", erroroffset, errorcode, errormsg);
        return errorcode;
    }
    return EOK;
}

static int sss_regexp_pcre2_match(sss_regexp_t *self,
                           const char *subject,
                           int startoffset,
                           int options)
{
    if (!self->re) {
        return SSS_REGEXP_ERROR_NOMATCH;
    }
    if (self->match_data) {
        pcre2_match_data_free(self->match_data);
    }
    self->match_data = pcre2_match_data_create_from_pattern(self->re, NULL);
    if (!self->match_data) {
        return SSS_REGEXP_ERROR_NOMEMORY;
    }
    return pcre2_match(self->re,
                       (PCRE2_SPTR)subject,
                       strlen(subject),
                       startoffset,
                       options,
                       self->match_data,
                       NULL);
}

static int sss_regexp_pcre2_get_named_substring(sss_regexp_t *self,
                                         const char *name,
                                         const char **value)
{
    PCRE2_SIZE length;
    int rc;

    if (self->matched_string) {
        pcre2_substring_free((PCRE2_UCHAR *)(self->matched_string));
        self->matched_string = NULL;
    }
    rc = pcre2_substring_get_byname(self->match_data,
                                    (PCRE2_SPTR)name,
                                    (PCRE2_UCHAR **) &self->matched_string,
                                    &length);
    *value = self->matched_string;
    return rc;
}

/*
 * sss_regexp talloc destructor
 */
static int sss_regexp_destroy(sss_regexp_t *self)
{
    if (!self) return 0;
    return sss_regexp_pcre2_destroy(self);
}

/*
 * sss_regexp constructor
 */
int sss_regexp_new(TALLOC_CTX *mem_ctx,
                   const char *pattern,
                   int options,
                   sss_regexp_t **self_p)
{
    int ret;
    sss_regexp_t *self = talloc_zero(mem_ctx, sss_regexp_t);
    if (!self) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Not enough memory for sss_regexp_t.\n");
        *self_p = NULL;
        return SSS_REGEXP_ERROR_NOMEMORY;
    }
    talloc_set_destructor(self, sss_regexp_destroy);

    ret = sss_regexp_pcre2_compile(self,
                                   pattern,
                                   options);
    if (ret != EOK) {
        talloc_free(self);
        self = NULL;
    }
    *self_p = self;
    return ret;
}

/*
 * sss_regexp match function
 */
int sss_regexp_match(sss_regexp_t *self,
                     const char *subject,
                     int startoffset,
                     int options)
{
    if (!self || !self->re || !subject) return SSS_REGEXP_ERROR_NOMATCH;

    return sss_regexp_pcre2_match(self, subject, startoffset, options);
}


/*
 * sss_regexp get named substring
 */
int sss_regexp_get_named_substring(sss_regexp_t *self,
                                   const char *name,
                                   const char **value)
{
    if (!self || !self->re || !name) {
        *value = NULL;
        return SSS_REGEXP_ERROR_NOMATCH;
    }

    return sss_regexp_pcre2_get_named_substring(self, name, value);
}
