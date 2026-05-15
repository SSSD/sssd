/*
    SSSD

    Authors:
        Tomas Halman <thalman@redhat.com>

    Copyright (C) 2018 Red Hat

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

#ifndef SSS_REGEXP_H_
#define SSS_REGEXP_H_

#include <stddef.h>
#include <talloc.h>
#include "config.h"

/* regexp class */
typedef struct _sss_regexp_t sss_regexp_t;

#include <pcre2.h>
#define SSS_REGEXP_ERROR_NOMATCH  PCRE2_ERROR_NOMATCH
#define SSS_REGEXP_ERROR_NOMEMORY PCRE2_ERROR_NOMEMORY
#define SSS_REGEXP_NOTEMPTY       PCRE2_NOTEMPTY
#define SSS_REGEXP_EXTENDED       PCRE2_EXTENDED
#define SSS_REGEXP_DUPNAMES       PCRE2_DUPNAMES

/* how to use sss_regexp:
 *
 *  int err;
 *  const char *found;
 *
 *  sss_regexp_t *re
 *  err = sss_regexp_new (NULL, "#(?P<myname>.+)#", 0, &re);
 *  if (err != EOK) {
 *      goto fail;
 *  }
 *  int rc = sss_regexp_match (re,
 *                             "a#findthis#b",
 *                             0,
 *                             0);
 *  if (rc != 0) { ... }
 *  rc = sss_regexp_get_named_substring (re, "myname", &found);
 *  ...
 *  talloc_free (re);
 */

/*
 * Create new compiled regexp object.
 */
int sss_regexp_new(TALLOC_CTX *mem_ctx,
                   const char *pattern,
                   int options,
                   sss_regexp_t **self_p);

/*
 * Search subject with previously created regexp.
 */
int sss_regexp_match(sss_regexp_t *self,
                     const char *subject,
                     int startoffset,
                     int options);

/*
 * Get named substring from last sss_regexp_match.
 */
int sss_regexp_get_named_substring(sss_regexp_t *self,
                                   const char *name,
                                   const char **value);

#endif /* SSS_REGEXP_H_ */
