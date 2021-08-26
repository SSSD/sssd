/*
   SSSD

   tools_utils.c

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009

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

#include <popt.h>
#include <errno.h>

#include "util/util.h"
#include "tools/tools_util.h"

/*
 * Print poptUsage as well as our error message
 */
void usage(poptContext pc, const char *error)
{
    size_t lentmp;

    poptPrintUsage(pc, stderr, 0);

    if (error) {
        lentmp = strlen(error);
        if ((lentmp > 0) && (error[lentmp - 1] != '\n')) {
            fprintf(stderr, "%s\n", error);
            return;
        }

        fprintf(stderr, "%s", error);
    }
}

int set_locale(void)
{
    char *c;

    c = setlocale(LC_ALL, "");
    if (c == NULL) {
        /* If setlocale fails, continue with the default
         * locale. */
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to set locale\n");
    }

    errno = 0;
    c = bindtextdomain(PACKAGE, LOCALEDIR);
    if (c == NULL) {
        return errno;
    }

    errno = 0;
    c = textdomain(PACKAGE);
    if (c == NULL) {
        return errno;
    }

    return EOK;
}
