/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

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

char *sss_base64_encode(TALLOC_CTX *mem_ctx,
                        const unsigned char *in,
                        size_t insize)
{
    DEBUG(SSSDBG_CRIT_FAILURE, ("sss_base64_encode not implemented.\n"));
    return NULL;
}

unsigned char *sss_base64_decode(TALLOC_CTX *mem_ctx,
                                 const char *in,
                                 size_t *outsize)
{
    DEBUG(SSSDBG_CRIT_FAILURE, ("sss_base64_decode not implemented.\n"));
    return NULL;
}
