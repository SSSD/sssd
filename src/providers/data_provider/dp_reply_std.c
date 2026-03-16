/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <tevent.h>

#include "providers/data_provider/dp_private.h"
#include "providers/backend.h"
#include "util/sss_utf8.h"
#include "util/util.h"

void dp_reply_std_set(struct dp_reply_std *reply,
                      int error,
                      const char *msg)
{
    const char *def_msg;

    def_msg = sss_strerror(error);

    reply->error = error;
    reply->message = msg == NULL ? def_msg : msg;
}
