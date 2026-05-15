/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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
#include <talloc.h>

#include "sbus/sbus_request.h"
#include "sbus/sbus_private.h"

errno_t
sbus_invoker_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t
sbus_request_key(TALLOC_CTX *mem_ctx,
                 sbus_invoker_keygen keygen,
                 struct sbus_request *sbus_req,
                 void *input,
                 const char **_key)
{
    const char *(*args_fn)(TALLOC_CTX *, struct sbus_request *, void *);
    const char *(*noargs_fn)(TALLOC_CTX *, struct sbus_request *);
    const char *key;

    if (keygen == NULL) {
        *_key = NULL;
        return EOK;
    }

    if (input == NULL) {
        noargs_fn = keygen;
        key = noargs_fn(mem_ctx, sbus_req);
    } else {
        args_fn = keygen;
        key = args_fn(mem_ctx, sbus_req, input);
    }

    if (key == NULL) {
        return ENOMEM;
    }

    *_key = key;

    return EOK;

}
