/*
    Generated by sbus code generator

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

#include <inttypes.h>
#include <talloc.h>

#include "sbus/sbus_request.h"
#include "sbus/interface_dbus/sbus_dbus_arguments.h"
#include "sbus/interface_dbus/sbus_dbus_keygens.h"

const char *
_sbus_dbus_key_
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s:%s.%s:%s",
            sbus_req->type, sbus_req->destination, sbus_req->interface,
            sbus_req->member, sbus_req->path);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s:%s.%s:%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->destination,
        sbus_req->interface, sbus_req->member, sbus_req->path);
}

const char *
_sbus_dbus_key_s_0
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_dbus_invoker_args_s *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s:%s.%s:%s:%s",
            sbus_req->type, sbus_req->destination, sbus_req->interface,
            sbus_req->member, sbus_req->path, args->arg0);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s:%s.%s:%s:%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->destination, sbus_req->interface,
        sbus_req->member, sbus_req->path, args->arg0);
}

const char *
_sbus_dbus_key_ss_0_1
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_dbus_invoker_args_ss *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s:%s.%s:%s:%s:%s",
            sbus_req->type, sbus_req->destination, sbus_req->interface,
            sbus_req->member, sbus_req->path, args->arg0, args->arg1);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s:%s.%s:%s:%s:%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->destination, sbus_req->interface,
        sbus_req->member, sbus_req->path, args->arg0, args->arg1);
}

const char *
_sbus_dbus_key_su_0
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_dbus_invoker_args_su *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s:%s.%s:%s:%s",
            sbus_req->type, sbus_req->destination, sbus_req->interface,
            sbus_req->member, sbus_req->path, args->arg0);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s:%s.%s:%s:%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->destination, sbus_req->interface,
        sbus_req->member, sbus_req->path, args->arg0);
}
