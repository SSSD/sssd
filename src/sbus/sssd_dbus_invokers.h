/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

    SBUS: Interface introspection

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

#ifndef SSSD_DBUS_INVOKER_H_
#define SSSD_DBUS_INVOKER_H_

#include "sbus/sssd_dbus.h"

int sbus_invoke_get_y(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_b(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_n(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_q(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_i(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_u(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_x(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_t(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_d(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_s(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_o(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr);

int sbus_invoke_get_ay(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_an(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_aq(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_ai(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_au(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_ax(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_at(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_ad(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_as(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_ao(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr);

int sbus_invoke_get_aDOsasDE(DBusMessageIter *iter,
                             struct sbus_request *sbus_req,
                             void *function_ptr);

void sbus_invoke_get(struct sbus_request *sbus_req,
                     const char *type,
                     sbus_get_invoker_fn invoker_fn,
                     sbus_msg_handler_fn handler_fn);

void sbus_invoke_get_all(struct sbus_request *sbus_req);


#endif /* SSSD_DBUS_INVOKER_H_ */
