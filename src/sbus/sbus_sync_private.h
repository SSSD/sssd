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

#ifndef _SBUS_SYNC_PRIVATE_H_
#define _SBUS_SYNC_PRIVATE_H_

#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_sync.h"

/* Generic type of an invoker arguments writer. */
typedef errno_t (*sbus_invoker_writer_fn)(DBusMessageIter *, void *);

/* Generic type of an invoker arguments reader. */
typedef errno_t (*sbus_invoker_reader_fn)(TALLOC_CTX *, DBusMessageIter *, void *);

/* Generic type for iterator readers. */
typedef errno_t (*sbus_value_reader_fn)(DBusMessageIter *, void *);
typedef errno_t (*sbus_value_reader_talloc_fn)(TALLOC_CTX *, DBusMessageIter *, void *);

errno_t
sbus_write_input(DBusMessage *msg,
                 sbus_invoker_writer_fn writer,
                 void *input);

errno_t
sbus_read_output(TALLOC_CTX *mem_ctx,
                 DBusMessage *msg,
                 sbus_invoker_reader_fn reader,
                 void *output);

DBusMessage *
sbus_create_method_call(TALLOC_CTX *mem_ctx,
                        DBusMessage *raw_message,
                        sbus_invoker_writer_fn writer,
                        const char *bus,
                        const char *path,
                        const char *iface,
                        const char *method,
                        void *input);

DBusMessage *
sbus_create_signal_call(TALLOC_CTX *mem_ctx,
                        DBusMessage *raw_message,
                        sbus_invoker_writer_fn writer,
                        const char *path,
                        const char *iface,
                        const char *signal_name,
                        void *input);

/* Create Property.Set method call. Used in generated callers. */
DBusMessage *
sbus_create_set_call(TALLOC_CTX *mem_ctx,
                     sbus_invoker_writer_fn writer,
                     const char *bus,
                     const char *path,
                     const char *iface,
                     const char *property,
                     const char *type,
                     void *input);

/* Parse reply of an Properties.Get message. */
errno_t
sbus_parse_get_message(TALLOC_CTX *mem_ctx,
                       sbus_value_reader_fn reader,
                       sbus_value_reader_talloc_fn reader_talloc,
                       DBusMessage *msg,
                       void *_value_ptr);

struct sbus_parse_getall_table {
    /* Property name. */
    const char *name;

    /* Read to read its value. */
    sbus_value_reader_fn reader;
    sbus_value_reader_talloc_fn reader_talloc;

    /* Destination where to store the value. */
    void *destination;
    bool *is_set;
};

/* Parse reply of an Properties.GetAll message. */
errno_t
sbus_parse_getall_message(TALLOC_CTX *mem_ctx,
                          struct sbus_parse_getall_table *table,
                          DBusMessage *msg);

errno_t
sbus_sync_call_method(TALLOC_CTX *mem_ctx,
                      struct sbus_sync_connection *conn,
                      DBusMessage *raw_message,
                      sbus_invoker_writer_fn writer,
                      const char *bus,
                      const char *path,
                      const char *iface,
                      const char *method,
                      void *input,
                      DBusMessage **_reply);

void
sbus_sync_call_signal(struct sbus_sync_connection *conn,
                      DBusMessage *raw_message,
                      sbus_invoker_writer_fn writer,
                      const char *path,
                      const char *iface,
                      const char *signal_name,
                      void *input);

#endif /* _SBUS_SYNC_PRIVATE_H_ */
