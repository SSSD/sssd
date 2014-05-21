/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#include "config.h"

#include <stdio.h>
#include <sys/time.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"
#include "sbus/sssd_dbus_meta.h"

static const struct sbus_arg_meta introspect_method_arg_out[] = {
    { "data", "s" },
    { NULL, }
};

const struct sbus_method_meta introspect_method =
    { DBUS_INTROSPECT_METHOD, NULL, introspect_method_arg_out, 0, NULL };

#define SSS_INTROSPECT_DOCTYPE  \
    "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" \
    "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"

#define SSS_INTROSPECT_INTERFACE_INTROSPECTABLE                      \
     " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"   \
     "   <method name=\"Introspect\">\n"                             \
     "     <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"      \
     "   </method>\n"                                                \
     " </interface>\n"

#define SSS_INTROSPECT_INTERFACE_PROPERTIES                                 \
     " <interface name=\"org.freedesktop.DBus.Properties\">\n"              \
     "   <method name=\"Get\">\n"                                           \
     "     <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"         \
     "     <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"          \
     "     <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"            \
     "   </method>\n"                                                       \
     "   <method name=\"GetAll\">\n"                                        \
     "     <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"         \
     "     <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"   \
     "   </method>\n"                                                       \
     " </interface>\n"

struct introspect_ctx {
    FILE *f;
    char *buf;
    size_t size;

    const struct sbus_interface_meta *iface;
};

static int introspect_ctx_destructor(struct introspect_ctx *ictx)
{
    if (ictx->f) {
        fclose(ictx->f);
    }

    free(ictx->buf);
    ictx->buf = NULL;
    return 0;
}

static errno_t introspect_begin(struct introspect_ctx *ictx)
{
    errno_t ret;

    ictx->f = open_memstream(&ictx->buf, &ictx->size);
    if (ictx->f == NULL) {
        return ENOMEM;
    }

    ret = fputs(SSS_INTROSPECT_DOCTYPE, ictx->f);
    if (ret < 0) return EIO;
    ret = fputs("<node>\n", ictx->f);
    if (ret < 0) return EIO;

    ret = fprintf(ictx->f, "  <interface name=\"%s\">\n", ictx->iface->name);
    if (ret <= 0) return EIO;

    return EOK;
}

static errno_t introspect_add_arg(struct introspect_ctx *ictx,
                                  const struct sbus_arg_meta *a,
                                  const char *direction)
{
    errno_t ret;

    ret = fprintf(ictx->f,
                  "      <arg type=\"%s\" name=\"%s\"",
                  a->type, a->name);
    if (ret <= 0) return EIO;

    if (direction) {
        ret = fprintf(ictx->f, " direction=\"%s\"", direction);
        if (ret <= 0) return EIO;
    }

    ret = fprintf(ictx->f, "/>\n");
    if (ret <= 0) return EIO;

    return EOK;
}

#define introspect_add_in_arg(i, a) introspect_add_arg(i, a, "in");
#define introspect_add_out_arg(i, a) introspect_add_arg(i, a, "out");
#define introspect_add_sig_arg(i, a) introspect_add_arg(i, a, NULL);

static errno_t introspect_add_meth(struct introspect_ctx *ictx,
                                   const struct sbus_method_meta *m)
{
    errno_t ret;
    int i;

    ret = fprintf(ictx->f, "    <method name=\"%s\">\n", m->name);
    if (ret <= 0) return EIO;

    if (m->in_args != NULL) {
        for (i = 0; m->in_args[i].name != NULL; i++) {
            ret = introspect_add_in_arg(ictx, &m->in_args[i]);
            if (ret != EOK) {
                continue;
            }
        }
    }

    if (m->out_args != NULL) {
        for (i = 0; m->out_args[i].name != NULL; i++) {
            ret = introspect_add_out_arg(ictx, &m->out_args[i]);
            if (ret != EOK) {
                continue;
            }
        }
    }

    ret = fputs("    </method>\n", ictx->f);
    if (ret < 0) return EIO;

    return EOK;
}

static errno_t introspect_add_methods(struct introspect_ctx *ictx)
{
    errno_t ret;
    int i;

    if (ictx->iface->methods == NULL) {
        /* An interface with no methods */
        return EOK;
    }

    for (i = 0; ictx->iface->methods[i].name != NULL; i++) {
        ret = introspect_add_meth(ictx, &ictx->iface->methods[i]);
        if (ret != EOK) {
            continue;
        }
    }

    return EOK;
}

static errno_t introspect_add_sig(struct introspect_ctx *ictx,
                                  const struct sbus_signal_meta *s)
{
    errno_t ret;
    int i;

    ret = fprintf(ictx->f, "    <signal name=\"%s\">\n", s->name);
    if (ret <= 0) return EIO;

    if (s->args != NULL) {
        for (i = 0; s->args[i].name != NULL; i++) {
            ret = introspect_add_sig_arg(ictx, &s->args[i]);
            if (ret != EOK) {
                continue;
            }
        }
    }

    ret = fputs("    </signal>\n", ictx->f);
    if (ret < 0) return EIO;

    return EOK;
}

static errno_t introspect_add_signals(struct introspect_ctx *ictx)
{
    errno_t ret;
    int i;

    if (ictx->iface->signals == NULL) {
        /* An interface with no signals */
        return EOK;
    }

    for (i = 0; ictx->iface->signals[i].name != NULL; i++) {
        ret = introspect_add_sig(ictx, &ictx->iface->signals[i]);
        if (ret != EOK) {
            continue;
        }
    }

    return EOK;
}

static errno_t introspect_add_prop(struct introspect_ctx *ictx,
                                   const struct sbus_property_meta *p)
{
    errno_t ret;

    ret = fprintf(ictx->f, "    <property name=\"%s\" type=\"%s\" access=\"%s\"/>\n",
                           p->name, p->type,
                           p->flags & SBUS_PROPERTY_WRITABLE ? "readwrite" : "read");
    if (ret <= 0) return EIO;

    return EOK;
}

static errno_t introspect_add_properties(struct introspect_ctx *ictx)
{
    errno_t ret;
    int i;

    if (ictx->iface->properties == NULL) {
        /* An interface with no properties */
        return EOK;
    }

    for (i = 0; ictx->iface->properties[i].name != NULL; i++) {
        ret = introspect_add_prop(ictx, &ictx->iface->properties[i]);
        if (ret != EOK) {
            continue;
        }
    }

    return EOK;
}

static errno_t introspect_finish(struct introspect_ctx *ictx)
{
    errno_t ret;

    ret = fputs("  </interface>\n", ictx->f);
    if (ret < 0) return EIO;

    ret = fputs(SSS_INTROSPECT_INTERFACE_INTROSPECTABLE, ictx->f);
    if (ret < 0) return EIO;

    ret = fputs(SSS_INTROSPECT_INTERFACE_PROPERTIES, ictx->f);
    if (ret < 0) return EIO;

    ret = fputs("</node>\n", ictx->f);
    if (ret < 0) return EIO;

    fflush(ictx->f);
    return EOK;
}

static char *sbus_introspect_xml(TALLOC_CTX *mem_ctx,
                                 const struct sbus_interface_meta *iface)
{
    struct introspect_ctx *ictx;
    char *buf_out = NULL;
    errno_t ret;

    ictx = talloc_zero(mem_ctx, struct introspect_ctx);
    if (ictx == NULL) {
        return NULL;
    }
    ictx->iface = iface;
    talloc_set_destructor(ictx, introspect_ctx_destructor);

    ret = introspect_begin(ictx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "introspect_begin failed: %d\n", ret);
        goto done;
    }

    ret = introspect_add_methods(ictx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "introspect_add_methods failed: %d\n", ret);
        goto done;
    }

    ret = introspect_add_signals(ictx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "introspect_add_signals failed: %d\n", ret);
        goto done;
    }

    ret = introspect_add_properties(ictx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "introspect_add_properties failed: %d\n", ret);
        goto done;
    }

    ret = introspect_finish(ictx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "introspect_finish failed: %d\n", ret);
        goto done;
    }

    buf_out = talloc_memdup(mem_ctx, ictx->buf, ictx->size + 1);
    DEBUG(SSSDBG_TRACE_LIBS, "Introspection: \n%s\n", buf_out);
done:
    talloc_free(ictx);
    return buf_out;
}

int sbus_introspect(struct sbus_request *dbus_req, void *pvt)
{
    char *xml;
    DBusError dberr;
    const struct sbus_interface_meta *iface;
    struct sbus_introspect_ctx *ictx;

    ictx = talloc_get_type(pvt, struct sbus_introspect_ctx);
    if (ictx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
    }
    iface = ictx->iface;

    xml = sbus_introspect_xml(dbus_req, iface);
    if (xml == NULL) {
        dbus_error_init(&dberr);
        dbus_set_error_const(&dberr,
                             DBUS_ERROR_NO_MEMORY,
                             "Failed to generate introspection data\n");
        return sbus_request_fail_and_finish(dbus_req, &dberr);
    }

    return sbus_request_return_and_finish(dbus_req,
                                          DBUS_TYPE_STRING, &xml,
                                          DBUS_TYPE_INVALID);

}
