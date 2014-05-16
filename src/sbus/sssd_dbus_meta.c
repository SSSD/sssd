/*
    Authors:
        Stef Walter <stefw@redhat.com>

    Copyright (C) 2014 Red Hat

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
#include "sbus/sssd_dbus_meta.h"

const struct sbus_method_meta *
sbus_meta_find_method(const struct sbus_interface_meta *interface,
                      const char *method_name)
{
    const struct sbus_method_meta *method;

    for (method = interface->methods; method && method->name; method++) {
        if (strcmp(method_name, method->name) == 0) {
            return method;
        }
    }

    return NULL;
}

const struct sbus_signal_meta *
sbus_meta_find_signal(const struct sbus_interface_meta *interface,
                      const char *signal_name)
{
    const struct sbus_signal_meta *sig;

    for (sig = interface->signals; sig && sig->name; sig++) {
        if (strcmp(signal_name, sig->name) == 0) {
            return sig;
        }
    }

    return NULL;
}

const struct sbus_property_meta *
sbus_meta_find_property(const struct sbus_interface_meta *interface,
                        const char *property_name)
{
    const struct sbus_property_meta *property;

    for (property = interface->properties; property && property->name; property++) {
        if (strcmp(property_name, property->name) == 0) {
            return property;
        }
    }

    return NULL;
}
