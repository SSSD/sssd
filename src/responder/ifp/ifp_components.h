/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#ifndef _IFP_COMPONENTS_H_
#define _IFP_COMPONENTS_H_

#include "responder/ifp/ifp_iface_generated.h"
#include "responder/ifp/ifp_private.h"

#define INFOPIPE_COMPONENT_PATH_PFX "/org/freedesktop/sssd/infopipe/Components"
#define INFOPIPE_COMPONENT_PATH INFOPIPE_COMPONENT_PATH_PFX "*"

#define INFOPIPE_BACKEND_PATH INFOPIPE_COMPONENT_PATH_PFX "/Backends*"

/* org.freedesktop.sssd.infopipe */

int ifp_list_components(struct sbus_request *dbus_req, void *data);

int ifp_list_responders(struct sbus_request *dbus_req, void *data);

int ifp_list_backends(struct sbus_request *dbus_req, void *data);

int ifp_find_monitor(struct sbus_request *dbus_req, void *data);

int ifp_find_responder_by_name(struct sbus_request *dbus_req,
                               void *data,
                               const char *arg_name);

int ifp_find_backend_by_name(struct sbus_request *dbus_req,
                             void *data,
                             const char *arg_name);

/* org.freedesktop.sssd.infopipe.Components */

int ifp_component_enable(struct sbus_request *dbus_req, void *data);

int ifp_component_disable(struct sbus_request *dbus_req, void *data);

int ifp_component_change_debug_level(struct sbus_request *dbus_req,
                                     void *data,
                                     uint32_t arg_new_level);

int ifp_component_change_debug_level_tmp(struct sbus_request *dbus_req,
                                         void *data,
                                         uint32_t arg_new_level);

void ifp_component_get_name(struct sbus_request *dbus_req,
                            void *data,
                            const char **_out);

void ifp_component_get_debug_level(struct sbus_request *dbus_req,
                                   void *data,
                                   uint32_t *_out);

void ifp_component_get_enabled(struct sbus_request *dbus_req,
                               void *data,
                               bool *_out);

void ifp_component_get_type(struct sbus_request *dbus_req,
                            void *data,
                            const char **_out);

/* org.freedesktop.sssd.infopipe.Components.Backends */

void ifp_backend_get_providers(struct sbus_request *dbus_req,
                               void *data,
                               const char ***_out,
                               int *_out_len);

#endif /* _IFP_COMPONENTS_H_ */
