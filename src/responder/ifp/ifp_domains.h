/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
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

#ifndef IFP_DOMAINS_H_
#define IFP_DOMAINS_H_

#include "responder/ifp/ifp_iface_generated.h"
#include "responder/ifp/ifp_private.h"

#define INFOPIPE_DOMAIN_PATH_PFX "/org/freedesktop/sssd/infopipe/Domains"
#define INFOPIPE_DOMAIN_PATH     INFOPIPE_DOMAIN_PATH_PFX"*"

/* org.freedesktop.sssd.infopipe */

int ifp_list_domains(struct sbus_request *dbus_req,
                     void *data);

int ifp_find_domain_by_name(struct sbus_request *dbus_req,
                            void *data,
                            const char *arg_name);

/* org.freedesktop.sssd.infopipe.Domains */

void ifp_dom_get_name(struct sbus_request *dbus_req,
                      void *data,
                      const char **_out);

void ifp_dom_get_provider(struct sbus_request *dbus_req,
                          void *data,
                          const char **_out);

void ifp_dom_get_primary_servers(struct sbus_request *dbus_req,
                                 void *data,
                                 const char ***_out,
                                 int *_out_len);

void ifp_dom_get_backup_servers(struct sbus_request *dbus_req,
                                void *data,
                                const char ***_out,
                                int *_out_len);

void ifp_dom_get_min_id(struct sbus_request *dbus_req,
                        void *data,
                        uint32_t *_out);

void ifp_dom_get_max_id(struct sbus_request *dbus_req,
                        void *data,
                        uint32_t *_out);

void ifp_dom_get_realm(struct sbus_request *dbus_req,
                       void *data,
                       const char **_out);

void ifp_dom_get_forest(struct sbus_request *dbus_req,
                        void *data,
                        const char **_out);

void ifp_dom_get_login_format(struct sbus_request *dbus_req,
                              void *data,
                              const char **_out);

void ifp_dom_get_fqdn_format(struct sbus_request *dbus_req,
                             void *data,
                             const char **_out);

void ifp_dom_get_enumerable(struct sbus_request *dbus_req,
                            void *data,
                            bool *_out);

void ifp_dom_get_use_fqdn(struct sbus_request *dbus_req,
                          void *data,
                          bool *_out);

void ifp_dom_get_subdomain(struct sbus_request *dbus_req,
                           void *data,
                           bool *_out);

void ifp_dom_get_parent_domain(struct sbus_request *dbus_req,
                              void *data,
                              const char **_out);

#endif /* IFP_DOMAINS_H_ */
