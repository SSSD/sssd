#
# Abstract directory server instance class
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import ldap


class DS(object):
    """Abstract directory server instance."""

    def __init__(self, dir, port, base_dn, admin_rdn, admin_pw):
        """
            Initialize the instance.

            Arguments:
            dir         Path to the root of the filesystem hierarchy to create
                        the instance under.
            port        TCP port on localhost to bind the server to.
            base_dn     Base DN.
            admin_rdn   Administrator DN, relative to BASE_DN.
            admin_pw    Administrator password.
        """
        self.dir = dir
        self.port = port
        self.ldap_url = "ldap://localhost:" + str(self.port)
        self.base_dn = base_dn
        self.admin_rdn = admin_rdn
        self.admin_dn = admin_rdn + "," + base_dn
        self.admin_pw = admin_pw

    def setup(self):
        """Setup the instance"""
        raise NotImplementedError()

    def teardown(self):
        """Teardown the instance"""
        raise NotImplementedError()

    def bind(self):
        """Connect to the server and bind as admin, return connection."""
        conn = ldap.initialize(self.ldap_url)
        conn.simple_bind_s(self.admin_dn, self.admin_pw)
        return conn
