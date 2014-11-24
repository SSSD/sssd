#
# LDAP modlist generation
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

def user(base_dn, uid, uidNumber, gidNumber):
    """
    Generate an RFC2307(bis) user add-modlist for passing to ldap.add*
    """
    uidNumber = str(uidNumber)
    gidNumber = str(gidNumber)
    return (
        "uid=" + uid + ",ou=Users," + base_dn,
        [
            ('objectClass',     ['top', 'inetOrgPerson', 'posixAccount']),
            ('cn',              [uidNumber]),
            ('sn',              ['User']),
            ('uidNumber',       [uidNumber]),
            ('gidNumber',       [gidNumber]),
            ('userPassword',    ['Password' + uidNumber]),
            ('homeDirectory',   ['/home/' + uid]),
            ('loginShell',      ['/bin/bash']),
        ]
    )

def group(base_dn, cn, gidNumber, member_uids=[]):
    """
    Generate an RFC2307 group add-modlist for passing to ldap.add*.
    """
    gidNumber = str(gidNumber)
    attr_list = [
        ('objectClass', ['top', 'posixGroup']),
        ('gidNumber', [gidNumber])
    ]
    if len(member_uids) > 0:
        attr_list.append(('memberUid', member_uids))
    return ("cn=" + cn + ",ou=Groups," + base_dn, attr_list)

def group_bis(base_dn, cn, gidNumber, member_uids=[], member_gids=[]):
    """
    Generate an RFC2307bis group add-modlist for passing to ldap.add*.
    """
    gidNumber = str(gidNumber)
    attr_list = [
        ('objectClass', ['top', 'extensibleObject', 'groupOfNames']),
        ('gidNumber', [gidNumber])
    ]
    if len(member_uids) > 0:
        attr_list.append(
            ('member', [
                "uid=" + uid + ",ou=Users," + base_dn for
                    uid in member_uids
            ])
        )
    if len(member_gids) > 0:
        attr_list.append(
            ('member', [
                "cn=" + gid + ",ou=Groups," + base_dn for
                    gid in member_gids
            ])
        )
    return ("cn=" + cn + ",ou=Groups," + base_dn, attr_list)

class List(list):
    """LDAP add-modlist list"""

    def __init__(self, base_dn):
        self.base_dn = base_dn

    def add_user(self, uid, uidNumber, gidNumber,
                 base_dn=None):
        """Add an RFC2307(bis) user add-modlist."""
        self.append(user(base_dn or self.base_dn,
                         uid, uidNumber, gidNumber))

    def add_group(self, cn, gidNumber, member_uids=[],
                  base_dn=None):
        """Add an RFC2307 group add-modlist."""
        self.append(group(base_dn or self.base_dn,
                          cn, gidNumber, member_uids))

    def add_group_bis(self, cn, gidNumber,
                      member_uids=[], member_gids=[],
                      base_dn=None):
        """Add an RFC2307bis group add-modlist."""
        self.append(group_bis(base_dn or self.base_dn,
                              cn, gidNumber,
                              member_uids, member_gids))
