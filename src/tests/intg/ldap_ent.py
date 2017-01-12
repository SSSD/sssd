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


def user(base_dn, uid, uidNumber, gidNumber,
         userPassword=None,
         gecos=None,
         homeDirectory=None,
         loginShell=None,
         cn=None,
         sn=None):
    """
    Generate an RFC2307(bis) user add-modlist for passing to ldap.add*
    """
    uidNumber = str(uidNumber).encode('utf-8')
    gidNumber = str(gidNumber).encode('utf-8')
    user = (
        "uid=" + uid + ",ou=Users," + base_dn,
        [
            ('objectClass', [b'top', b'inetOrgPerson', b'posixAccount']),
            ('cn', [uidNumber if cn is None else cn.encode('utf-8')]),
            ('sn', [b'User' if sn is None else sn.encode('utf-8')]),
            ('uidNumber', [uidNumber]),
            ('gidNumber', [gidNumber]),
            ('userPassword', [b'Password' + uidNumber
                              if userPassword is None
                              else userPassword.encode('utf-8')]),
            ('homeDirectory', [b'/home/' + uid.encode('utf-8')
                               if homeDirectory is None
                               else homeDirectory.encode('utf-8')]),
            ('loginShell', [b'/bin/bash'
                            if loginShell is None
                            else loginShell.encode('utf-8')]),
        ]
    )
    if gecos is not None:
        user[1].append(('gecos', [gecos.encode('utf-8')]))
    return user


def group(base_dn, cn, gidNumber, member_uids=()):
    """
    Generate an RFC2307 group add-modlist for passing to ldap.add*.
    """
    gidNumber = str(gidNumber).encode('utf-8')
    attr_list = [
        ('objectClass', [b'top', b'posixGroup']),
        ('gidNumber', [gidNumber])
    ]
    if len(member_uids) > 0:
        mem_uids = [member.encode('utf-8') for member in member_uids]
        attr_list.append(('memberUid', mem_uids))
    return ("cn=" + cn + ",ou=Groups," + base_dn, attr_list)


def group_bis(base_dn, cn, gidNumber, member_uids=(), member_gids=()):
    """
    Generate an RFC2307bis group add-modlist for passing to ldap.add*.
    """
    gidNumber = str(gidNumber).encode('utf-8')
    attr_list = [
        ('objectClass', [b'top', b'extensibleObject', b'groupOfNames']),
        ('gidNumber', [gidNumber])
    ]
    member_list = []
    for uid in member_uids:
        member_list.append("uid=" + uid + ",ou=Users," + base_dn)
    for gid in member_gids:
        member_list.append("cn=" + gid + ",ou=Groups," + base_dn)
    if len(member_list) > 0:
        mem_list = [member.encode('utf-8') for member in member_list]
        attr_list.append(('member', mem_list))
    return ("cn=" + cn + ",ou=Groups," + base_dn, attr_list)


def netgroup(base_dn, cn, triples=(), members=()):
    """
    Generate an RFC2307bis netgroup add-modlist for passing to ldap.add*.
    """
    attr_list = [
        ('objectClass', [b'top', b'nisNetgroup'])
    ]
    if triples:
        triples = [triple.encode('utf-8') for triple in triples]
        attr_list.append(('nisNetgroupTriple', triples))
    if members:
        members = [member.encode('utf-8') for member in members]
        attr_list.append(('memberNisNetgroup', members))
    return ("cn=" + cn + ",ou=Netgroups," + base_dn, attr_list)


class List(list):
    """LDAP add-modlist list"""

    def __init__(self, base_dn):
        self.base_dn = base_dn

    def add_user(self, uid, uidNumber, gidNumber,
                 base_dn=None,
                 userPassword=None,
                 gecos=None,
                 homeDirectory=None,
                 loginShell=None,
                 cn=None,
                 sn=None):
        """Add an RFC2307(bis) user add-modlist."""
        self.append(user(base_dn or self.base_dn,
                         uid, uidNumber, gidNumber,
                         userPassword=userPassword,
                         gecos=gecos,
                         homeDirectory=homeDirectory,
                         loginShell=loginShell,
                         cn=cn,
                         sn=sn))

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

    def add_netgroup(self, cn, triples=(), members=(), base_dn=None):
        """Add an RFC2307bis netgroup add-modlist."""
        self.append(netgroup(base_dn or self.base_dn,
                             cn, triples, members))
