#
# LDAP modlist generation
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


def user(base_dn, uid, uidNumber, gidNumber,
         userPassword=None,
         gecos=None,
         homeDirectory=None,
         loginShell=None,
         cn=None,
         sn=None,
         sshPubKey=(),
         mail=None):
    """
    Generate an RFC2307(bis) user add-modlist for passing to ldap.add*
    """
    uidNumber = str(uidNumber).encode('utf-8')
    gidNumber = str(gidNumber).encode('utf-8')
    user = (
        "uid=" + uid + ",ou=Users," + base_dn,
        [
            ('objectClass', [b'top', b'inetOrgPerson', b'mailRecipient',
                             b'posixAccount', b'ldapPublicKey']),
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
    if len(sshPubKey) > 0:
        pubkeys = [key.encode('utf-8') for key in sshPubKey]
        user[1].append(('sshPublicKey', pubkeys))
    if mail is not None:
        user[1].append(('mail', [mail.encode('utf-8')]))
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


def sudo_rule(base_dn, name, users=(), hosts=(), commands=()):
    """
    Generate a sudo rule for passing to ldap.add*
    """
    attr_list = [
        ('objectClass', [b'top', b'sudoRole']),
        ('cn', [name.encode('utf-8')])
    ]

    if len(users) > 0:
        sudo_user_list = [u.encode('utf-8') for u in users]
        attr_list.append(('sudoUser', sudo_user_list))
    if len(hosts) > 0:
        sudo_host_list = [h.encode('utf-8') for h in hosts]
        attr_list.append(('sudoHost', sudo_host_list))
    if len(commands) > 0:
        sudo_command_list = [cmd.encode('utf-8') for cmd in commands]
        attr_list.append(('sudoCommand', sudo_command_list))
    return ("cn=" + name + ",ou=sudoers," + base_dn, attr_list)


def ip_host(base_dn, name, aliases=(), addresses=()):
    """
    Generate an RFC2307 ipHost add-modlist for passing to ldap.add*.
    """
    attr_list = [
        ('objectClass', [b'top', b'device', b'ipHost']),
    ]
    if (len(aliases)) > 0:
        alias_list = [alias.encode('utf-8') for alias in aliases]
        alias_list.insert(0, name.encode('utf-8'))
        attr_list.append(('cn', alias_list))
    else:
        attr_list.append(('cn', [name.encode('utf-8')]))
    if len(addresses) > 0:
        addr_list = [addr.encode('utf-8') for addr in addresses]
        attr_list.append(('ipHostNumber', addr_list))
    return ("cn=" + name + ",ou=Hosts," + base_dn, attr_list)


def ip_net(base_dn, name, address, aliases=()):
    """
    Generate an RFC2307 ipNetwork add-modlist for passing to ldap.add*.
    """
    attr_list = [
        ('objectClass', [b'top', b'ipNetwork']),
        ('ipNetworkNumber', [address.encode('utf-8')]),
    ]
    if (len(aliases)) > 0:
        alias_list = [alias.encode('utf-8') for alias in aliases]
        alias_list.insert(0, name.encode('utf-8'))
        attr_list.append(('cn', alias_list))
    else:
        attr_list.append(('cn', [name.encode('utf-8')]))
    return ("cn=" + name + ",ou=Networks," + base_dn, attr_list)


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
                 sn=None,
                 sshPubKey=(),
                 mail=None):
        """Add an RFC2307(bis) user add-modlist."""
        self.append(user(base_dn or self.base_dn,
                         uid, uidNumber, gidNumber,
                         userPassword=userPassword,
                         gecos=gecos,
                         homeDirectory=homeDirectory,
                         loginShell=loginShell,
                         cn=cn,
                         sn=sn,
                         sshPubKey=sshPubKey,
                         mail=mail))

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

    def add_sudo_rule(self, name,
                      users=(), hosts=(), commands=(),
                      base_dn=None):
        self.append(sudo_rule(base_dn or self.base_dn,
                              name, users, hosts, commands))

    def add_host(self, name, aliases=[], addresses=[], base_dn=None):
        """Add an RFC2307 ipHost add-modlist."""
        self.append(ip_host(base_dn or self.base_dn,
                            name, aliases, addresses))

    def add_ipnet(self, name, address, aliases=[], base_dn=None):
        """Add an RFC2307 ipNetwork add-modlist."""
        self.append(ip_net(base_dn or self.base_dn,
                           name, address, aliases))
