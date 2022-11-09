#
# SSSD integration test - operations on UNIX user and group database
#
# Copyright (c) 2016 Red Hat, Inc.
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
import pwd
import grp
import pytest

import ent


USER1 = dict(name='user1', passwd='*', uid=10001, gid=20001,
             gecos='User for tests',
             dir='/home/user1',
             shell='/bin/bash')

GROUP1 = dict(name='group1',
              gid=30001,
              mem=['user1'])


def test_useradd(passwd_ops_setup):
    with pytest.raises(KeyError):
        pwd.getpwnam("user1")
    passwd_ops_setup.useradd(**USER1)
    ent.assert_passwd_by_name("user1", USER1)


def test_usermod(passwd_ops_setup):
    passwd_ops_setup.useradd(**USER1)
    ent.assert_passwd_by_name("user1", USER1)

    USER1['shell'] = '/bin/zsh'
    passwd_ops_setup.usermod(**USER1)
    ent.assert_passwd_by_name("user1", USER1)


def test_userdel(passwd_ops_setup):
    passwd_ops_setup.useradd(**USER1)
    ent.assert_passwd_by_name("user1", USER1)

    passwd_ops_setup.userdel("user1")
    with pytest.raises(KeyError):
        pwd.getpwnam("user1")


def test_groupadd(group_ops_setup):
    with pytest.raises(KeyError):
        grp.getgrnam("group1")
    group_ops_setup.groupadd(**GROUP1)
    ent.assert_group_by_name("group1", GROUP1)


def test_groupmod(group_ops_setup):
    group_ops_setup.groupadd(**GROUP1)
    ent.assert_group_by_name("group1", GROUP1)

    modgroup = dict(GROUP1)
    modgroup['mem'] = []

    group_ops_setup.groupmod(old_name=GROUP1["name"], **modgroup)
    ent.assert_group_by_name("group1", modgroup)


def test_groupdel(group_ops_setup):
    group_ops_setup.groupadd(**GROUP1)
    ent.assert_group_by_name("group1", GROUP1)

    group_ops_setup.groupdel("group1")
    with pytest.raises(KeyError):
        grp.getgrnam("group1")
