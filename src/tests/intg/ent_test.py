#
# ent.py module tests
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
import re
import pytest
import ent
from util import backup_envvar_file, restore_envvar_file


@pytest.fixture(scope="module")
def passwd_path(request):
    name = "NSS_WRAPPER_PASSWD"
    request.addfinalizer(lambda: restore_envvar_file(name))
    return backup_envvar_file(name)


@pytest.fixture(scope="module")
def group_path(request):
    name = "NSS_WRAPPER_GROUP"
    request.addfinalizer(lambda: restore_envvar_file(name))
    return backup_envvar_file(name)


USER1 = dict(name="user1", passwd="x", uid=1001, gid=2001,
             gecos="User 1", dir="/home/user1", shell="/bin/bash")
USER2 = dict(name="user2", passwd="x", uid=1002, gid=2002,
             gecos="User 2", dir="/home/user2", shell="/bin/bash")
USER_LIST = [USER1, USER2]
USER_NAME_DICT = dict((u["name"], u) for u in USER_LIST)
USER_UID_DICT = dict((u["uid"], u) for u in USER_LIST)


EMPTY_GROUP = dict(name="empty_group", passwd="x", gid=2000,
                   mem=ent.contains_only())
GROUP1 = dict(name="group1", passwd="x", gid=2001,
              mem=ent.contains_only())
GROUP2 = dict(name="group2", passwd="x", gid=2002,
              mem=ent.contains_only())
ONE_USER_GROUP1 = dict(name="one_user_group1", passwd="x", gid=2011,
                       mem=ent.contains_only("user1"))
ONE_USER_GROUP2 = dict(name="one_user_group2", passwd="x", gid=2012,
                       mem=ent.contains_only("user2"))
TWO_USER_GROUP = dict(name="two_user_group", passwd="x", gid=2020,
                      mem=ent.contains_only("user1", "user2"))
GROUP_LIST = [EMPTY_GROUP,
              GROUP1,
              GROUP2,
              ONE_USER_GROUP1,
              ONE_USER_GROUP2,
              TWO_USER_GROUP]
GROUP_NAME_DICT = dict((g["name"], g) for g in GROUP_LIST)
GROUP_GID_DICT = dict((g["gid"], g) for g in GROUP_LIST)


@pytest.fixture(scope="module")
def users_and_groups(request, passwd_path, group_path):
    passwd_contents = "".join([
        "{name}:{passwd}:{uid}:{gid}:{gecos}:{dir}:{shell}\n".format(**u)
        for u in USER_LIST
    ])
    group_contents = "".join([
        "%s:%s:%s:%s\n" % (g["name"], g["passwd"], g["gid"],
                           ",".join(g["mem"]))
        for g in GROUP_LIST
    ])

    with open(passwd_path, "a") as f:
        f.write(passwd_contents)
    with open(group_path, "a") as f:
        f.write(group_contents)


def test_assert_passwd_by_name(users_and_groups):
    ent.assert_passwd_by_name("user1", {})
    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001))
    ent.assert_passwd_by_name("user1", USER1)

    try:
        ent.assert_passwd_by_name("user3", {})
        assert False
    except AssertionError as e:
        assert str(e) in ("'getpwnam(): name not found: user3'",
                          "\"getpwnam(): name not found: 'user3'\"")

    try:
        ent.assert_passwd_by_name("user2", dict(name="user1"))
        assert False
    except AssertionError as e:
        assert str(e) == "'name' mismatch: 'user1' != 'user2'"


def test_assert_passwd_by_uid(users_and_groups):
    ent.assert_passwd_by_uid(1001, {})
    ent.assert_passwd_by_uid(1001, dict(name="user1", uid=1001))
    ent.assert_passwd_by_uid(1001, USER1)

    try:
        ent.assert_passwd_by_uid(1003, {})
        assert False
    except AssertionError as e:
        assert str(e) == "'getpwuid(): uid not found: 1003'"

    try:
        ent.assert_passwd_by_uid(1002, dict(name="user1"))
        assert False
    except AssertionError as e:
        assert str(e) == "'name' mismatch: 'user1' != 'user2'"


def test_assert_passwd_list(users_and_groups):
    ent.assert_passwd_list(ent.contains())
    ent.assert_passwd_list(ent.contains(USER1))
    ent.assert_passwd_list(ent.contains_only(*USER_LIST))
    try:
        ent.assert_passwd_list(ent.contains_only())
        assert False
    except AssertionError as e:
        assert not re.search("expected users not found:", str(e))
        assert re.search("unexpected users found:", str(e))
    try:
        ent.assert_passwd_list(ent.contains(dict(name="non_existent")))
        assert False
    except AssertionError as e:
        assert re.search("expected users not found:", str(e))
        assert not re.search("unexpected users found:", str(e))


def test_assert_each_passwd_by_name(users_and_groups):
    ent.assert_each_passwd_by_name({})
    ent.assert_each_passwd_by_name(dict(user1=USER1))
    ent.assert_each_passwd_by_name(USER_NAME_DICT)
    try:
        ent.assert_each_passwd_by_name(dict(user3={}))
        assert False
    except AssertionError as e:
        assert str(e) in ("'getpwnam(): name not found: user3'",
                          "\"getpwnam(): name not found: 'user3'\"")
    try:
        ent.assert_each_passwd_by_name(dict(user1=dict(name="user2")))
        assert False
    except AssertionError as e:
        assert str(e) == \
            "user 'user1' mismatch: 'name' mismatch: 'user2' != 'user1'"


def test_assert_each_passwd_by_uid(users_and_groups):
    ent.assert_each_passwd_by_uid({})
    ent.assert_each_passwd_by_uid({1001: USER1})
    ent.assert_each_passwd_by_uid(USER_UID_DICT)
    try:
        ent.assert_each_passwd_by_uid({1003: {}})
        assert False
    except AssertionError as e:
        assert str(e) == "'getpwuid(): uid not found: 1003'"
    try:
        ent.assert_each_passwd_by_uid({1001: dict(uid=1002)})
        assert False
    except AssertionError as e:
        assert str(e) == \
            "user 1001 mismatch: 'uid' mismatch: 1002 != 1001"


def test_assert_each_passwd_with_name(users_and_groups):
    ent.assert_each_passwd_with_name([])
    ent.assert_each_passwd_with_name([USER1])
    ent.assert_each_passwd_with_name(USER_LIST)
    try:
        ent.assert_each_passwd_with_name([dict(name="user3")])
        assert False
    except AssertionError as e:
        assert str(e) in ("'getpwnam(): name not found: user3'",
                          "\"getpwnam(): name not found: 'user3'\"")
    try:
        ent.assert_each_passwd_with_name([dict(name="user1", uid=1002)])
        assert False
    except AssertionError as e:
        assert str(e) == \
            "user 'user1' mismatch: 'uid' mismatch: 1002 != 1001"


def test_assert_each_passwd_with_uid(users_and_groups):
    ent.assert_each_passwd_with_uid([])
    ent.assert_each_passwd_with_uid([USER1])
    ent.assert_each_passwd_with_uid(USER_LIST)
    try:
        ent.assert_each_passwd_with_uid([dict(uid=1003)])
        assert False
    except AssertionError as e:
        assert str(e) == "'getpwuid(): uid not found: 1003'"
    try:
        ent.assert_each_passwd_with_uid([dict(name="user2", uid=1001)])
        assert False
    except AssertionError as e:
        assert str(e) == \
            "user 1001 mismatch: 'name' mismatch: 'user2' != 'user1'"


def test_assert_passwd(users_and_groups):
    ent.assert_passwd(ent.contains())
    ent.assert_passwd(ent.contains(USER1))
    ent.assert_passwd(ent.contains_only(*USER_LIST))
    try:
        ent.assert_passwd(ent.contains(dict(name="user3", uid=1003)))
        assert False
    except AssertionError as e:
        assert re.search("list mismatch:", str(e))
        assert re.search("expected users not found:", str(e))
        assert not re.search("unexpected users found:", str(e))
    try:
        ent.assert_passwd(ent.contains_only(USER1))
        assert False
    except AssertionError as e:
        assert re.search("list mismatch:", str(e))
        assert not re.search("expected users not found:", str(e))
        assert re.search("unexpected users found:", str(e))


def test_group_member_matching(users_and_groups):
    ent.assert_group_by_name("empty_group", dict(mem=ent.contains()))
    ent.assert_group_by_name("empty_group", dict(mem=ent.contains_only()))
    try:
        ent.assert_group_by_name("empty_group",
                                 dict(mem=ent.contains("user1")))
    except AssertionError as e:
        assert re.search("member list mismatch:", str(e))
        assert re.search("expected members not found:", str(e))

    ent.assert_group_by_name("one_user_group1", dict(mem=ent.contains()))
    ent.assert_group_by_name("one_user_group1",
                             dict(mem=ent.contains("user1")))
    ent.assert_group_by_name("one_user_group1",
                             dict(mem=ent.contains_only("user1")))
    try:
        ent.assert_group_by_name("one_user_group1",
                                 dict(mem=ent.contains_only()))
    except AssertionError as e:
        assert re.search("member list mismatch:", str(e))
        assert re.search("unexpected members found:", str(e))
        assert not re.search("expected members not found:", str(e))
    try:
        ent.assert_group_by_name("one_user_group1",
                                 dict(mem=ent.contains_only("user3")))
    except AssertionError as e:
        assert re.search("member list mismatch:", str(e))
        assert re.search("unexpected members found:", str(e))
        assert re.search("expected members not found:", str(e))
    try:
        ent.assert_group_by_name("one_user_group1",
                                 dict(mem=ent.contains("user3")))
    except AssertionError as e:
        assert re.search("member list mismatch:", str(e))
        assert not re.search("unexpected members found:", str(e))
        assert re.search("expected members not found:", str(e))

    ent.assert_group_by_name("two_user_group", dict(mem=ent.contains()))
    ent.assert_group_by_name("two_user_group",
                             dict(mem=ent.contains("user1")))
    ent.assert_group_by_name("two_user_group",
                             dict(mem=ent.contains("user1", "user2")))
    ent.assert_group_by_name("two_user_group",
                             dict(mem=ent.contains_only("user1", "user2")))
    try:
        ent.assert_group_by_name("two_user_group",
                                 dict(mem=ent.contains_only("user1")))
    except AssertionError as e:
        assert re.search("member list mismatch:", str(e))
        assert re.search("unexpected members found:", str(e))
        assert not re.search("expected members not found:", str(e))


def test_assert_group_by_name(users_and_groups):
    ent.assert_group_by_name("group1", {})
    ent.assert_group_by_name("group1", dict(name="group1", gid=2001))
    ent.assert_group_by_name("group1", GROUP1)

    try:
        ent.assert_group_by_name("group3", {})
        assert False
    except AssertionError as e:
        assert str(e) in ("'getgrnam(): name not found: group3'",
                          "\"getgrnam(): name not found: 'group3'\"")

    try:
        ent.assert_group_by_name("group2", dict(name="group1"))
        assert False
    except AssertionError as e:
        assert str(e) == "'name' mismatch: 'group1' != 'group2'"


def test_assert_group_by_gid(users_and_groups):
    ent.assert_group_by_gid(2001, {})
    ent.assert_group_by_gid(2001, dict(name="group1", gid=2001))
    ent.assert_group_by_gid(2001, GROUP1)

    try:
        ent.assert_group_by_gid(2003, {})
        assert False
    except AssertionError as e:
        assert str(e) == "'getgrgid(): gid not found: 2003'"

    try:
        ent.assert_group_by_gid(2002, dict(name="group1"))
        assert False
    except AssertionError as e:
        assert str(e) == "'name' mismatch: 'group1' != 'group2'"


def test_assert_group_list(users_and_groups):
    ent.assert_group_list(ent.contains())
    ent.assert_group_list(ent.contains(GROUP1))
    ent.assert_group_list(ent.contains_only(*GROUP_LIST))
    try:
        ent.assert_group_list(ent.contains_only())
        assert False
    except AssertionError as e:
        assert not re.search("expected groups not found:", str(e))
        assert re.search("unexpected groups found:", str(e))
    try:
        ent.assert_group_list(ent.contains(dict(name="non_existent")))
        assert False
    except AssertionError as e:
        assert re.search("expected groups not found:", str(e))
        assert not re.search("unexpected groups found:", str(e))


def test_assert_each_group_by_name(users_and_groups):
    ent.assert_each_group_by_name({})
    ent.assert_each_group_by_name(dict(group1=GROUP1))
    ent.assert_each_group_by_name(GROUP_NAME_DICT)
    try:
        ent.assert_each_group_by_name(dict(group3={}))
        assert False
    except AssertionError as e:
        assert str(e) in ("'getgrnam(): name not found: group3'",
                          "\"getgrnam(): name not found: 'group3'\"")
    try:
        ent.assert_each_group_by_name(dict(group1=dict(name="group2")))
        assert False
    except AssertionError as e:
        assert str(e) == "group 'group1' mismatch: " + \
                         "'name' mismatch: 'group2' != 'group1'"


def test_assert_each_group_by_gid(users_and_groups):
    ent.assert_each_group_by_gid({})
    ent.assert_each_group_by_gid({2001: GROUP1})
    ent.assert_each_group_by_gid(GROUP_GID_DICT)
    try:
        ent.assert_each_group_by_gid({2003: {}})
        assert False
    except AssertionError as e:
        assert str(e) == "'getgrgid(): gid not found: 2003'"
    try:
        ent.assert_each_group_by_gid({2001: dict(gid=2002)})
        assert False
    except AssertionError as e:
        assert str(e) == \
            "group 2001 mismatch: 'gid' mismatch: 2002 != 2001"


def test_assert_each_group_with_name(users_and_groups):
    ent.assert_each_group_with_name([])
    ent.assert_each_group_with_name([GROUP1])
    ent.assert_each_group_with_name(GROUP_LIST)
    try:
        ent.assert_each_group_with_name([dict(name="group3")])
        assert False
    except AssertionError as e:
        assert str(e) in ("'getgrnam(): name not found: group3'",
                          "\"getgrnam(): name not found: 'group3'\"")
    try:
        ent.assert_each_group_with_name([dict(name="group1", gid=2002)])
        assert False
    except AssertionError as e:
        assert str(e) == \
            "group 'group1' mismatch: 'gid' mismatch: 2002 != 2001"


def test_assert_each_group_with_gid(users_and_groups):
    ent.assert_each_group_with_gid([])
    ent.assert_each_group_with_gid([GROUP1])
    ent.assert_each_group_with_gid(GROUP_LIST)
    try:
        ent.assert_each_group_with_gid([dict(gid=2003)])
        assert False
    except AssertionError as e:
        assert str(e) == "'getgrgid(): gid not found: 2003'"
    try:
        ent.assert_each_group_with_gid([dict(name="group2", gid=2001)])
        assert False
    except AssertionError as e:
        assert str(e) == \
            "group 2001 mismatch: 'name' mismatch: 'group2' != 'group1'"


def test_assert_group(users_and_groups):
    ent.assert_group(ent.contains())
    ent.assert_group(ent.contains(GROUP1))
    ent.assert_group(ent.contains_only(*GROUP_LIST))
    try:
        ent.assert_group(ent.contains(dict(name="group3", gid=2003)))
        assert False
    except AssertionError as e:
        assert re.search("list mismatch:", str(e))
        assert re.search("expected groups not found:", str(e))
        assert not re.search("unexpected groups found:", str(e))
    try:
        ent.assert_group(ent.contains_only(GROUP1))
        assert False
    except AssertionError as e:
        assert re.search("list mismatch:", str(e))
        assert not re.search("expected groups not found:", str(e))
        assert re.search("unexpected groups found:", str(e))
