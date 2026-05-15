#!/usr/bin/env python
# coding=utf-8

# Authors:
#   Jakub Hrozek <jhrozek@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
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

import os
import tempfile
import shutil
import unittest
import subprocess
import errno

# module under test
import pysss


class LocalTest(unittest.TestCase):
    local_path = "/var/lib/sss/db/sssd.ldb"

    def setUp(self):
        self.local = pysss.local()

    def _run_and_check(self, runme):
        (status, output) = subprocess.call(runme, shell=True)
        self.failUnlessEqual(status, 0, output)

    def _get_object_info(self, name, subtree, domain):
        search_dn = "dn=name=%s,cn=%s,cn=%s,cn=sysdb" % (name, subtree, domain)
        try:
            cmd = "ldbsearch -H %s %s" % (self.local_path, search_dn)
            output = subprocess.check_call(cmd, shell=True)
            output = output.decode('utf-8')
        except subprocess.CalledProcessError:
            return {}

        kw = {}
        for key, value in \
                [ln.split(':') for ln in output.split('\n') if ":" in ln]:
            kw[key] = value.strip()

        del kw['asq']
        return kw

    def get_user_info(self, name, domain="LOCAL"):
        return self._get_object_info(name, "users", domain)

    def get_group_info(self, name, domain="LOCAL"):
        return self._get_object_info(name, "groups", domain)

    def _validate_object(self, kw, name, **kwargs):
        if kw == {}:
            self.fail("Could not get %s info" % name)
        for key in kwargs.keys():
            self.assert_(str(kwargs[key]) == str(kw[key]),
                         "%s %s != %s %s" % (key, kwargs[key], key, kw[key]))

    def validate_user(self, username, **kwargs):
        return self._validate_object(self.get_user_info(username), "user",
                                     **kwargs)

    def validate_group(self, groupname, **kwargs):
        return self._validate_object(self.get_group_info(groupname), "group",
                                     **kwargs)

    def _validate_no_object(self, kw, name):
        if kw != {}:
            self.fail("Got %s info" % name)

    def validate_no_user(self, username):
        return self._validate_no_object(self.get_user_info(username), "user")

    def validate_no_group(self, groupname):
        return self._validate_no_object(self.get_group_info(groupname),
                                        "group")

    def _get_object_membership(self, name, subtree, domain):
        search_dn = "dn=name=%s,cn=%s,cn=%s,cn=sysdb" % (name, subtree, domain)
        try:
            cmd = "ldbsearch -H %s %s" % (self.local_path, search_dn)
            output = subprocess.check_call(cmd, shell=True)
            output = output.decode('utf-8')
        except subprocess.CalledProcessError:
            return []

        members = [value.strip() for key, value in
                   [ln.split(':') for ln in output.split('\n') if ":" in ln]
                   if key == "memberof"]
        return members

    def _assertMembership(self, name, group_list, subtree, domain):
        members = self._get_object_membership(name, subtree, domain)
        for group in group_list:
            group_dn = "name=%s,cn=groups,cn=%s,cn=sysdb" % (group, domain)
            if group_dn in members:
                members.remove(group_dn)
            else:
                self.fail("Cannot find required group %s" % group_dn)

        if len(members) > 0:
            self.fail("More groups than selected")

    def assertUserMembership(self, name, group_list, domain="LOCAL"):
        return self._assertMembership(name, group_list, "users", domain)

    def assertGroupMembership(self, name, group_list, domain="LOCAL"):
        return self._assertMembership(name, group_list, "groups", domain)

    def get_user_membership(self, name, domain="LOCAL"):
        return self._get_object_membership(name, "users", domain)

    def get_group_membership(self, name, domain="LOCAL"):
        return self._get_object_membership(name, "groups", domain)

    def add_group(self, groupname):
        self._run_and_check("sss_groupadd %s" % (groupname))

    def remove_group(self, groupname):
        self._run_and_check("sss_groupdel %s" % (groupname))

    def add_user(self, username):
        self._run_and_check("sss_useradd %s" % (username))

    def add_user_not_home(self, username):
        self._run_and_check("sss_useradd -M %s" % (username))

    def remove_user(self, username):
        self._run_and_check("sss_userdel %s" % (username))

    def remove_user_not_home(self, username):
        self._run_and_check("sss_userdel -R %s" % (username))


class SanityTest(unittest.TestCase):
    def testInstantiate(self):
        "Test that the local backed binding can be instantiated"
        local = pysss.local()
        self.assert_(local.__class__, "<type 'sss.local'>")


class UseraddTest(LocalTest):
    def tearDown(self):
        if self.username:
            self.remove_user(self.username)

    def testUseradd(self):
        "Test adding a local user"
        self.username = "testUseradd"
        self.local.useradd(self.username)
        self.validate_user(self.username)
        # check home directory was created with default name
        self.assertEquals(os.access("/home/%s" % self.username, os.F_OK), True)

    def testUseraddWithParams(self):
        "Test adding a local user with modified parameters"
        self.username = "testUseraddWithParams"
        self.local.useradd(self.username,
                           gecos="foo bar",
                           homedir="/home/foobar",
                           shell="/bin/zsh")
        self.validate_user(self.username,
                           gecos="foo bar",
                           homeDirectory="/home/foobar",
                           loginShell="/bin/zsh")
        # check home directory was created with nondefault name
        self.assertEquals(os.access("/home/foobar", os.F_OK), True)

    def testUseraddNoHomedir(self):
        "Test adding a local user without creating his home dir"
        self.username = "testUseraddNoHomedir"
        self.local.useradd(self.username, create_home=False)
        self.validate_user(self.username)
        # check home directory was not created
        username_path = "/home/%s" % self.username
        self.assertEquals(os.access(username_path, os.F_OK), False)
        self.local.userdel(self.username, remove=False)
        self.username = None  # fool tearDown into not removing the user

    def testUseraddAlternateSkeldir(self):
        "Test adding a local user and init his homedir from a custom location"
        self.username = "testUseraddAlternateSkeldir"

        skeldir = tempfile.mkdtemp()
        fd, path = tempfile.mkstemp(dir=skeldir)
        fdo = os.fdopen(fd)
        fdo.flush()
        fdo.close
        self.assertEquals(os.access(path, os.F_OK), True)
        filename = os.path.basename(path)

        try:
            self.local.useradd(self.username, skel=skeldir)
            self.validate_user(self.username)
            path = "/home/%s/%s" % (self.username, filename)
            self.assertEquals(os.access(path, os.F_OK), True)
        finally:
            shutil.rmtree(skeldir)

    def testUseraddToGroups(self):
        "Test adding a local user with group membership"
        self.username = "testUseraddToGroups"
        self.add_group("gr1")
        self.add_group("gr2")
        try:
            self.local.useradd(self.username,
                               groups=["gr1", "gr2"])
            self.assertUserMembership(self.username,
                                      ["gr1", "gr2"])
        finally:
            self.remove_group("gr1")
            self.remove_group("gr2")

    def testUseraddWithUID(self):
        "Test adding a local user with a custom UID"
        self.username = "testUseraddWithUID"
        self.local.useradd(self.username,
                           uid=1024)
        self.validate_user(self.username,
                           uidNumber=1024)


class UseraddTestNegative(LocalTest):
    def testUseraddNoParams(self):
        "Test that local.useradd() requires the username parameter"
        self.assertRaises(TypeError, self.local.useradd)

    def testUseraddUserAlreadyExists(self):
        "Test adding a local with a duplicate name"
        self.username = "testUseraddUserAlreadyExists"
        self.local.useradd(self.username)
        try:
            self.local.useradd(self.username)
        except IOError as e:
            self.assertEquals(e.errno, errno.EEXIST)
        else:
            self.fail("Was expecting exception")
        finally:
            self.remove_user(self.username)

    def testUseraddUIDAlreadyExists(self):
        "Test adding a local with a duplicate user ID"
        self.username = "testUseraddUIDAlreadyExists1"
        self.local.useradd(self.username, uid=1025)
        try:
            self.local.useradd("testUseraddUIDAlreadyExists2", uid=1025)
        except IOError as e:
            self.assertEquals(e.errno, errno.EEXIST)
        else:
            self.fail("Was expecting exception")
        finally:
            self.remove_user(self.username)


class UserdelTest(LocalTest):
    def testUserdel(self):
        self.add_user("testUserdel")
        self.assertEquals(os.access("/home/testUserdel", os.F_OK), True)
        self.validate_user("testUserdel")
        self.local.userdel("testUserdel")
        self.validate_no_user("testUserdel")
        self.assertEquals(os.access("/home/testUserdel", os.F_OK), False)

    def testUserdelNotHomedir(self):
        self.add_user("testUserdel")
        self.assertEquals(os.access("/home/testUserdel", os.F_OK), True)
        self.validate_user("testUserdel")
        self.local.userdel("testUserdel", remove=False)
        self.validate_no_user("testUserdel")
        self.assertEquals(os.access("/home/testUserdel", os.F_OK), True)
        shutil.rmtree("/home/testUserdel")
        os.remove("/var/mail/testUserdel")

    def testUserdelNegative(self):
        self.validate_no_user("testUserdelNegative")
        try:
            self.local.userdel("testUserdelNegative")
        except IOError as e:
            self.assertEquals(e.errno, errno.ENOENT)
        else:
            self.fail("Was expecting exception")


class UsermodTest(LocalTest):
    def setUp(self):
        self.local = pysss.local()
        self.username = "UsermodTest"
        self.add_user_not_home(self.username)

    def tearDown(self):
        self.remove_user_not_home(self.username)

    def testUsermod(self):
        "Test modifying user attributes"
        self.local.usermod(self.username,
                           gecos="foo bar",
                           homedir="/home/foobar",
                           shell="/bin/zsh")
        self.validate_user(self.username,
                           gecos="foo bar",
                           homeDirectory="/home/foobar",
                           loginShell="/bin/zsh")

    def testUsermodUID(self):
        "Test modifying UID"
        self.local.usermod(self.username,
                           uid=1024)
        self.validate_user(self.username,
                           uidNumber=1024)

    def testUsermodGroupMembership(self):
        "Test adding to and removing from groups"
        self.add_group("gr1")
        self.add_group("gr2")

        try:
            self.local.usermod(self.username,
                               addgroups=["gr1", "gr2"])
            self.assertUserMembership(self.username,
                                      ["gr1", "gr2"])
            self.local.usermod(self.username,
                               rmgroups=["gr2"])
            self.assertUserMembership(self.username,
                                      ["gr1"])
            self.local.usermod(self.username,
                               rmgroups=["gr1"])
            self.assertUserMembership(self.username,
                                      [])
        finally:
            self.remove_group("gr1")
            self.remove_group("gr2")

    def testUsermodLockUnlock(self):
        "Test locking and unlocking user"
        self.local.usermod(self.username,
                           lock=self.local.lock)
        self.validate_user(self.username,
                           disabled="true")
        self.local.usermod(self.username,
                           lock=self.local.unlock)
        self.validate_user(self.username,
                           disabled="false")


class GroupaddTest(LocalTest):
    def tearDown(self):
        if self.groupname:
            self.remove_group(self.groupname)

    def testGroupadd(self):
        "Test adding a local group"
        self.groupname = "testGroupadd"
        self.local.groupadd(self.groupname)
        self.validate_group(self.groupname)

    def testGroupaddWithGID(self):
        "Test adding a local group with a custom GID"
        self.groupname = "testUseraddWithGID"
        self.local.groupadd(self.groupname,
                            gid=1024)
        self.validate_group(self.groupname,
                            gidNumber=1024)


class GroupaddTestNegative(LocalTest):
    def testGroupaddNoParams(self):
        "Test that local.groupadd() requires the groupname parameter"
        self.assertRaises(TypeError, self.local.groupadd)

    def testGroupaddUserAlreadyExists(self):
        "Test adding a local with a duplicate name"
        self.groupname = "testGroupaddUserAlreadyExists"
        self.local.groupadd(self.groupname)
        try:
            self.local.groupadd(self.groupname)
        except IOError as e:
            self.assertEquals(e.errno, errno.EEXIST)
        else:
            self.fail("Was expecting exception")
        finally:
            self.remove_group(self.groupname)

    def testGroupaddGIDAlreadyExists(self):
        "Test adding a local with a duplicate group ID"
        self.groupname = "testGroupaddGIDAlreadyExists1"
        self.local.groupadd(self.groupname, gid=1025)
        try:
            self.local.groupadd("testGroupaddGIDAlreadyExists2", gid=1025)
        except IOError as e:
            self.assertEquals(e.errno, errno.EEXIST)
        else:
            self.fail("Was expecting exception")
        finally:
            self.remove_group(self.groupname)


class GroupdelTest(LocalTest):
    def testGroupdel(self):
        self.add_group("testGroupdel")
        self.validate_group("testGroupdel")
        self.local.groupdel("testGroupdel")
        self.validate_no_group("testGroupdel")

    def testGroupdelNegative(self):
        self.validate_no_group("testGroupdelNegative")
        try:
            self.local.groupdel("testGroupdelNegative")
        except IOError as e:
            self.assertEquals(e.errno, errno.ENOENT)
        else:
            self.fail("Was expecting exception")


class GroupmodTest(LocalTest):
    def setUp(self):
        self.local = pysss.local()
        self.groupname = "GroupmodTest"
        self.add_group(self.groupname)

    def tearDown(self):
        self.remove_group(self.groupname)

    def testGroupmodGID(self):
        "Test modifying UID"
        self.local.groupmod(self.groupname,
                            gid=1024)
        self.validate_group(self.groupname,
                            gidNumber=1024)

    def testGroupmodGroupMembership(self):
        "Test adding to groups"
        self.add_group("gr1")
        self.add_group("gr2")
        try:
            self.local.groupmod(self.groupname,
                                addgroups=["gr1", "gr2"])
            self.assertGroupMembership(self.groupname,
                                       ["gr1", "gr2"])
            self.local.groupmod(self.groupname,
                                rmgroups=["gr2"])
            self.assertGroupMembership(self.groupname,
                                       ["gr1"])
            self.local.groupmod(self.groupname,
                                rmgroups=["gr1"])
            self.assertGroupMembership(self.groupname,
                                       [])
        finally:
            self.remove_group("gr1")
            self.remove_group("gr2")


# -------------- run the test suite -------------- #
if __name__ == "__main__":
    unittest.main()
