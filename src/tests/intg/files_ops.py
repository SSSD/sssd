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

import os
import os.path
import tempfile
import pytest

import ent
from util import backup_envvar_file, restore_envvar_file


@pytest.fixture
def passwd_ops_setup(request):
    pwd_file = os.environ["NSS_WRAPPER_PASSWD"]
    backup_envvar_file("NSS_WRAPPER_PASSWD")
    request.addfinalizer(lambda: restore_envvar_file("NSS_WRAPPER_PASSWD"))
    pwd_ops = PasswdOps(pwd_file)
    return pwd_ops


@pytest.fixture
def group_ops_setup(request):
    grp_file = os.environ["NSS_WRAPPER_GROUP"]
    backup_envvar_file("NSS_WRAPPER_GROUP")
    request.addfinalizer(lambda: restore_envvar_file("NSS_WRAPPER_GROUP"))
    grp_ops = GroupOps(grp_file)
    return grp_ops


@pytest.fixture
def group_db_setup(request):
    group = request.param
    grp_ops = group_ops_setup(request)
    grp_ops.groupadd(**group)
    ent.assert_group_by_name(group['name'], group)
    return grp_ops


class FilesOps(object):
    """
    A naive implementation of operations as a basis for user or group
    operations. Uses rename to (hopefully) trigger the same fs-level
    notifications as shadow-utils would.
    """
    def __init__(self, file_name):
        self.file_name = file_name
        self.tmp_dir = os.path.dirname(self.file_name)

    @staticmethod
    def _get_named_line(name, contents):
        for num, line in enumerate(contents, 0):
            pname = line.split(':')[0]
            if name == pname:
                return num
        raise KeyError("%s not found" % name)

    def _read_contents(self):
        with open(self.file_name, "r") as pfile:
            contents = pfile.readlines()
        return contents

    def _write_contents(self, contents):
        tmp_file = tempfile.NamedTemporaryFile(mode='w', dir=self.tmp_dir,
                                               delete=False)
        tmp_file.writelines(contents)
        tmp_file.flush()

        os.rename(tmp_file.name, self.file_name)

    def _append_line(self, new_line):
        contents = self._read_contents()
        contents.extend(new_line)
        self._write_contents(contents)

    def _subst_line(self, key, line):
        contents = self._read_contents()
        kindex = self._get_named_line(key, contents)
        contents[kindex] = line
        self._write_contents(contents)

    def _del_line(self, key):
        contents = self._read_contents()
        kindex = self._get_named_line(key, contents)
        contents.pop(kindex)
        self._write_contents(contents)

        contents = self._read_contents()

    def _has_line(self, key):
        try:
            self._get_named_line(key, self._read_contents())
            return True
        except KeyError:
            return False


class PasswdOps(FilesOps):
    """
    A naive implementation of user operations
    """
    def __init__(self, file_name):
        super(PasswdOps, self).__init__(file_name)

    def _pwd2line(self, name, uid, gid, passwd, gecos, homedir, shell):
        pwd_fmt = "{name}:{passwd}:{uid}:{gid}:{gecos}:{homedir}:{shell}\n"
        return pwd_fmt.format(name=name,
                              passwd=passwd,
                              uid=uid,
                              gid=gid,
                              gecos=gecos,
                              homedir=homedir,
                              shell=shell)

    def useradd(self, name, uid, gid, passwd='', gecos='', dir='', shell=''):
        pwd_line = self._pwd2line(name, uid, gid, passwd, gecos, dir, shell)
        self._append_line(pwd_line)

    def usermod(self, name, uid, gid, passwd='', gecos='', dir='', shell=''):
        pwd_line = self._pwd2line(name, uid, gid, passwd, gecos, dir, shell)
        self._subst_line(name, pwd_line)

    def userdel(self, name):
        self._del_line(name)

    def userexist(self, name):
        return self._has_line(name)


class GroupOps(FilesOps):
    """
    A naive implementation of group operations
    """
    def __init__(self, file_name):
        super(GroupOps, self).__init__(file_name)

    def _grp2line(self, name, gid, mem, passwd):
        member_list = ",".join(m for m in mem)
        grp_fmt = "{name}:{passwd}:{gid}:{member_list}\n"
        return grp_fmt.format(name=name,
                              passwd=passwd,
                              gid=gid,
                              member_list=member_list)

    def groupadd(self, name, gid, mem, passwd="*"):
        grp_line = self._grp2line(name, gid, mem, passwd)
        self._append_line(grp_line)

    def groupmod(self, old_name, name, gid, mem, passwd="*"):
        grp_line = self._grp2line(name, gid, mem, passwd)
        self._subst_line(old_name, grp_line)

    def groupdel(self, name):
        self._del_line(name)

    def groupexist(self, name):
        return self._has_line(name)
