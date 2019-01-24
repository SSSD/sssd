#
# SSSD files domain tests
#
# Copyright (c) 2019 Red Hat, Inc.
# Author: Lukas Slebodnik <lslebodn@redhat.com>
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

import subprocess


def test_missing_domains():
    # Utilities in shadow-utils call sss_cache but it might fail in case
    # sssd has never been started on such host.
    ret = subprocess.call(["sss_cache", "-U"])
    assert ret == 0

    ret = subprocess.call(["sss_cache", "-G"])
    assert ret == 0

    ret = subprocess.call(["sss_cache", "-E"])
    assert ret == 0
