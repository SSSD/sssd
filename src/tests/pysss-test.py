#!/usr/bin/env python
#  SSSD
#
#  SSSD python SSS API tests
#
#  Copyright (C) Red Hat
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function

import unittest
import sys
import os
import tempfile

BUILD_DIR = os.getenv('builddir') or "."
TEST_DIR = os.path.realpath(os.getenv('SSS_TEST_DIR') or ".")
MODPATH = tempfile.mkdtemp(prefix="tp_pysss_", dir=TEST_DIR)


class PysssImport(unittest.TestCase):
    def setUp(self):
        " Make sure we load the in-tree module "
        self.system_path = sys.path[:]
        sys.path = [MODPATH]

    def tearDown(self):
        " Restore the system path "
        sys.path = self.system_path

    def test_import(self):
        " Import the module and assert it comes from tree "
        try:
            dest_module_path = MODPATH + "/pysss.so"

            if sys.version_info[0] > 2:
                src_module_path = BUILD_DIR + "/.libs/_py3sss.so"
            else:
                src_module_path = BUILD_DIR + "/.libs/_py2sss.so"

            src_module_path = os.path.abspath(src_module_path)
            os.symlink(src_module_path, dest_module_path)

            import pysss
        except ImportError as ex:
            print("Could not load the pysss module. Please check if it is "
                  "compiled", file=sys.stderr)
            raise ex
        self.assertEqual(os.path.realpath(pysss.__file__),
                         os.path.realpath(MODPATH + "/pysss.so"))


class PysssEncryptTest(unittest.TestCase):
    def test_encrypt(self):
        obfuscator = pysss.password()

        val1 = obfuscator.encrypt("123", obfuscator.AES_256)
        self.assertEqual(len(val1), 96)

        val2 = obfuscator.encrypt("123", obfuscator.AES_256)
        self.assertEqual(len(val2), 96)

        self.assertNotEqual(val1, val2)


if __name__ == "__main__":
    error = 0

    suite = unittest.TestLoader().loadTestsFromTestCase(PysssImport)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x1
        # need to bail out here because pysss could not be imported
        sys.exit(error)

    # import the pysss module into the global namespace, but make sure it's
    # the one in tree
    sys.path.insert(0, MODPATH)
    import pysss

    loadTestsFromTestCase = unittest.TestLoader().loadTestsFromTestCase

    suite = loadTestsFromTestCase(PysssEncryptTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x2

    sys.exit(error)
