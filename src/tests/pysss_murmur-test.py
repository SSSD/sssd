#!/usr/bin/env python
#  SSSD
#
#  Unit tests for pysss_murmur
#
#  Copyright (C) Sumit Bose <sbose@redhat.com>        2012
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
MODPATH = tempfile.mkdtemp(prefix="tp_pysss_murmur_", dir=TEST_DIR)


class PySssMurmurImport(unittest.TestCase):
    def setUp(self):
        " Make sure we load the in-tree module "
        self.system_path = sys.path[:]
        sys.path = [MODPATH]
        print(os.getcwd())
        print(MODPATH)

    def tearDown(self):
        " Restore the system path "
        sys.path = self.system_path

    def testImport(self):
        " Import the module and assert it comes from tree "
        try:
            dest_module_path = MODPATH + "/pysss_murmur.so"

            if sys.version_info[0] > 2:
                src_module_path = BUILD_DIR + "/.libs/_py3sss_murmur.so"
            else:
                src_module_path = BUILD_DIR + "/.libs/_py2sss_murmur.so"

            src_module_path = os.path.abspath(src_module_path)
            os.symlink(src_module_path, dest_module_path)

            import pysss_murmur
        except ImportError as e:
            print("Could not load the pysss_murmur module. "
                  "Please check if it is compiled", file=sys.stderr)
            raise e
        self.assertEqual(os.path.realpath(pysss_murmur.__file__),
                         os.path.realpath(MODPATH + "/pysss_murmur.so"))


class PySssMurmurTestNeg(unittest.TestCase):
    def test_invalid_arguments(self):
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, 1, 2, 3)
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test", 2)
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test")
        self.assertRaises(ValueError, pysss_murmur.murmurhash3)

    def test_invalid_length(self):
        seed = 12345

        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "t", -1, seed)
        # length is off by one
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test", 5,
                          seed)
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test",
                          0xffffffffff, seed)


class PySssMurmurTestPos(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        os.unlink(MODPATH + "/pysss_murmur.so")
        os.rmdir(MODPATH)

    def testExpectedHash(self):
        sid_str = "S-1-5-21-2153326666-2176343378-3404031434"
        seed = 0xdeadbeef

        hash_val = pysss_murmur.murmurhash3(sid_str, 0, seed)
        self.assertEqual(hash_val, 233162409)

        hash_val = pysss_murmur.murmurhash3(sid_str, len(sid_str), seed)
        self.assertEqual(hash_val, 93103853)

    def test_memory_cache_usage(self):
        seed = 0xbeefdead
        input_str = "test_user1"
        input_len = len(input_str)

        val_bin = pysss_murmur.murmurhash3(input_str + '\0',
                                           input_len + 1, seed)
        self.assertEqual(val_bin, 1198610880)

        val_bin = pysss_murmur.murmurhash3(input_str + '\0' * 5,
                                           input_len + 5, seed)
        self.assertEqual(val_bin, 2917868047)


if __name__ == "__main__":
    error = 0

    suite = unittest.TestLoader().loadTestsFromTestCase(PySssMurmurImport)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x1
        # need to bail out here because pysss_murmur could not be imported
        sys.exit(error)

    # import the pysss_murmur module into the global namespace, but make sure
    # it's the one in tree
    sys.path.insert(0, MODPATH)
    import pysss_murmur

    suite = unittest.TestLoader().loadTestsFromTestCase(PySssMurmurTestNeg)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x2

    suite = unittest.TestLoader().loadTestsFromTestCase(PySssMurmurTestPos)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x4

    sys.exit(error)
