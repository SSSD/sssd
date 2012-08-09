#!/usr/bin/python
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

import unittest
import sys
import os
import copy

srcdir = os.getenv('builddir')
if not srcdir:
    srcdir = "."
MODPATH = srcdir + "/.libs" #FIXME - is there a way to get this from libtool?

def compat_assertItemsEqual(this, expected_seq, actual_seq, msg=None):
    return this.assertEqual(sorted(expected_seq), sorted(actual_seq))

def compat_assertIsInstance(this, obj, cls, msg=None):
    return this.assertTrue(isinstance(obj, cls))

# add compat methods for old unittest.TestCase versions
# (python < 2.7, RHEL5 for instance)
if not hasattr(unittest.TestCase, "assertItemsEqual"):
    setattr(unittest.TestCase, "assertItemsEqual", compat_assertItemsEqual)
if not hasattr(unittest.TestCase, "assertIsInstance"):
    setattr(unittest.TestCase, "assertIsInstance", compat_assertIsInstance)

class PySssMurmurImport(unittest.TestCase):
    def setUp(self):
        " Make sure we load the in-tree module "
        self.system_path = sys.path[:]
        sys.path = [ MODPATH ]

    def tearDown(self):
        " Restore the system path "
        sys.path = self.system_path

    def testImport(self):
        " Import the module and assert it comes from tree "
        try:
            import pysss_murmur
        except ImportError, e:
            print >>sys.stderr, "Could not load the pysss_murmur module. Please check if it is compiled"
            raise e
        self.assertEqual(pysss_murmur.__file__, MODPATH + "/pysss_murmur.so")

class PySssMurmurTest(unittest.TestCase):
    def testExpectedHash(self):
        hash = pysss_murmur.murmurhash3("S-1-5-21-2153326666-2176343378-3404031434", 41, 0xdeadbeef)
        self.assertEqual(hash, 93103853)

    def testInvalidArguments(self):
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, 1, 2, 3)
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test", 2)
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test")
        self.assertRaises(ValueError, pysss_murmur.murmurhash3)
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test", -1, 3)
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test", 2,
                          0xffffffffff)
        self.assertRaises(ValueError, pysss_murmur.murmurhash3, "test",
                          0xffffffffff, 3)


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

    suite = unittest.TestLoader().loadTestsFromTestCase(PySssMurmurTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x2

    sys.exit(error)
