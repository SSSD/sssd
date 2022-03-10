#!/usr/bin/env python
#  SSSD
#
#  SSSD HBAC python API tests
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
import copy
import tempfile

BUILD_DIR = os.getenv('builddir') or "."
TEST_DIR = os.path.realpath(os.getenv('SSS_TEST_DIR') or ".")
MODPATH = tempfile.mkdtemp(prefix="tp_pyhbac_", dir=TEST_DIR)


if sys.version_info[0] > 2:
    unicode = str


def compat_assertIsInstance(this, obj, cls, msg=None):
    return this.assertTrue(isinstance(obj, cls))


def compat_assertItemsEqual(this, expected_seq, actual_seq, msg=None):
    return this.assertEqual(sorted(expected_seq), sorted(actual_seq))


# add compat assertIsInstance for old unittest.TestCase versions
# (python < 2.7, RHEL6 for instance)
if not hasattr(unittest.TestCase, "assertIsInstance"):
    setattr(unittest.TestCase, "assertIsInstance", compat_assertIsInstance)

# Python3 renamed assertItemsEqual to assertCountEqual but at the same time
# Python2 doesn't have assertCountEqual, see http://bugs.python.org/issue17866
if not hasattr(unittest.TestCase, "assertCountEqual"):
    if not hasattr(unittest.TestCase, "assertItemsEqual"):
        # This is RHEL-6
        setattr(unittest.TestCase, "assertItemsEqual", compat_assertItemsEqual)

    setattr(unittest.TestCase,
            "assertCountEqual",
            unittest.TestCase.assertItemsEqual)


class PyHbacImport(unittest.TestCase):
    def setUp(self):
        " Make sure we load the in-tree module "
        self.system_path = sys.path[:]
        sys.path = [MODPATH]

    def tearDown(self):
        " Restore the system path "
        sys.path = self.system_path

    def testImport(self):
        " Import the module and assert it comes from tree "
        try:
            dest_module_path = MODPATH + "/pyhbac.so"

            if sys.version_info[0] > 2:
                src_module_path = BUILD_DIR + "/.libs/_py3hbac.so"
            else:
                src_module_path = BUILD_DIR + "/.libs/_py2hbac.so"

            src_module_path = os.path.abspath(src_module_path)
            os.symlink(src_module_path, dest_module_path)

            import pyhbac
        except ImportError as e:
            print("Could not load the pyhbac module. Please check if it is "
                  "compiled", file=sys.stderr)
            raise e
        self.assertEqual(os.path.realpath(pyhbac.__file__),
                         os.path.realpath(MODPATH + "/pyhbac.so"))


class PyHbacRuleElementTest(unittest.TestCase):
    def testInstantiateEmpty(self):
        el = pyhbac.HbacRuleElement()
        self.assertCountEqual(el.names, [])
        self.assertCountEqual(el.groups, [])
        self.assertCountEqual(el.category, set([pyhbac.HBAC_CATEGORY_NULL]))

    def testInit(self):
        names = ["foo", "bar"]
        el = pyhbac.HbacRuleElement(names=names)
        self.assertCountEqual(el.names, names)

        groups = ["abc", "def"]
        el = pyhbac.HbacRuleElement(groups=groups)
        self.assertCountEqual(el.groups, groups)

    def testGetSet(self):
        names = ["foo", "bar"]
        el = pyhbac.HbacRuleElement()
        self.assertCountEqual(el.names, [])
        el.names = names
        self.assertCountEqual(el.names, names)

        groups = ["abc", "def"]
        el = pyhbac.HbacRuleElement()
        self.assertCountEqual(el.groups, [])
        el.groups = groups
        self.assertCountEqual(el.groups, groups)

        # Test other iterables than list
        groups = ("abc", "def")
        el = pyhbac.HbacRuleElement()
        self.assertCountEqual(el.groups, [])
        el.groups = groups
        self.assertCountEqual(el.groups, groups)

    def testCategory(self):
        el = pyhbac.HbacRuleElement()
        assert pyhbac.HBAC_CATEGORY_NULL in el.category
        assert pyhbac.HBAC_CATEGORY_ALL not in el.category

        el.category.add(pyhbac.HBAC_CATEGORY_ALL)
        assert pyhbac.HBAC_CATEGORY_ALL in el.category

        el.category = set([pyhbac.HBAC_CATEGORY_ALL])
        assert pyhbac.HBAC_CATEGORY_ALL in el.category

        # negative tests
        self.assertRaises(TypeError, el.__setattr__, "category",
                          [pyhbac.HBAC_CATEGORY_ALL])
        self.assertRaises(TypeError, el.__setattr__, "category", None)
        self.assertRaises(TypeError, el.__setattr__, "category", 1)

    def testNotIterable(self):
        self.assertRaises(TypeError, pyhbac.HbacRuleElement, names=123)
        self.assertRaises(TypeError, pyhbac.HbacRuleElement, names=None)

    def testRuleElementReference(self):
        def _get_rule():
            users = ["foo", "bar"]
            user_groups = ["abc", "def"]
            return pyhbac.HbacRuleElement(names=users, groups=user_groups)

        el = _get_rule()
        self.assertCountEqual(el.names, ["foo", "bar"])
        self.assertCountEqual(el.groups, ["abc", "def"])

    def testRepr(self):
        el = pyhbac.HbacRuleElement()
        self.assertEqual(el.__repr__(), u'<category 0 names [] groups []>')

        el.category.add(pyhbac.HBAC_CATEGORY_ALL)
        el.names = ['foo']
        el.groups = ['bar, baz']
        self.assertEqual(el.__repr__(),
                         u'<category 1 names [foo] groups [bar, baz]>')


class PyHbacRuleTest(unittest.TestCase):
    def testRuleGetSetName(self):
        name = "testGetRule"
        new_name = "testGetNewRule"

        rule = pyhbac.HbacRule(name)
        self.assertEqual(rule.name, unicode(name))

        rule.name = new_name
        self.assertEqual(rule.name, unicode(new_name))

    def testRuleGetSetEnabled(self):
        rule = pyhbac.HbacRule("testRuleGetSetEnabled")

        rule.enabled = True
        self.assertEqual(rule.enabled, True)
        rule.enabled = False
        self.assertEqual(rule.enabled, False)

        rule.enabled = "TRUE"
        self.assertEqual(rule.enabled, True)
        rule.enabled = "FALSE"
        self.assertEqual(rule.enabled, False)

        rule.enabled = "true"
        self.assertEqual(rule.enabled, True)
        rule.enabled = "false"
        self.assertEqual(rule.enabled, False)

        rule.enabled = "True"
        self.assertEqual(rule.enabled, True)
        rule.enabled = "False"
        self.assertEqual(rule.enabled, False)

        rule.enabled = 1
        self.assertEqual(rule.enabled, True)
        rule.enabled = 0
        self.assertEqual(rule.enabled, False)

        # negative test
        self.assertRaises(TypeError, rule.__setattr__, "enabled", None)
        self.assertRaises(TypeError, rule.__setattr__, "enabled", [])
        self.assertRaises(ValueError, rule.__setattr__, "enabled", "foo")
        self.assertRaises(ValueError, rule.__setattr__, "enabled", 5)

    def testRuleElementInRule(self):
        users = ["foo", "bar"]
        user_groups = ["abc", "def"]

        # rule should contain empty elements after instantiation
        rule = pyhbac.HbacRule("testRuleElement")
        self.assertIsInstance(rule.users, pyhbac.HbacRuleElement)
        self.assertIsInstance(rule.services, pyhbac.HbacRuleElement)
        self.assertIsInstance(rule.targethosts, pyhbac.HbacRuleElement)
        self.assertIsInstance(rule.srchosts, pyhbac.HbacRuleElement)

        self.assertIsInstance(rule.users.names, list)
        self.assertIsInstance(rule.users.groups, list)
        self.assertCountEqual(rule.users.names, [])
        self.assertCountEqual(rule.users.groups, [])

        # Assign by copying a HbacRuleElement
        user_el = pyhbac.HbacRuleElement(names=users, groups=user_groups)
        rule = pyhbac.HbacRule("testRuleElement")
        rule.users = user_el
        self.assertCountEqual(rule.users.names, users)
        self.assertCountEqual(rule.users.groups, user_groups)

        # Assign directly
        rule = pyhbac.HbacRule("testRuleElement")
        rule.users.names = users
        rule.users.groups = user_groups
        self.assertCountEqual(rule.users.names, users)
        self.assertCountEqual(rule.users.groups, user_groups)

    def testRuleElementInRuleReference(self):
        " Test that references to RuleElement are kept even if element goes"
        " out of scope "
        def _get_rule():
            users = ["foo", "bar"]
            user_groups = ["abc", "def"]
            el = pyhbac.HbacRuleElement(names=users, groups=user_groups)
            rule = pyhbac.HbacRule("testRuleElement")
            rule.users = el
            return rule

        rule = _get_rule()
        self.assertCountEqual(rule.users.names, ["foo", "bar"])
        self.assertCountEqual(rule.users.groups, ["abc", "def"])

    def testRepr(self):
        r = pyhbac.HbacRule('foo')
        self.assertEqual(r.__repr__(),
                         u"<name foo enabled 0 "
                         "users <category 0 names [] groups []> "
                         "services <category 0 names [] groups []> "
                         "targethosts <category 0 names [] groups []> "
                         "srchosts <category 0 names [] groups []>>")

        name = "someuser"
        service = "ssh"
        srchost = "host1"
        targethost = "host2"

        r.users.names = [name]
        r.services.names = [service]
        r.srchosts.names = [srchost]
        r.targethosts.names = [targethost]

        self.assertEqual(r.__repr__(),
                         u"<name foo enabled 0 "
                         "users <category 0 names [%s] groups []> "
                         "services <category 0 names [%s] groups []> "
                         "targethosts <category 0 names [%s] groups []> "
                         "srchosts <category 0 names [%s] groups []>>" %
                         (name, service, targethost, srchost))

    def testValidate(self):
        r = pyhbac.HbacRule('valid_rule')

        valid, missing = r.validate()
        self.assertEqual(valid, False)
        self.assertCountEqual(missing, (pyhbac.HBAC_RULE_ELEMENT_USERS,
                                        pyhbac.HBAC_RULE_ELEMENT_SERVICES,
                                        pyhbac.HBAC_RULE_ELEMENT_TARGETHOSTS,
                                        pyhbac.HBAC_RULE_ELEMENT_SOURCEHOSTS))

        r.users.names = ["someuser"]
        r.services.names = ["ssh"]

        valid, missing = r.validate()
        self.assertEqual(valid, False)
        self.assertCountEqual(missing, (pyhbac.HBAC_RULE_ELEMENT_TARGETHOSTS,
                                        pyhbac.HBAC_RULE_ELEMENT_SOURCEHOSTS))

        r.srchosts.names = ["host1"]
        r.targethosts.names = ["host2"]

        valid, missing = r.validate()
        self.assertEqual(valid, True)


class PyHbacRequestElementTest(unittest.TestCase):
    def testInstantiateEmpty(self):
        el = pyhbac.HbacRequestElement()
        self.assertCountEqual(el.name, "")
        self.assertCountEqual(el.groups, [])

    def testInit(self):
        name = "foo"
        el = pyhbac.HbacRequestElement(name=name)
        self.assertCountEqual(el.name, name)

        groups = ["abc", "def"]
        el = pyhbac.HbacRequestElement(groups=groups)
        self.assertCountEqual(el.groups, groups)

    def testGetSet(self):
        name = "foo"
        el = pyhbac.HbacRequestElement()
        self.assertCountEqual(el.name, "")
        el.name = name
        self.assertCountEqual(el.name, name)

        groups = ["abc", "def"]
        el = pyhbac.HbacRequestElement()
        self.assertCountEqual(el.groups, [])
        el.groups = groups
        self.assertCountEqual(el.groups, groups)

        # Test other iterables than list
        groups = ("abc", "def")
        el = pyhbac.HbacRequestElement()
        self.assertCountEqual(el.groups, [])
        el.groups = groups
        self.assertCountEqual(el.groups, groups)

    def testGroupsNotIterable(self):
        self.assertRaises(TypeError, pyhbac.HbacRequestElement, groups=None)
        self.assertRaises(TypeError, pyhbac.HbacRequestElement, groups=123)

    def testRepr(self):
        r = pyhbac.HbacRequestElement()
        self.assertEqual(r.__repr__(), u"<name  groups []>")

        r.name = 'foo'
        r.groups = ['bar', 'baz']
        self.assertEqual(r.__repr__(), u"<name foo groups [bar,baz]>")


class PyHbacRequestTest(unittest.TestCase):
    def testRequestElementHandling(self):
        name = "req_name"
        groups = ["g1", "g2"]

        # The request should be empty after instantiation
        req = pyhbac.HbacRequest()
        self.assertIsInstance(req.user, pyhbac.HbacRequestElement)
        self.assertIsInstance(req.service, pyhbac.HbacRequestElement)
        self.assertIsInstance(req.targethost, pyhbac.HbacRequestElement)
        self.assertIsInstance(req.srchost, pyhbac.HbacRequestElement)

        self.assertEqual(req.user.name, "")
        self.assertIsInstance(req.user.groups, list)
        self.assertCountEqual(req.user.groups, [])

        # Assign by copying a HbacRequestElement
        user_el = pyhbac.HbacRequestElement(name=name, groups=groups)
        req = pyhbac.HbacRequest()
        req.user = user_el
        self.assertCountEqual(req.user.name, name)
        self.assertCountEqual(req.user.groups, groups)

        # Assign directly
        req = pyhbac.HbacRequest()
        req.user.name = name
        req.user.groups = groups
        self.assertCountEqual(req.user.name, name)
        self.assertCountEqual(req.user.groups, groups)

    def testRuleName(self):
        req = pyhbac.HbacRequest()
        self.assertEqual(req.rule_name, None)
        # python 2.4 raises TypError, 2.7 raises AttributeError
        self.assertRaises((TypeError, AttributeError), req.__setattr__,
                          "rule_name", "foo")

    def testEvaluate(self):
        name = "someuser"
        service = "ssh"
        srchost = "host1"
        targethost = "host2"

        allow_rule = pyhbac.HbacRule("allowRule", enabled=True)
        allow_rule.users.names = [name]
        allow_rule.services.names = [service]
        allow_rule.srchosts.names = [srchost]
        allow_rule.targethosts.names = [targethost]

        req = pyhbac.HbacRequest()
        req.user.name = name
        req.service.name = service
        req.srchost.name = srchost
        req.targethost.name = targethost

        # Test that an allow rule on its own allows access
        res = req.evaluate((allow_rule,))
        self.assertEqual(res, pyhbac.HBAC_EVAL_ALLOW)
        self.assertEqual(req.rule_name, "allowRule")

        # Test that a user not in the rule is not allowed
        req.user.name = "someotheruser"
        res = req.evaluate((allow_rule, ))
        self.assertEqual(res, pyhbac.HBAC_EVAL_DENY)
        self.assertEqual(req.rule_name, None)

        # But allows if the rule is an ALL rule
        allow_rule.users.category.add(pyhbac.HBAC_CATEGORY_ALL)
        res = req.evaluate((allow_rule, ))
        self.assertEqual(res, pyhbac.HBAC_EVAL_ALLOW)

    def testRepr(self):
        name = "someuser"
        service = "ssh"
        srchost = "host1"
        targethost = "host2"

        req = pyhbac.HbacRequest()

        self.assertEqual(req.__repr__(), "<user <name  groups []> "
                                         "service <name  groups []> "
                                         "targethost <name  groups []> "
                                         "srchost <name  groups []>>")

        req.user.name = name
        req.service.name = service
        req.srchost.name = srchost
        req.targethost.name = targethost

        self.assertEqual(req.__repr__(), "<user <name %s groups []> "
                                         "service <name %s groups []> "
                                         "targethost <name %s groups []> "
                                         "srchost <name %s groups []>>" %
                                         (name, service, targethost, srchost))

    def testEvaluateNegative(self):
        name = "someuser"
        service = "ssh"
        srchost = "host1"
        targethost = "host2"

        allow_rule = pyhbac.HbacRule("allowRule", enabled=True)
        allow_rule.users.names = [name]
        allow_rule.services.names = [service]
        allow_rule.srchosts.names = [srchost]
        allow_rule.targethosts.names = [targethost]

        req = pyhbac.HbacRequest()
        req.service.name = service
        req.srchost.name = srchost
        req.targethost.name = targethost
        req.user.name = name

        saveuser = req.user
        req.user = None  # need to catch this

        # catch invalid category value
        savecat = copy.copy(allow_rule.users.category)
        allow_rule.users.category.add(pyhbac.HBAC_EVAL_ERROR)
        self.assertRaises(ValueError, req.evaluate, (allow_rule,))
        allow_rule.users.category = savecat

        # Test that invalid type is raised
        self.assertRaises(TypeError, req.evaluate, (allow_rule,))

        req.user = saveuser
        allow_rule.users = None  # need to catch this
        self.assertRaises(TypeError, req.evaluate, (allow_rule,))

        # catch invalid rule type
        self.assertRaises(TypeError, req.evaluate, (allow_rule, None))


class PyHbacModuleTest(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        os.unlink(MODPATH + "/pyhbac.so")
        os.rmdir(MODPATH)

    def testHasResultTypes(self):
        assert hasattr(pyhbac, "HBAC_EVAL_ALLOW")
        assert hasattr(pyhbac, "HBAC_EVAL_DENY")
        assert hasattr(pyhbac, "HBAC_EVAL_ERROR")

    def testHasErrorTypes(self):
        assert hasattr(pyhbac, "HBAC_ERROR_UNKNOWN")
        assert hasattr(pyhbac, "HBAC_SUCCESS")
        assert hasattr(pyhbac, "HBAC_ERROR_NOT_IMPLEMENTED")
        assert hasattr(pyhbac, "HBAC_ERROR_OUT_OF_MEMORY")
        assert hasattr(pyhbac, "HBAC_ERROR_UNPARSEABLE_RULE")

    def testHasCategories(self):
        assert hasattr(pyhbac, "HBAC_CATEGORY_NULL")
        assert hasattr(pyhbac, "HBAC_CATEGORY_ALL")

    def testHasRuleElementTypes(self):
        assert hasattr(pyhbac, "HBAC_RULE_ELEMENT_USERS")
        assert hasattr(pyhbac, "HBAC_RULE_ELEMENT_SERVICES")
        assert hasattr(pyhbac, "HBAC_RULE_ELEMENT_TARGETHOSTS")
        assert hasattr(pyhbac, "HBAC_RULE_ELEMENT_SOURCEHOSTS")

    def testHbacResultString(self):
        results = [pyhbac.HBAC_EVAL_ALLOW, pyhbac.HBAC_EVAL_DENY,
                   pyhbac.HBAC_EVAL_ERROR]
        for r in results:
            s = pyhbac.hbac_result_string(r)
            self.assertIsInstance(s, unicode)
            assert len(s) > 0

    def testHbacErrorString(self):
        errors = [pyhbac.HBAC_ERROR_UNKNOWN,
                  pyhbac.HBAC_SUCCESS,
                  pyhbac.HBAC_ERROR_NOT_IMPLEMENTED,
                  pyhbac.HBAC_ERROR_OUT_OF_MEMORY,
                  pyhbac.HBAC_ERROR_UNPARSEABLE_RULE]
        for e in errors:
            s = pyhbac.hbac_error_string(e)
            self.assertIsInstance(s, unicode)
            assert len(s) > 0


if __name__ == "__main__":
    error = 0

    suite = unittest.TestLoader().loadTestsFromTestCase(PyHbacImport)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x1
        # need to bail out here because pyhbac could not be imported
        sys.exit(error)

    # import the pyhbac module into the global namespace, but make sure it's
    # the one in tree
    sys.path.insert(0, MODPATH)
    import pyhbac

    loadTestsFromTestCase = unittest.TestLoader().loadTestsFromTestCase

    suite = loadTestsFromTestCase(PyHbacRuleElementTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x2

    suite = loadTestsFromTestCase(PyHbacRuleTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x3

    suite = loadTestsFromTestCase(PyHbacRequestElementTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x4

    suite = loadTestsFromTestCase(PyHbacRequestTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x5

    suite = loadTestsFromTestCase(PyHbacModuleTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x6

    sys.exit(error)
