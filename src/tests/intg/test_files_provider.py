#
# SSSD files domain tests
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
import stat
import time
import config
import signal
import subprocess
import pwd
import grp
import pytest
import tempfile

import ent
import sssd_id
from sssd_nss import NssReturnCode
from sssd_passwd import (call_sssd_getpwnam,
                         call_sssd_getpwuid)
from sssd_group import call_sssd_getgrnam, call_sssd_getgrgid
from files_ops import PasswdOps, GroupOps
from util import unindent

def have_files_provider():
    return os.environ['FILES_PROVIDER'] == "enabled"

# Sync this with files_ops.c
FILES_REALLOC_CHUNK = 64

CANARY = dict(name='canary', passwd='x', uid=100001, gid=200001,
              gecos='Used to check if passwd is resolvable',
              dir='/home/canary',
              shell='/bin/bash')

USER1 = dict(name='user1', passwd='x', uid=10001, gid=20001,
             gecos='User for tests',
             dir='/home/user1',
             shell='/bin/bash')

USER2 = dict(name='user2', passwd='x', uid=10002, gid=20001,
             gecos='User2 for tests',
             dir='/home/user2',
             shell='/bin/bash')

OV_USER1 = dict(name='ov_user1', passwd='x', uid=10010, gid=20010,
                gecos='Overriden User 1',
                dir='/home/ov/user1',
                shell='/bin/ov_user1_shell')

ALT_USER1 = dict(name='alt_user1', passwd='x', uid=60001, gid=70001,
                 gecos='User for tests from alt files',
                 dir='/home/altuser1',
                 shell='/bin/bash')

ALL_USERS = [CANARY, USER1, USER2, OV_USER1, ALT_USER1]

CANARY_GR = dict(name='canary',
                 gid=300001,
                 mem=[])

GROUP1 = dict(name='group1',
              gid=30001,
              mem=['user1'])

OV_GROUP1 = dict(name='ov_group1',
                 gid=30002,
                 mem=['user1'])

GROUP12 = dict(name='group12',
               gid=30012,
               mem=['user1', 'user2'])

GROUP_NOMEM = dict(name='group_nomem',
                   gid=40000,
                   mem=[])

ALT_GROUP1 = dict(name='alt_group1',
                  gid=80001,
                  mem=['alt_user1'])


def start_sssd():
    """Start sssd and add teardown for stopping it and removing state"""
    os.environ["SSS_FILES_PASSWD"] = os.environ["NSS_WRAPPER_PASSWD"]
    os.environ["SSS_FILES_GROUP"] = os.environ["NSS_WRAPPER_GROUP"]
    if subprocess.call(["sssd", "-D", "--logger=files"]) != 0:
        raise Exception("sssd start failed")


def stop_sssd():
    pid_file = open(config.PIDFILE_PATH, "r")
    pid = int(pid_file.read())
    os.kill(pid, signal.SIGTERM)
    while True:
        try:
            os.kill(pid, signal.SIGCONT)
        except OSError:
            break
        time.sleep(1)


def restart_sssd():
    stop_sssd()
    start_sssd()


def create_conf_fixture(request, contents):
    """Generate sssd.conf and add teardown for removing it"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)
    request.addfinalizer(lambda: os.unlink(config.CONF_PATH))


def create_sssd_fixture(request):
    start_sssd()

    def teardown():
        try:
            stop_sssd()
        except Exception:
            pass
        for path in os.listdir(config.DB_PATH):
            os.unlink(config.DB_PATH + "/" + path)
        for path in os.listdir(config.MCACHE_PATH):
            os.unlink(config.MCACHE_PATH + "/" + path)
    request.addfinalizer(teardown)


# Fixtures
@pytest.fixture
def files_domain_only(request):
    conf = unindent("""\
        [sssd]
        domains             = files
        services            = nss

        [domain/files]
        id_provider = files
        fallback_to_nss = False
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def files_multiple_sources(request):
    _, alt_passwd_path = tempfile.mkstemp(prefix='altpasswd')
    request.addfinalizer(lambda: os.unlink(alt_passwd_path))
    alt_pwops = PasswdOps(alt_passwd_path)

    _, alt_group_path = tempfile.mkstemp(prefix='altgroup')
    request.addfinalizer(lambda: os.unlink(alt_group_path))
    alt_grops = GroupOps(alt_group_path)

    passwd_list = ",".join([os.environ["NSS_WRAPPER_PASSWD"], alt_passwd_path])
    group_list = ",".join([os.environ["NSS_WRAPPER_GROUP"], alt_group_path])

    conf = unindent("""\
        [sssd]
        domains             = files
        services            = nss

        [nss]
        debug_level = 10

        [domain/files]
        id_provider = files
        fallback_to_nss = False
        passwd_files = {passwd_list}
        group_files = {group_list}
        debug_level = 10
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return alt_pwops, alt_grops


@pytest.fixture
def files_multiple_sources_nocreate(request):
    """
    Sets up SSSD with multiple sources, but does not actually create
    the files.
    """
    alt_passwd_path = tempfile.mktemp(prefix='altpasswd')
    request.addfinalizer(lambda: os.unlink(alt_passwd_path))

    alt_group_path = tempfile.mktemp(prefix='altgroup')
    request.addfinalizer(lambda: os.unlink(alt_group_path))

    passwd_list = ",".join([os.environ["NSS_WRAPPER_PASSWD"], alt_passwd_path])
    group_list = ",".join([os.environ["NSS_WRAPPER_GROUP"], alt_group_path])

    conf = unindent("""\
        [sssd]
        domains             = files
        services            = nss

        [nss]
        debug_level = 10

        [domain/files]
        id_provider = files
        fallback_to_nss = False
        passwd_files = {passwd_list}
        group_files = {group_list}
        debug_level = 10
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return alt_passwd_path, alt_group_path


@pytest.fixture
def proxy_to_files_domain_only(request):
    conf = unindent("""\
        [sssd]
        domains             = proxy
        services            = nss

        [domain/proxy]
        id_provider = proxy
        proxy_lib_name = files
        auth_provider = none
        resolver_provider = none
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def no_sssd_domain(request):
    conf = unindent("""\
        [sssd]
        services            = nss
        enable_files_domain = true
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def no_files_domain(request):
    conf = unindent("""\
        [sssd]
        services            = nss
        enable_files_domain = true

        [domain/disabled.files]
        id_provider = files
        fallback_to_nss = False
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def disabled_files_domain(request):
    conf = unindent("""\
        [sssd]
        domains             = proxy
        services            = nss
        enable_files_domain = false

        [domain/proxy]
        id_provider = proxy
        proxy_lib_name = files
        auth_provider = none
        resolver_provider = none
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def domain_resolution_order(request):
    conf = unindent("""\
        [sssd]
        domains             = files
        services            = nss
        domain_resolution_order = foo

        [domain/files]
        id_provider = files
        fallback_to_nss = False
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def default_domain_suffix(request):
    conf = unindent("""\
        [sssd]
        domains             = files
        services            = nss
        default_domain_suffix = foo

        [domain/files]
        id_provider = files
        fallback_to_nss = False
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def override_homedir_and_shell(request):
    conf = unindent("""\
        [sssd]
        domains             = files
        services            = nss

        [domain/files]
        id_provider = files
        fallback_to_nss = False
        override_homedir = /test/bar
        override_shell = /bin/bar

        [nss]
        override_homedir = /test/foo
        override_shell = /bin/foo
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def setup_pw_with_list(pwd_ops, user_list):
    for user in user_list:
        pwd_ops.useradd(**user)
    ent.assert_passwd_by_name(CANARY['name'], CANARY)
    return pwd_ops


@pytest.fixture
def add_user_with_canary(passwd_ops_setup):
    return setup_pw_with_list(passwd_ops_setup, [CANARY, USER1])


@pytest.fixture
def setup_pw_with_canary(passwd_ops_setup):
    return setup_pw_with_list(passwd_ops_setup, [CANARY])


def add_group_members(pwd_ops, group):
    members = {x['name']: x for x in ALL_USERS}
    for member in group['mem']:
        if pwd_ops.userexist(member):
            continue

        pwd_ops.useradd(**members[member])


def setup_gr_with_list(pwd_ops, grp_ops, group_list):
    for group in group_list:
        add_group_members(pwd_ops, group)
        grp_ops.groupadd(**group)

    ent.assert_group_by_name(CANARY_GR['name'], CANARY_GR)
    return grp_ops


@pytest.fixture
def add_group_with_canary(passwd_ops_setup, group_ops_setup):
    return setup_gr_with_list(
        passwd_ops_setup, group_ops_setup, [GROUP1, CANARY_GR]
    )


@pytest.fixture
def setup_gr_with_canary(passwd_ops_setup, group_ops_setup):
    return setup_gr_with_list(passwd_ops_setup, group_ops_setup, [CANARY_GR])


def poll_canary(fn, name, threshold=20):
    """
    If we query SSSD while it's updating its cache, it would return NOTFOUND
    rather than a result from potentially outdated or incomplete cache. In
    reality this doesn't hurt because the order of the modules is normally
    "sss files" so the user lookup would fall back to files. But in tests
    we use this loop to wait until the canary user who is always there is
    resolved.
    """
    for _ in range(0, threshold):
        res, _ = fn(name)
        if res == NssReturnCode.SUCCESS:
            return True
        elif res == NssReturnCode.NOTFOUND:
            time.sleep(0.1)
            continue
        else:
            return False
    return False


def sssd_getpwnam_sync(name):
    ret = poll_canary(call_sssd_getpwnam, CANARY["name"])
    if ret is False:
        return NssReturnCode.NOTFOUND, None

    return call_sssd_getpwnam(name)


def sssd_getpwuid_sync(uid):
    ret = poll_canary(call_sssd_getpwnam, CANARY["name"])
    if ret is False:
        return NssReturnCode.NOTFOUND, None

    return call_sssd_getpwuid(uid)


def sssd_getgrnam_sync(name):
    ret = poll_canary(call_sssd_getgrnam, CANARY_GR["name"])
    if ret is False:
        return NssReturnCode.NOTFOUND, None

    return call_sssd_getgrnam(name)


def sssd_getgrgid_sync(name):
    ret = poll_canary(call_sssd_getgrnam, CANARY_GR["name"])
    if ret is False:
        return NssReturnCode.NOTFOUND, None

    return call_sssd_getgrgid(name)


def sssd_id_sync(name):
    sssd_getpwnam_sync(CANARY["name"])
    res, _, groups = sssd_id.get_user_groups(name)
    return res, groups


def sync_files_provider(name=None):
    """
    Tests with files provider can fail because files provider did not yet
    finish updating its cache. Polling for presents of the canary user makes
    sure that we wait until the cache is updated.
    """
    if name is None:
        name = CANARY["name"]

    ret = poll_canary(call_sssd_getpwnam, name)
    assert ret


# Helper functions
def user_generator(seqnum):
    return dict(name='user%d' % seqnum,
                passwd='x',
                uid=10000 + seqnum,
                gid=20000 + seqnum,
                gecos='User for tests',
                dir='/home/user%d' % seqnum,
                shell='/bin/bash')


def check_user(exp_user, delay=1.0):
    if delay > 0:
        time.sleep(delay)

    res, found_user = sssd_getpwnam_sync(exp_user["name"])
    assert res == NssReturnCode.SUCCESS
    assert found_user == exp_user


def group_generator(seqnum):
    return dict(name='group%d' % seqnum,
                gid=30000 + seqnum,
                mem=[])


def check_group(exp_group, delay=1.0):
    if delay > 0:
        time.sleep(delay)

    res, found_group = sssd_getgrnam_sync(exp_group["name"])
    assert res == NssReturnCode.SUCCESS
    assert found_group == exp_group


def check_group_by_gid(exp_group, delay=1.0):
    if delay > 0:
        time.sleep(delay)

    res, found_group = sssd_getgrgid_sync(exp_group["gid"])
    assert res == NssReturnCode.SUCCESS
    assert found_group == exp_group


def check_group_list(exp_groups_list):
    for exp_group in exp_groups_list:
        check_group(exp_group)


def assert_user_overriden():
    """
    There is an issue in nss_wrapper [0] and nss_wrapper always looks into
    the files first before using the NSS module. This lets this check fail
    because the user is found in the file and hence will be returned
    without overridden values.
    In order to work this around while there's no fix for nss_wrapper, let's
    use the fully-qualified name when looking up the USER1

    https://bugzilla.samba.org/show_bug.cgi?id=12883)
    """
    ent.assert_passwd_by_name(USER1["name"] + "@files", OV_USER1)
    ent.assert_passwd_by_name(OV_USER1["name"], OV_USER1)


def assert_group_overriden():
    """
    There is an issue in nss_wrapper [0] and nss_wrapper always looks into
    the files first before using the NSS module. This lets this check fail
    because the user is found in the file and hence will be returned
    without overridden values.
    In order to work this around while there's no fix for nss_wrapper, let's
    use the fully-qualified name when looking up the GROUP1

    https://bugzilla.samba.org/show_bug.cgi?id=12883)
    """
    ent.assert_group_by_name(GROUP1["name"] + "@files", OV_GROUP1)
    ent.assert_group_by_name(OV_GROUP1["name"], OV_GROUP1)


# User tests
@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getpwnam_after_start(add_user_with_canary, files_domain_only):
    """
    Test that after startup without any additional operations, a user
    can be resolved through sssd
    """
    res, user = sssd_getpwnam_sync(USER1["name"])
    assert res == NssReturnCode.SUCCESS
    assert user == USER1


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getpwuid_after_start(add_user_with_canary, files_domain_only):
    """
    Test that after startup without any additional operations, a user
    can be resolved through sssd
    """
    res, user = sssd_getpwuid_sync(USER1["uid"])
    assert res == NssReturnCode.SUCCESS
    assert user == USER1


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_user_overriden(add_user_with_canary, files_domain_only):
    """
    Test that user override works with files domain only
    """
    # Override
    subprocess.check_call(["sss_override", "user-add", USER1["name"],
                           "-u", str(OV_USER1["uid"]),
                           "-g", str(OV_USER1["gid"]),
                           "-n", OV_USER1["name"],
                           "-c", OV_USER1["gecos"],
                           "-h", OV_USER1["dir"],
                           "-s", OV_USER1["shell"]])

    restart_sssd()

    assert_user_overriden()


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_group_overriden(add_group_with_canary, files_domain_only):
    """
    Test that user override works with files domain only
    """
    # Override
    subprocess.check_call(["sss_override", "group-add", GROUP1["name"],
                           "-n", OV_GROUP1["name"],
                           "-g", str(OV_GROUP1["gid"])])

    restart_sssd()

    assert_group_overriden()


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getpwnam_neg(files_domain_only):
    """
    Test that a nonexistent user cannot be resolved by name
    """
    res, _ = call_sssd_getpwnam("nosuchuser")
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getpwuid_neg(files_domain_only):
    """
    Test that a nonexistent user cannot be resolved by UID
    """
    res, _ = call_sssd_getpwuid(12345)
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_root_does_not_resolve(files_domain_only):
    """
    SSSD currently does not resolve the root user even though it can
    be resolved through the NSS interface
    """
    nss_root = pwd.getpwnam("root")
    assert nss_root is not None

    res, _ = call_sssd_getpwnam("root")
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_uid_zero_does_not_resolve(files_domain_only):
    """
    SSSD currently does not resolve the UID 0 even though it can
    be resolved through the NSS interface
    """
    nss_root = pwd.getpwuid(0)
    assert nss_root is not None

    res, _ = call_sssd_getpwuid(0)
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_add_remove_add_file_user(setup_pw_with_canary, files_domain_only):
    """
    Test that removing a user is detected and the user
    is removed from the sssd database. Similarly, an add
    should be detected. Do this several times to test retaining
    the inotify watch for moved and unlinked files.
    """
    res, _ = call_sssd_getpwnam(USER1["name"])
    assert res == NssReturnCode.NOTFOUND

    setup_pw_with_canary.useradd(**USER1)
    check_user(USER1)

    setup_pw_with_canary.userdel(USER1["name"])
    time.sleep(1.0)
    res, _ = sssd_getpwnam_sync(USER1["name"])
    assert res == NssReturnCode.NOTFOUND

    setup_pw_with_canary.useradd(**USER1)
    check_user(USER1)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_mod_user_shell(add_user_with_canary, files_domain_only):
    """
    Test that modifying a user shell is detected and the user
    is modified in the sssd database
    """
    res, user = sssd_getpwnam_sync(USER1["name"])
    assert res == NssReturnCode.SUCCESS
    assert user == USER1

    moduser = dict(USER1)
    moduser['shell'] = '/bin/zsh'
    add_user_with_canary.usermod(**moduser)

    check_user(moduser)


def incomplete_user_setup(pwd_ops, del_field, exp_field):
    adduser = dict(USER1)
    del adduser[del_field]
    exp_user = dict(USER1)
    exp_user[del_field] = exp_field

    pwd_ops.useradd(**adduser)

    return exp_user


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_user_no_shell(setup_pw_with_canary, files_domain_only):
    """
    Test that resolving a user without a shell defined works and returns
    a fallback value
    """
    check_user(incomplete_user_setup(setup_pw_with_canary, 'shell', ''))


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_user_no_dir(setup_pw_with_canary, files_domain_only):
    """
    Test that resolving a user without a homedir defined works and returns
    a fallback value
    """
    check_user(incomplete_user_setup(setup_pw_with_canary, 'dir', ''))


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_user_no_gecos(setup_pw_with_canary, files_domain_only):
    """
    Test that resolving a user without a gecos defined works and returns
    a fallback value
    """
    check_user(incomplete_user_setup(setup_pw_with_canary, 'gecos', ''))


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_user_no_passwd(setup_pw_with_canary, files_domain_only):
    """
    Test that resolving a user without a password defined works and returns
    a fallback value
    """
    check_user(incomplete_user_setup(setup_pw_with_canary, 'passwd', 'x'))


def bad_incomplete_user_setup(pwd_ops, del_field):
    adduser = dict(USER1)
    adduser[del_field] = ''

    pwd_ops.useradd(**adduser)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_incomplete_user_fail(setup_pw_with_canary, files_domain_only):
    """
    Test resolving an incomplete user where the missing field is required
    to be present in the user record and thus the user shouldn't resolve.

    We cannot test UID and GID missing because nss_wrapper doesn't even
    load the malformed passwd file, then.
    """
    bad_incomplete_user_setup(setup_pw_with_canary, 'name')
    res, user = sssd_getpwnam_sync(USER1["name"])
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_after_start(add_group_with_canary, files_domain_only):
    """
    Test that after startup without any additional operations, a group
    can be resolved through sssd by name
    """
    check_group(GROUP1)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrgid_after_start(add_group_with_canary, files_domain_only):
    """
    Test that after startup without any additional operations, a group
    can be resolved through sssd by GID
    """
    check_group_by_gid(GROUP1)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_neg(files_domain_only):
    """
    Test that a nonexistent group cannot be resolved
    """
    res, user = sssd_getgrnam_sync("nosuchgroup")
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrgid_neg(files_domain_only):
    """
    Test that a nonexistent group cannot be resolved
    """
    res, user = sssd_getgrgid_sync(123456)
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_root_group_does_not_resolve(files_domain_only):
    """
    SSSD currently does not resolve the root group even though it can
    be resolved through the NSS interface
    """
    nss_root = grp.getgrnam("root")
    assert nss_root is not None

    res, user = call_sssd_getgrnam("root")
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_gid_zero_does_not_resolve(files_domain_only):
    """
    SSSD currently does not resolve the group with GID 0 even though it
    can be resolved through the NSS interface
    """
    nss_root = grp.getgrgid(0)
    assert nss_root is not None

    res, user = call_sssd_getgrgid(0)
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.flaky(max_runs=5)
@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_add_remove_add_file_group(
        setup_pw_with_canary, setup_gr_with_canary, files_domain_only
):
    """
    Test that removing a group is detected and the group
    is removed from the sssd database. Similarly, an add
    should be detected. Do this several times to test retaining
    the inotify watch for moved and unlinked files.
    """
    res, group = call_sssd_getgrnam(GROUP1["name"])
    assert res == NssReturnCode.NOTFOUND

    add_group_members(setup_pw_with_canary, GROUP1)
    setup_gr_with_canary.groupadd(**GROUP1)
    check_group(GROUP1)

    setup_gr_with_canary.groupdel(GROUP1["name"])
    time.sleep(1)
    res, group = call_sssd_getgrnam(GROUP1["name"])
    assert res == NssReturnCode.NOTFOUND

    setup_gr_with_canary.groupadd(**GROUP1)
    check_group(GROUP1)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_mod_group_name(add_group_with_canary, files_domain_only):
    """
    Test that modifying a group name is detected and the group
    is modified in the sssd database
    """
    check_group(GROUP1)

    modgroup = dict(GROUP1)
    modgroup['name'] = 'group1_mod'
    add_group_with_canary.groupmod(old_name=GROUP1["name"], **modgroup)

    check_group(modgroup)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_mod_group_gid(add_group_with_canary, files_domain_only):
    """
    Test that modifying a group name is detected and the group
    is modified in the sssd database
    """
    check_group(GROUP1)

    modgroup = dict(GROUP1)
    modgroup['gid'] = 30002
    add_group_with_canary.groupmod(old_name=GROUP1["name"], **modgroup)

    check_group(modgroup)


@pytest.fixture
def add_group_nomem_with_canary(passwd_ops_setup, group_ops_setup):
    return setup_gr_with_list(
        passwd_ops_setup, group_ops_setup, [GROUP_NOMEM, CANARY_GR]
    )


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_no_members(add_group_nomem_with_canary, files_domain_only):
    """
    Test that after startup without any additional operations, a group
    can be resolved through sssd
    """
    check_group(GROUP_NOMEM)


def groupadd_list(grp_ops, groups):
    for group in groups:
        grp_ops.groupadd(**group)


def useradd_list(pwd_ops, users):
    for usr in users:
        pwd_ops.useradd(**usr)


def user_and_group_setup(pwd_ops, grp_ops, users, groups, reverse):
    """
    The reverse is added so that we test cases where a group is added first,
    then a user for this group is created -- in that case, we need to properly
    link the group after the user is added.
    """
    if reverse is False:
        useradd_list(pwd_ops, users)
        groupadd_list(grp_ops, groups)
    else:
        groupadd_list(grp_ops, groups)
        useradd_list(pwd_ops, users)


def members_check(added_groups):
    # Test that users are members as per getgrnam
    check_group_list(added_groups)

    # Test that users are members as per initgroups
    for group in added_groups:
        for member in group['mem']:
            res, groups = sssd_id_sync(member)
            assert res == sssd_id.NssReturnCode.SUCCESS
            assert group['name'] in groups


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_members_users_first(setup_pw_with_canary,
                                      setup_gr_with_canary,
                                      files_domain_only):
    """
    A user is linked with a group
    """
    user_and_group_setup(setup_pw_with_canary,
                         setup_gr_with_canary,
                         [USER1],
                         [GROUP1],
                         False)
    members_check([GROUP1])


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_members_users_multiple(setup_pw_with_canary,
                                         setup_gr_with_canary,
                                         files_domain_only):
    """
    Multiple users are linked with a group
    """
    user_and_group_setup(setup_pw_with_canary,
                         setup_gr_with_canary,
                         [USER1, USER2],
                         [GROUP12],
                         False)
    members_check([GROUP12])


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_members_groups_first(setup_pw_with_canary,
                                       setup_gr_with_canary,
                                       files_domain_only):
    """
    A group is linked with a user
    """
    user_and_group_setup(setup_pw_with_canary,
                         setup_gr_with_canary,
                         [USER1],
                         [GROUP1],
                         True)
    members_check([GROUP1])


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_ghost(setup_pw_with_canary,
                        setup_gr_with_canary,
                        files_domain_only):
    """
    Test that group if not found (and will be handled by nss_files) if there
    are any ghost members.
    """
    user_and_group_setup(setup_pw_with_canary,
                         setup_gr_with_canary,
                         [],
                         [GROUP12],
                         False)

    time.sleep(1)
    res, group = call_sssd_getgrnam(GROUP12["name"])
    assert res == NssReturnCode.NOTFOUND

    for member in GROUP12['mem']:
        res, _ = call_sssd_getpwnam(member)
        assert res == NssReturnCode.NOTFOUND


def ghost_and_member_test(pw_ops, grp_ops, reverse):
    user_and_group_setup(pw_ops,
                         grp_ops,
                         [USER1],
                         [GROUP12],
                         reverse)

    time.sleep(1)
    res, group = call_sssd_getgrnam(GROUP12["name"])
    assert res == NssReturnCode.NOTFOUND

    # We checked that the group added has the same members as group12,
    # so both user1 and user2. Now check that user1 is a member of
    # group12 and its own primary GID but user2 doesn't exist, it's
    # just a ghost entry
    res, groups = sssd_id_sync('user1')
    assert res == sssd_id.NssReturnCode.SUCCESS
    assert len(groups) == 2
    assert 'group12' in groups

    res, _ = call_sssd_getpwnam('user2')
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_user_ghost_and_member(setup_pw_with_canary,
                                        setup_gr_with_canary,
                                        files_domain_only):
    """
    Test that a group with one member and one ghost.
    """
    ghost_and_member_test(setup_pw_with_canary,
                          setup_gr_with_canary,
                          False)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_user_member_and_ghost(setup_pw_with_canary,
                                        setup_gr_with_canary,
                                        files_domain_only):
    """
    Test that a group with one member and one ghost, adding the group
    first and then linking the member
    """
    ghost_and_member_test(setup_pw_with_canary,
                          setup_gr_with_canary,
                          True)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_add_remove_members(setup_pw_with_canary,
                                     add_group_nomem_with_canary,
                                     files_domain_only):
    """
    Test that a user is linked with a group
    """
    pwd_ops = setup_pw_with_canary

    check_group(GROUP_NOMEM)

    for usr in [USER1, USER2]:
        pwd_ops.useradd(**usr)

    modgroup = dict(GROUP_NOMEM)
    modgroup['mem'] = ['user1', 'user2']
    add_group_nomem_with_canary.groupmod(old_name=modgroup['name'], **modgroup)
    check_group(modgroup)

    res, groups = sssd_id_sync('user1')
    assert res == sssd_id.NssReturnCode.SUCCESS
    assert len(groups) == 2
    assert 'group_nomem' in groups

    res, groups = sssd_id_sync('user2')
    assert res == sssd_id.NssReturnCode.SUCCESS
    assert 'group_nomem' in groups

    modgroup['mem'] = ['user2']
    add_group_nomem_with_canary.groupmod(old_name=modgroup['name'], **modgroup)
    check_group(modgroup)

    # User1 exists, but is not a member of any supplementary group anymore
    res, _ = call_sssd_getpwnam('user1')
    assert res == sssd_id.NssReturnCode.SUCCESS
    res, groups = sssd_id_sync('user1')
    assert res == sssd_id.NssReturnCode.NOTFOUND

    # user2 still is
    res, groups = sssd_id_sync('user2')
    assert res == sssd_id.NssReturnCode.SUCCESS
    assert len(groups) == 2
    assert 'group_nomem' in groups


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_getgrnam_add_remove_ghosts(setup_pw_with_canary,
                                    add_group_nomem_with_canary,
                                    files_domain_only):
    """
    Test that a user is linked with a group
    """
    check_group(GROUP_NOMEM)

    modgroup = dict(GROUP_NOMEM)
    modgroup['mem'] = ['user1', 'user2']
    add_group_nomem_with_canary.groupmod(old_name=modgroup['name'], **modgroup)
    time.sleep(1)
    res, group = call_sssd_getgrnam(modgroup['name'])
    assert res == sssd_id.NssReturnCode.NOTFOUND

    modgroup['mem'] = ['user2']
    add_group_nomem_with_canary.groupmod(old_name=modgroup['name'], **modgroup)
    time.sleep(1)
    res, group = call_sssd_getgrnam(modgroup['name'])
    assert res == sssd_id.NssReturnCode.NOTFOUND

    res, _ = call_sssd_getpwnam('user1')
    assert res == NssReturnCode.NOTFOUND
    res, _ = call_sssd_getpwnam('user2')
    assert res == NssReturnCode.NOTFOUND


def realloc_users(pwd_ops, num):
    # Intentionally not including the last one because
    # canary is added first
    for i in range(1, num):
        user = user_generator(i)
        pwd_ops.useradd(**user)

    user = user_generator(num - 1)
    check_user(user)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_realloc_users_exact(setup_pw_with_canary, files_domain_only):
    """
    Test that returning exactly FILES_REALLOC_CHUNK users (see files_ops.c)
    works fine to test reallocation logic. Test exact number of users to
    check for off-by-one errors.
    """
    realloc_users(setup_pw_with_canary, FILES_REALLOC_CHUNK)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_realloc_users(setup_pw_with_canary, files_domain_only):
    """
    Test that returning exactly FILES_REALLOC_CHUNK users (see files_ops.c)
    works fine to test reallocation logic.
    """
    realloc_users(setup_pw_with_canary, FILES_REALLOC_CHUNK * 3)


def realloc_groups(grp_ops, num):
    for i in range(1, num):
        group = group_generator(i)
        grp_ops.groupadd(**group)

    group = group_generator(num - 1)
    check_group(group)


@pytest.mark.flaky(max_runs=5)
@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_realloc_groups_exact(setup_gr_with_canary, files_domain_only):
    """
    Test that returning exactly FILES_REALLOC_CHUNK groups (see files_ops.c)
    works fine to test reallocation logic. Test exact number of groups to
    check for off-by-one errors.
    """
    realloc_groups(setup_gr_with_canary, FILES_REALLOC_CHUNK * 3)


@pytest.mark.flaky(max_runs=5)
@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_realloc_groups(setup_gr_with_canary, files_domain_only):
    """
    Test that returning exactly FILES_REALLOC_CHUNK groups (see files_ops.c)
    works fine to test reallocation logic. Test exact number of groups to
    check for off-by-one errors.
    """
    realloc_groups(setup_gr_with_canary, FILES_REALLOC_CHUNK * 3)


# Files domain autoconfiguration tests
@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_no_sssd_domain(add_user_with_canary, no_sssd_domain):
    """
    Test that if no sssd domain is configured, sssd will add the implicit one
    """
    res, user = sssd_getpwnam_sync(USER1["name"])
    assert res == NssReturnCode.SUCCESS
    assert user == USER1


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_proxy_to_files_domain_only(add_user_with_canary,
                                    proxy_to_files_domain_only):
    """
    Test that implicit_files domain is not started together with proxy to files
    """
    res, _ = call_sssd_getpwnam("{0}@implicit_files".format(USER1["name"]))
    assert res == NssReturnCode.NOTFOUND


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_no_files_domain(add_user_with_canary, no_files_domain):
    """
    Test that if no files domain is configured, sssd will add the implicit one
    """
    res, user = sssd_getpwnam_sync(USER1["name"])
    assert res == NssReturnCode.SUCCESS
    assert user == USER1


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_disable_files_domain(add_user_with_canary, disabled_files_domain):
    """
    Test disabled files domain
    """
    # The local user will not be resolvable through nss_sss now
    res, user = sssd_getpwnam_sync(USER1["name"])
    assert res != NssReturnCode.SUCCESS


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_multiple_passwd_group_files(add_user_with_canary,
                                     add_group_with_canary,
                                     files_multiple_sources):
    """
    Test that users and groups can be mirrored from multiple files
    """
    alt_pwops, alt_grops = files_multiple_sources
    alt_pwops.useradd(**ALT_USER1)
    alt_grops.groupadd(**ALT_GROUP1)

    check_user(USER1)
    check_user(ALT_USER1)

    check_group(GROUP1)
    check_group(ALT_GROUP1)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_multiple_files_created_after_startup(add_user_with_canary,
                                              add_group_with_canary,
                                              files_multiple_sources_nocreate):
    """
    Test that users and groups can be mirrored from multiple files,
    but those files are not created when SSSD starts, only afterwards.
    """
    alt_passwd_path, alt_group_path = files_multiple_sources_nocreate

    check_user(USER1)
    check_group(GROUP1)

    # touch the files
    for fpath in (alt_passwd_path, alt_group_path):
        with open(fpath, "w"):
            os.utime(fpath)

    alt_pwops = PasswdOps(alt_passwd_path)
    alt_grops = GroupOps(alt_group_path)
    alt_pwops.useradd(**ALT_USER1)
    alt_grops.groupadd(**ALT_GROUP1)

    check_user(ALT_USER1)
    check_group(ALT_GROUP1)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_files_with_domain_resolution_order(add_user_with_canary,
                                            domain_resolution_order):
    """
    Test that when using domain_resolution_order the user won't be using
    its fully-qualified name.
    """
    check_user(USER1)


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_files_with_default_domain_suffix(add_user_with_canary,
                                          default_domain_suffix):
    """
    Test that when using domain_resolution_order the user won't be using
    its fully-qualified name.
    """
    ret = poll_canary(call_sssd_getpwuid, CANARY["uid"])
    if ret is False:
        return NssReturnCode.NOTFOUND, None

    res, found_user = call_sssd_getpwuid(USER1["uid"])
    assert res == NssReturnCode.SUCCESS
    assert found_user == USER1


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_files_with_override_homedir(add_user_with_canary,
                                     override_homedir_and_shell):
    res, user = sssd_getpwnam_sync(USER1["name"])
    assert res == NssReturnCode.SUCCESS
    assert user["dir"] == USER1["dir"]


@pytest.mark.skipif(not have_files_provider(),
                    reason="'files provider' disabled, skipping")
def test_files_with_override_shell(add_user_with_canary,
                                   override_homedir_and_shell):
    res, user = sssd_getpwnam_sync(USER1["name"])
    assert res == NssReturnCode.SUCCESS
    assert user["shell"] == USER1["shell"]
