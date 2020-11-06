"""conftest.py for all tests"""

from __future__ import print_function
import subprocess
import pytest
import time
import random
import os
import posixpath
from subprocess import CalledProcessError
# pylint: disable=unused-import
from pytest_multihost import make_multihost_fixture
# pylint: disable=unused-import
from sssd.testlib.common.qe_class import session_multihost
from sssd.testlib.common.qe_class import create_testdir
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.ipa.utils import ipaTools
from sssd.testlib.common.utils import ADOperations
from sssd.testlib.common.expect import pexpect_ssh


def pytest_configure():
    """ Namespace hook to add below dict in the pytest namespace """
    pytest.num_masters = 1
    pytest.num_ad = 1
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 1
    pytest.num_others = 0

# ====================  Function Scoped Fixtures ==============


@pytest.fixture(scope="function")
def hbac_sshd_rule(session_multihost, request):
    """
    Setup hbac rule for service sshd which allows
    user foobar1 to ssh from client host.
    """
    ipa_server_tools = ipaTools(session_multihost.master[0])
    client_host = session_multihost.client[0].sys_hostname
    ipa_server_tools.add_hbac_rule('test1', 'foobar1', client_host, 'sshd')

    def delete_hbac_rule():
        """ Delete hbac rule """
        ipa_server_tools.del_hbac_rule('test1')
    request.addfinalizer(delete_hbac_rule)


@pytest.fixture(scope="function")
def create_aduser_group(session_multihost, request):
    """ create AD user group """
    uid = random.randint(9999, 999999)
    ad = ADOperations(session_multihost.ad[0])
    ad_user = 'testuser%d' % uid
    ad_group = 'testgroup%d' % uid
    ad.create_ad_unix_user_group(ad_user, ad_group)

    def remove_ad_user_group():
        """ Remove windows AD user and group """
        ad.delete_ad_user_group(ad_group)
        ad.delete_ad_user_group(ad_user)

    request.addfinalizer(remove_ad_user_group)
    return (ad_user, ad_group)


# ====================  Class Scoped Fixtures ================
@pytest.fixture(scope="class")
def default_ipa_users(session_multihost, request):
    """ Create IPA Users foobar0 to foobar9 """
    kinit_admin = 'kinit admin'
    session_multihost.master[0].run_command(kinit_admin,
                                            stdin_text='Secret123',
                                            raiseonerr=False)
    for i in range(10):
        user_info = {'firstname': 'Foo',
                     'lastname': 'bar%d' % i,
                     'loginname': 'foobar%d' % i,
                     'default_password': 'RedHat@123',
                     'reset_password': 'Secret123'}
        useradd = "echo '%s' | ipa user-add --first %s "\
                  " --last %s --password %s" % (user_info['default_password'],
                                                user_info['firstname'],
                                                user_info['lastname'],
                                                user_info['loginname'])
        cmd = session_multihost.master[0].run_command(useradd,
                                                      raiseonerr=False)
        assert cmd.returncode == 0

    def remove_ipa_users():
        """ Remove ipa users foobar1 to foobar10 """
        for i in range(10):
            user = 'foobar%d' % i
            cmd = 'ipa user-del foobar%d' % i
            session_multihost.master[0].run_command(cmd)
    request.addfinalizer(remove_ipa_users)


@pytest.fixture(scope="class")
def reset_password(session_multihost, request):
    """ Reset passwords for users foobar0 to foobar9 """
    tools = sssdTools(session_multihost.client[0])
    for i in range(10):
        user = 'foobar%d' % i
        cmd = "echo -e 'RedHat@123\nSecret123\nSecret123' | kinit %s" % user
        session_multihost.client[0].run_command(cmd)
        kdestroy = 'kdestroy'
        session_multihost.client[0].run_command(kdestroy)


@pytest.fixture(scope="class")
def disable_allow_all_hbac(session_multihost, request):
    """ Disable allow_all hbac rule """
    disable_allow_all = 'ipa hbacrule-disable allow_all'
    try:
        session_multihost.master[0].run_command(disable_allow_all)
    except CalledProcessError:
        pytest.fail("Failed to disable allow_all rule")

    def allow_all_hbac():
        """ Enable allow_all hbac rule """
        allow_all = 'ipa hbacrule-enable allow_all'
        try:
            session_multihost.master[0].run_command(allow_all)
        except CalledProcessError:
            pytest.fail("Failed to enable allow_all rule")
    request.addfinalizer(allow_all_hbac)


@pytest.fixture(scope="class")
def multihost(session_multihost, request):
    """ Multihost fixture to be used by tests
    :param obj session_multihost: multihost object
    :return obj session_multihost: return multihost object
    """
    if hasattr(request.cls(), 'class_setup'):
        request.cls().class_setup(session_multihost)
        request.addfinalizer(
            lambda: request.cls().class_teardown(session_multihost))
    return session_multihost


@pytest.fixture(scope="class")
def create_ad_users(session_multihost, request):
    """ Create AD Users """
    cwd = os.path.dirname(os.path.abspath(__file__))
    file_list = ['users.csv', 'add-users.ps1', 'remove-users.ps1']
    for filename in file_list:
        remote_file_path = posixpath.join('/home/administrator', filename)
        source_file_path = posixpath.join(cwd, filename)
        session_multihost.ad[0].transport.put_file(source_file_path,
                                                   remote_file_path)
    user_add_cmd = 'powershell -inputformat none -noprofile ./add-users.ps1'
    session_multihost.ad[0].run_command(user_add_cmd, raiseonerr=False)

    def remove_users():
        """ Remove AD users """
        del_cmd = 'powershell -inputformat none -noprofile ./remove-users.ps1'
        session_multihost.ad[0].run_command(del_cmd, raiseonerr=False)
    request.addfinalizer(remove_users)


@pytest.fixture(scope="class")
def create_ad_groups(session_multihost, request):
    """ Create AD Groups """
    cwd = os.path.dirname(os.path.abspath(__file__))
    file_list = ['groups.csv', 'nestedgroups.csv',
                 'add-groups.ps1', 'remove-groups.ps1']
    for filename in file_list:
        remote_file_path = posixpath.join('/home/administrator', filename)
        source_file_path = posixpath.join(cwd, filename)
        session_multihost.ad[0].transport.put_file(source_file_path,
                                                   remote_file_path)
    add_cmd = 'powershell -inputformat none -noprofile ./add-groups.ps1'
    session_multihost.ad[0].run_command(add_cmd, raiseonerr=False)

    def remove_ad_groups():
        """ Remove AD Groups """
        del_cmd = 'powershell -inputformat none -noprofile ./remove-groups.ps1'
        session_multihost.ad[0].run_command(del_cmd, raiseonerr=False)
    request.addfinalizer(remove_ad_groups)


# ====================  Session Scoped Fixtures ================

@pytest.fixture(scope="session", autouse=True)
# pylint: disable=unused-argument
def setup_ipa_client(session_multihost, request):
    """ Setup ipa client """
    sssd_client = sssdTools(session_multihost.client[0])
    client_hostname = session_multihost.client[0].sys_hostname
    server_hostname = session_multihost.master[0].sys_hostname
    ipa_client = ipaTools(session_multihost.client[0])
    ipa_server = ipaTools(session_multihost.master[0])
    ipa_client.install_common_pkgs()
    ipa_server.install_common_pkgs()
    ipa_client_uuid = ipa_client.get_default_nw_uuid()
    ipa_client_ip = ipa_client.get_interface_ip(ipa_client_uuid)
    ipa_server_uuid = ipa_server.get_default_nw_uuid()
    ipa_server_ip = ipa_server.get_interface_ip(ipa_server_uuid)
    sssd_client.update_resolv_conf(ipa_server_ip)

    options = "--ip-address=%s --hostname %s "\
              "--server %s --domain %s "\
              "--realm %s -w %s -p %s -U" % (ipa_client_ip,
                                             client_hostname,
                                             server_hostname,
                                             "testrealm.test",
                                             "TESTREALM.TEST",
                                             "Secret123",
                                             "admin")
    client_install_cmd = "ipa-client-install %s" % options
    try:
        cmd = session_multihost.client[0].run_command(client_install_cmd)
    except subprocess.CalledProcessError:
        pytest.fail("ipa client install failed")

    def teardown_session():
        """ Uninstall ipa client from server """
        client_uninstall_cmd = 'ipa-client-install --uninstall -U'
        session_multihost.client[0].run_command(client_uninstall_cmd)
    request.addfinalizer(teardown_session)
