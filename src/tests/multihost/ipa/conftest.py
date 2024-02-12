"""conftest.py for all tests"""

from __future__ import print_function
import subprocess
import random
import os
import posixpath
import pexpect
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.ipa.utils import ipaTools
from sssd.testlib.common.utils import ADOperations
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF


pytest_plugins = (
    'sssd.testlib.common.fixtures',
    'pytest_importance',
    'pytest_ticket',
    'sssd.testlib.common.custom_log',
)


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


@pytest.fixture(autouse=True)
def capture_sssd_logs(session_multihost, request):
    """This will print sssd logs in case of test failure"""
    yield
    if request.session.testsfailed:
        client = session_multihost.client[0]
        print(f"\n\n===Logs for {request.node.name}===\n\n")
        for data_d in client.run_command("ls /var/log/sssd/").stdout_text.split():
            client.run_command(f'echo "--- {data_d} ---"; '
                               f'cat /var/log/sssd/{data_d}')


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
    return ad_user, ad_group


@pytest.fixture(scope="function")
def backup_config_pam_gssapi_services(session_multihost, request):
    """ Take backup of files, Configure domain_params
        Configure /etc/pam.d/sudo
        Configure /etc/pam.d/sudo-i
    """
    tools = sssdTools(session_multihost.client[0])
    domain_name = tools.get_domain_section_name()
    client = sssdTools(session_multihost.client[0])
    domain_params = {'pam_gssapi_services': 'sudo, sudo-i'}
    client.sssd_conf(f'{domain_name}', domain_params)
    session_multihost.client[0].service_sssd('restart')
    session_multihost.client[0].run_command("cp -vf  /etc/pam.d/sudo "
                                            "/etc/pam.d/sudo_bkp")
    session_multihost.client[0].run_command("cp -vf  /etc/pam.d/sudo-i "
                                            "/etc/pam.d/sudo-i_bkp")
    session_multihost.client[0].run_command("sed -i '1 a auth "
                                            "sufficient pam_sss_gss.so' "
                                            "/etc/pam.d/sudo")
    session_multihost.client[0].run_command("sed -i '1 a auth sufficient "
                                            "pam_sss_gss.so' "
                                            "/etc/pam.d/sudo-i")

    def restore():
        session_multihost.client[0].run_command("cp -vf  "
                                                "/etc/pam.d/sudo_bkp "
                                                "/etc/pam.d/sudo")
        session_multihost.client[0].run_command("cp -vf  "
                                                "/etc/pam.d/sudo-i_bkp "
                                                "/etc/pam.d/sudo-i")
        session_multihost.client[0].run_command("rm -vf /tmp/domain_list_*")

    request.addfinalizer(restore)


@pytest.fixture(scope="function")
def create_reverse_zone(session_multihost, request):
    """ Creates reverse zone """
    client_ip = session_multihost.client[0].ip
    subnet = client_ip.split(".", 3)
    del subnet[-1]
    subnet.reverse()
    zone = '.'.join(subnet) + '.in-addr.arpa.'
    policy = 'grant * tcp-self * PTR'

    cmd_createzone = 'ipa dnszone-add %s ' \
                     '--dynamic-update=true ' \
                     '--allow-sync-ptr=true ' \
                     '--skip-overlap-check ' \
                     '--forward-policy=none' % zone
    cmd_modifyzone = 'ipa dnszone-mod %s ' \
                     '--update-policy=\'%s;\'' % (zone, policy)
    session_multihost.master[0].run_command(cmd_createzone,
                                            raiseonerr=False)
    session_multihost.master[0].run_command(cmd_modifyzone,
                                            raiseonerr=False)

    def remove_reverse_zone():
        """  removes reverse zone """
        cmd_removezone = 'ipa dnszone-del %s' % zone
        session_multihost.master[0].run_command(cmd_removezone,
                                                raiseonerr=False)

    request.addfinalizer(remove_reverse_zone)


@pytest.fixture(scope="function")
def default_ipa_groups(session_multihost, request):
    """ Create IPA Groups ipa-group0 to ipa-group9 """
    kinit_admin = 'kinit admin'
    session_multihost.master[0].run_command(kinit_admin,
                                            stdin_text='Secret123',
                                            raiseonerr=False)
    ipa_grp_gid_start = 342156780
    ipa_grp_count = 10
    for i in range(ipa_grp_count):
        gid = ipa_grp_gid_start + i
        group_add = 'ipa group-add ipa-group%d --desc="IPA group%d" --gid %d'\
                    % (i, i, gid)

        cmd = session_multihost.master[0].run_command(group_add,
                                                      raiseonerr=False)
        assert cmd.returncode == 0

    def remove_ipa_groups():
        """ Remove ipa Groups ipa-group0 to ipa-group9 """
        for i in range(10):
            cmd = 'ipa group-del ipa-group%d' % i
            session_multihost.master[0].run_command(cmd)
    request.addfinalizer(remove_ipa_groups)
    return ipa_grp_gid_start


@pytest.fixture(scope="function")
def add_group_member(session_multihost, request):
    """ Add  members in groups of IPA """
    kinit_admin = 'kinit admin'
    session_multihost.master[0].run_command(kinit_admin,
                                            stdin_text='Secret123',
                                            raiseonerr=False)
    for i in range(5):
        for j in range(10):
            add_gr_member = 'ipa group-add-member ipa-group%d ' \
                            '--users=foobar%d' % (i, j)

            cmd = session_multihost.master[0].run_command(add_gr_member,
                                                          raiseonerr=False)
            assert cmd.returncode == 0

    def remove_group_member():
        """ Remove users from IPA groups """
        for i in range(5):
            for j in range(10):
                cmd = ' ipa group-remove-member ipa-group%d --users=foobar%d'\
                      % (i, j)
                session_multihost.master[0].run_command(cmd)
    request.addfinalizer(remove_group_member)


@pytest.fixture(scope='function')
def backupsssdconf(session_multihost, request):
    """ Backup and restore sssd.conf """
    tools = sssdTools(session_multihost.client[0])
    tools.backup_sssd_conf()
    session_multihost.client[0].service_sssd('stop')

    def restoresssdconf():
        """ Restore sssd.conf """
        tools.restore_sssd_conf()
    request.addfinalizer(restoresssdconf)

# ====================  Class Scoped Fixtures ================


@pytest.fixture(scope='class')
def environment_setup(session_multihost, request):
    """
    Install necessary packages
    """
    client = session_multihost.client[0]
    if "Fedora" in client.distro:
        client.run_command("yum install -y shadow-utils*")
    else:
        client.run_command("yum --enablerepo=*-CRB install -y shadow-utils*")

    client.run_command("yum install -y gcc")
    client.run_command("yum install -y podman")
    with pytest.raises(subprocess.CalledProcessError):
        client.run_command("grep subid /etc/nsswitch.conf")
    file_location = "/data/list_subid_ranges.c"
    client.transport.put_file(os.path.dirname(os.path.abspath(__file__))
                              + file_location,
                              '/tmp/list_subid_ranges.c')
    client.run_command("gcc /tmp/list_subid_ranges.c"
                       "  -lsubid -o /tmp/list_subid_ranges")

    def remove():
        """ Remove file """
        for file in ['list_subid_ranges', 'list_subid_ranges.c']:
            client.run_command(f"rm -vf /tmp/{file}")

    request.addfinalizer(remove)


@pytest.fixture(scope='class')
def subid_generate(session_multihost, request):
    """
    Generate subid for user admin
    """
    user = "admin"
    test_password = "Secret123"

    p_ssh = pexpect.pxssh.pxssh(
        options={"StrictHostKeyChecking": "no",
                 "UserKnownHostsFile": "/dev/null"}
    )
    p_ssh.force_password = True
    try:
        p_ssh.login(session_multihost.client[0].ip, user, test_password)
        p_ssh.sendline('kinit')
        p_ssh.expect('Password for .*:', timeout=10)
        p_ssh.sendline(test_password)
        p_ssh.prompt(timeout=5)
        p_ssh.sendline(f'ipa subid-generate --owner={user}; echo "retcode:$?"')
        p_ssh.prompt(timeout=5)
        subid_gen_out = str(p_ssh.before)
        p_ssh.logout()
    except pexpect.pxssh.ExceptionPxssh:
        pytest.fail("Failed to login via ssh.")
    assert "retcode:0" in subid_gen_out, "Generating subid range failed."


@pytest.fixture(scope='class')
def bkp_cnfig_for_subid_files(session_multihost, request):
    """ Back up files used in test
        And config /etc/nsswitch.conf
    """
    session_multihost.client[0].run_command("cp -vf  "
                                            "/etc/subuid "
                                            "/tmp/subuid_bkp")
    session_multihost.client[0].run_command("cp -vf  "
                                            "/etc/subgid "
                                            "/tmp/subgid_bkp")
    session_multihost.client[0].run_command("cp -vf  "
                                            "/etc/nsswitch.conf "
                                            "/tmp/nsswitch.conf_bkp")
    session_multihost.client[0].run_command("echo 'subid: sss'  "
                                            ">> /etc/nsswitch.conf")

    def restore():
        """ Restore """
        session_multihost.client[0].run_command("mv -vf  "
                                                "/tmp/subuid_bkp "
                                                "/etc/subuid")
        session_multihost.client[0].run_command("mv -vf  "
                                                "/tmp/subgid_bkp "
                                                "/etc/subgid")
        session_multihost.client[0].run_command("mv -vf  "
                                                "/tmp/nsswitch.conf_bkp "
                                                "/etc/nsswitch.conf")
    request.addfinalizer(restore)


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
        useradd = "echo '%s' | ipa user-add --first %s " \
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
            cmd = 'ipa user-del foobar%d' % i
            session_multihost.master[0].run_command(cmd)

    request.addfinalizer(remove_ipa_users)


@pytest.fixture(scope="class")
def reset_password(session_multihost, request):
    """ Reset passwords for users foobar0 to foobar9 """
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
    except subprocess.CalledProcessError:
        pytest.fail("Failed to disable allow_all rule")

    def allow_all_hbac():
        """ Enable allow_all hbac rule """
        allow_all = 'ipa hbacrule-enable allow_all'
        try:
            session_multihost.master[0].run_command(allow_all)
        except subprocess.CalledProcessError:
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
    ipa_client_ip = session_multihost.client[0].ip
    ipa_server_uuid = ipa_server.get_default_nw_uuid()
    ipa_server_ip = ipa_server.get_interface_ip(ipa_server_uuid)
    sssd_client.update_resolv_conf(ipa_server_ip)
    options = "--ip-address=%s --hostname %s "\
              "--server %s --domain %s "\
              "--realm %s -w %s -p %s -U --mkhomedir" % (ipa_client_ip,
                                                         client_hostname,
                                                         server_hostname,
                                                         "testrealm.test",
                                                         "TESTREALM.TEST",
                                                         "Secret123",
                                                         "admin")
    client_install_cmd = "ipa-client-install %s" % options
    try:
        session_multihost.client[0].run_command(client_install_cmd)
    except subprocess.CalledProcessError:
        pytest.fail("ipa client install failed")

    def teardown_session():
        """ Uninstall ipa client from server """
        client_uninstall_cmd = 'ipa-client-install --uninstall -U'
        session_multihost.client[0].run_command(client_uninstall_cmd)
    request.addfinalizer(teardown_session)
