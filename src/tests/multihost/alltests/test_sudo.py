"""Automation tests for sudo

:requirement: sudo
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import time
import datetime
import re
import ldap
import pytest
from pexpect import pxssh
from sssd.testlib.common.expectsudo import pexpect_ssh
from sssd.testlib.common.exceptions import LdapException
from sssd.testlib.common.utils import SSHClient, LdapOperations
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name, ds_suffix, ou_name, sudo_ou, \
    ds_rootdn, ds_rootpw, user1, user1_password, sudo_command_echo, \
    sudo_rule_test, sudo_host, sudo_command, sudo_user, sudo_rule_test1, \
    sudo_rule_test2, sudo_rule_defaults, smart_interval, group_user1, \
    sudo_command_group, netgroups_ou, user2, ldapusers1, \
    sudo_command_bin_true, sudo_command_bin_echo, netgroup_client, \
    netgroup_client_not, sudo_command_dev_null, sudo_password, \
    sudo_test_user_dn, sudo_test_user_attrs, sudo_tuser_attrs, \
    sudo_tuser_dn, sudo_rule_testrule, sudo_test_user2_attrs, \
    sudo_test_user2_dn, sudo_testuser_attrs, sudo_testuser_dn, \
    sudo_tuser1_attrs, sudo_tuser1_dn


def full_refresh_init_retry(param_multihost):
    SMART_INTERVAL = 43200
    FULL_INTERVAL = 86400
    RETRY_INTERVAL = 120
    OVERLAP_INTERVAL = 2
    ldap_uri = f"ldap://{param_multihost.master[0].sys_hostname}"
    tools = sssdTools(param_multihost.client[0])
    tools.backup_sssd_conf()
    ssh = pexpect_ssh(param_multihost.client[0].sys_hostname,
                      username=user1,
                      password=user1_password,
                      enable_sync_original_prompt=False,
                      enable_auto_prompt_reset=False)
    SYSCTL_ORIG = param_multihost.client[0].run_command(r"sysctl -a | grep "
                                                        r"'^net\.ipv6\.conf"
                                                        r"\.[^.]\+.accept_\("
                                                        r"ra\|dad\) *=' | "
                                                        r"grep -v '\.\(all"
                                                        r"\|default\|lo\)\.'"
                                                        r" | tr -d ' ' | "
                                                        r"awk '{print}' "
                                                        r"ORS=' '")
    try:
        SYSCTL_MOD = param_multihost.client[0].run_command(r"sysctl -a | "
                                                           r"grep '^net\."
                                                           r"ipv6\.conf\."
                                                           r"[^.]\+.accept_"
                                                           r"\(ra\|dad\) "
                                                           r"*=' | grep -v "
                                                           r"'\.\(all\|defa"
                                                           r"ult\|lo\)\.' |"
                                                           r" tr -d ' ' | "
                                                           r"exec sed -e "
                                                           r"'s/=.*/=0/' "
                                                           r"| awk '{print}'"
                                                           r" ORS=' '")
        param_multihost.client[0].run_command(f"sysctl -q -w "
                                              f"{SYSCTL_MOD.stdout_text}")
        time.sleep(5)
        # insert rule to break sssd link
        client_sssd_break_link(param_multihost)
        # sssd config
        domain_section = f"domain/{ds_instance_name}"
        params = {"ldap_sudo_search_base": sudo_ou,
                  "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                  "entry_cache_nowait_percentage": "0",
                  "entry_cache_timeout": "0",
                  "ldap_sudo_smart_refresh_interval": SMART_INTERVAL,
                  "ldap_sudo_full_refresh_interval": FULL_INTERVAL}
        tools.sssd_conf(domain_section, params, action="update")
        param_multihost.client[0].service_sssd("restart")
        # restore link
        client_sssd_restore_link(param_multihost)
        time.sleep((OVERLAP_INTERVAL + RETRY_INTERVAL) / 2)
        time.sleep(RETRY_INTERVAL / 2)
        param_multihost.client[0].run_command(f"ldbsearch -H /var/lib/sss/db/"
                                              f"cache_{ds_instance_name}.ldb"
                                              f" name=test sudoRunAsUser | "
                                              f"grep ALL")
        (stdout, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                          user1_password)
        assert exit_code == 0
    finally:
        # exit teardown
        param_multihost.client[0].run_command(f"sysctl -q -w "
                                              f"{SYSCTL_ORIG.stdout_text}")
        tools.restore_sssd_conf()
        tools.clear_sssd_cache(start=True)


def client_sssd_break_link(param_multihost):
    server = param_multihost.master[0].ip
    iptables_insert_cmd = f"iptables --insert OUTPUT --destination " \
                          f"{server} --protocol tcp --destination-port " \
                          f"ldaps --jump REJECT --reject-with " \
                          f"icmp-host-unreachable"
    param_multihost.client[0].run_command(iptables_insert_cmd)
    status = param_multihost.client[0].run_command(f"nc -zvw10 {server} 636",
                                                   raiseonerr=False)
    assert status.returncode == 1, "sssd link break unsuccessful"


def client_sssd_restore_link(param_multihost):
    server = param_multihost.master[0].ip
    iptables_delete_cmd = f"iptables --delete OUTPUT --destination " \
                          f"{server} --protocol tcp --destination-port " \
                          f"ldaps --jump REJECT --reject-with " \
                          f"icmp-host-unreachable"
    param_multihost.client[0].run_command(iptables_delete_cmd)
    param_multihost.client[0].run_command(f"nc -zvw10 {server} 636")


def modify_attribute(ldap_obj: LdapOperations, rule_dn, modify_type,
                     attribute_name, attribute_value):
    replace_attr = [(modify_type, attribute_name,
                     attribute_value.encode('utf-8'))]
    (return_status, _) = ldap_obj.modify_ldap(rule_dn, replace_attr)
    assert return_status == "Success"


def add_sudo_rule(ldap_obj: LdapOperations, rule_dn, sudoHost, sudoCommand,
                  sudoUser, sudo_option=None, sudo_extra=None):
    if sudo_extra is None:
        sudo_extra = {}
    try:
        ldap_obj.add_sudo_rule(rule_dn, sudoHost, sudoCommand,
                               sudoUser, sudo_option)
    except LdapException:
        pytest.fail(f"Failed to add sudo rule {rule_dn}")
    else:
        if len(sudo_extra) > 0:
            for key in sudo_extra.keys():
                add_attr = [(ldap.MOD_ADD, key,
                             sudo_extra[key].encode('utf-8'))]
                (ret_status, _) = ldap_obj.modify_ldap(rule_dn, add_attr)
                assert ret_status == "Success"


def del_sudo_rule(ldap_obj: LdapOperations, dn):
    try:
        (ret, _) = ldap_obj.del_dn(dn)
    except LdapException:
        pytest.fail(f"{dn} doesn't exist or failed to delete {dn}")
    else:
        assert ret == "Success"


def add_sudoers_ou(ldap_obj: LdapOperations):
    try:
        ldap_obj.org_unit(ou_name, ds_suffix)
    except LdapException:
        pytest.fail("already exist or failed to add sudo ou ")


def del_sudoers_ou(ldap_obj: LdapOperations):
    try:
        (ret, _) = ldap_obj.del_dn(sudo_ou)
    except LdapException:
        pytest.fail("sudoers ou doesn't exist or failed to delete ou")
    else:
        assert ret == "Success"


def perform_sudo_command(param_multihost, user=user1,
                         user_password=user1_password,
                         command=sudo_command_echo):
    try:
        ssh = SSHClient(param_multihost.client[0].sys_hostname,
                        username=user, password=user_password)
    except paramiko.ssh_exception.AuthenticationException:
        pytest.fail(f"failed to login as {user}")
    else:
        (std_out, std_err, exit_status) = ssh.execute_cmd(command)
        ssh.close()
        return std_out, std_err, exit_status


def add_group(ldap_obj: LdapOperations, group_cn, gid_number,
              unique_member=None, add_unique_members=True,
              memberUid=None):
    if unique_member is not None:
        group_info = {"cn": group_cn,
                      "gidNumber": gid_number,
                      "uniqueMember": unique_member}
        try:
            ldap_obj.posix_group("ou=Groups", ds_suffix,
                                 group_info)
        except LdapException:
            assert False
    elif memberUid is not None:
        group_info = {"cn": group_cn,
                      "gidNumber": gid_number,
                      "memberUid": memberUid}
        try:
            ldap_obj.posix_group("ou=Groups", ds_suffix,
                                 group_info, memberUid=True)
        except LdapException:
            assert False
    else:
        default_unique_member = f"uid=foo0,ou=People,{ds_suffix}"
        group_info = {"cn": group_cn,
                      "gidNumber": gid_number,
                      "uniqueMember": default_unique_member}
        try:
            ldap_obj.posix_group("ou=Groups", ds_suffix,
                                 group_info)
        except LdapException:
            assert False
    group_dn = f"cn={group_cn},ou=Groups,{ds_suffix}"
    if add_unique_members:
        for i in range(1, 10):
            user_dn = f"uid=foo{i},ou=People,{ds_suffix}"
            add_member = [(ldap.MOD_ADD, "uniqueMember",
                           user_dn.encode('utf-8'))]
            (ret, _) = ldap_obj.modify_ldap(group_dn, add_member)
            assert ret == "Success"


def del_group(ldap_obj: LdapOperations, group_cn):
    group_dn = f"cn={group_cn},ou=Groups,{ds_suffix}"
    (ret, _) = ldap_obj.del_dn(group_dn)
    assert ret == "Success"


def add_netgroup_ou(ldap_obj: LdapOperations):
    try:
        ldap_obj.org_unit("Netgroups", ds_suffix)
    except LdapException:
        pytest.fail("already exist or failed to add Netgroups ou ")


def del_netgroup_ou(ldap_obj: LdapOperations):
    (ret, _) = ldap_obj.del_dn(netgroups_ou)
    assert ret == "Success"


def add_netgroup(ldap_obj: LdapOperations, netgroup_dn, nisNetgroupTriple):
    try:
        ldap_obj.create_netgroup(netgroup_dn, nisNetgroupTriple)
    except LdapException:
        pytest.fail(f"failed to add netgroup {netgroup_dn}")


def del_netgroup(ldap_obj: LdapOperations, netgroup_dn):
    (ret, _) = ldap_obj.del_dn(netgroup_dn)
    assert ret == "Success"


def load_filter_conf(param_multihost, sssdtools: sssdTools,
                     host_filter_value, field=None, field_value=None):
    if field is None or field_value is None:
        filter_params = {"ldap_sudo_use_host_filter": host_filter_value}
        filter_section = f"domain/{ds_instance_name}"
        sssdtools.sssd_conf(filter_section, filter_params, action="update")
        param_multihost.client[0].service_sssd("restart")
    else:
        filter_params = {"ldap_sudo_use_host_filter": host_filter_value,
                         "ldap_sudo_" + field: field_value}
        filter_section = f"domain/{ds_instance_name}"
        sssdtools.sssd_conf(filter_section, filter_params, action="update")
        param_multihost.client[0].service_sssd("restart")


def stress_attr(param_multihost, ldap_obj: LdapOperations, attr_suffix,
                value1, wait1, predicate1, value2, wait2, predicate2):
    status = 0
    ssh = pexpect_ssh(param_multihost.client[0].sys_hostname,
                      username=user1,
                      password=user1_password,
                      enable_sync_original_prompt=False,
                      enable_auto_prompt_reset=False)
    extra_attributes = {"sudoRunAsUser": "ALL", "sudoRunAsGroup": "ALL"}

    def user_is_denied():
        (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                    user1_password)
        return exit_code

    def user_is_allowed():
        (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                     user1_password)
        return exit_code

    def group_is_denied():
        (_, exit_code) = ssh.sudo_permission_denied(sudo_command_group,
                                                    user1_password)
        return exit_code

    def group_is_allowed():
        (_, exit_code) = ssh.sudo_permission_granted(sudo_command_group,
                                                     user1_password)
        return exit_code

    def user_requires_auth():
        (_, exit_code) = ssh.sudo_requires_auth(sudo_command_echo,
                                                user1_password)
        return exit_code

    def user_is_allowed_no_prompt():
        (_, _, exit_status) = perform_sudo_command(param_multihost)
        return exit_status

    def default():
        raise Exception("Incorrect key passed in dictionary")

    switcher = {"user_is_denied": user_is_denied,
                "user_is_allowed": user_is_allowed,
                "group_is_denied": group_is_denied,
                "group_is_allowed": group_is_allowed,
                "user_requires_auth": user_requires_auth,
                "user_is_allowed_no_prompt": user_is_allowed_no_prompt}
    for i in range(0, 5):
        modify_attribute(ldap_obj, sudo_rule_test, ldap.MOD_REPLACE,
                         "sudo" + attr_suffix, value1)
        time.sleep(wait1)
        if switcher.get(predicate1, default)() == 1:
            status = 1
            break
        modify_attribute(ldap_obj, sudo_rule_test, ldap.MOD_REPLACE,
                         "sudo" + attr_suffix, value2)
        time.sleep(wait2)
        if switcher.get(predicate2, default)() == 1:
            status = 1
            break
    del_sudo_rule(ldap_obj, sudo_rule_test)
    add_sudo_rule(ldap_obj, sudo_rule_test, sudo_host, sudo_command,
                  sudo_user, sudo_extra=extra_attributes)
    time.sleep(3)
    return status


def attr_empty(param_multihost, ldap_obj: LdapOperations, attr_suffix,
               refresh_wait, sudo_target):
    status = 0
    ssh = pexpect_ssh(param_multihost.client[0].sys_hostname,
                      username=user1,
                      password=user1_password,
                      enable_sync_original_prompt=False,
                      enable_auto_prompt_reset=False)

    def user_is_denied():
        (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                    user1_password)
        return exit_code

    def group_is_denied():
        (_, exit_code) = ssh.sudo_permission_denied(sudo_command_group,
                                                    user1_password)
        return exit_code

    def default():
        raise Exception("Incorrect key passed in dictionary")

    switcher = {"user": user_is_denied,
                "group": group_is_denied}
    modify_attribute(ldap_obj, sudo_rule_test, ldap.MOD_REPLACE, "sudo" +
                     attr_suffix, "")
    time.sleep(refresh_wait)
    if switcher.get(sudo_target, default)() == 1:
        status = 1
    return status


def attr_values(param_multihost, ldap_obj: LdapOperations, attr_suffix,
                refresh_wait, sudo_target, test_list: list):
    status = 0
    ssh = pexpect_ssh(param_multihost.client[0].sys_hostname,
                      username=user1,
                      password=user1_password,
                      enable_sync_original_prompt=False,
                      enable_auto_prompt_reset=False)

    def user_allowed():
        (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                     user1_password)
        return exit_code

    def user_denied():
        (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                    user1_password)
        return exit_code

    def group_allowed():
        (_, exit_code) = ssh.sudo_permission_granted(sudo_command_group,
                                                     user1_password)
        return exit_code

    def group_denied():
        (_, exit_code) = ssh.sudo_permission_denied(sudo_command_group,
                                                    user1_password)
        return exit_code

    def default():
        raise Exception("Incorrect key passed in dictionary")

    switcher = {"user_allowed": user_allowed,
                "user_denied": user_denied,
                "group_allowed": group_allowed,
                "group_denied": group_denied}
    for line in test_list:
        value = line.split(" ")[0]
        outcome = line.split(" ")[1]
        modify_attribute(ldap_obj, sudo_rule_test, ldap.MOD_REPLACE,
                         "sudo" + attr_suffix, value)
        time.sleep(refresh_wait)
        if switcher.get(sudo_target + "_" + outcome, default)() == 1:
            status = 1
            break
    return status


def future_time(seconds: int):
    seconds_added = datetime.datetime.now() + datetime.timedelta(0, seconds)
    return seconds_added.astimezone().strftime('%Y%m%d%H%M%S%z')


def add_large_user_groups(ldap_obj: LdapOperations, start: int, end: int):
    for i in range(start, end):
        number = str(i)
        # admin
        admin_dn = f"cn=admin{number},ou=Groups,{ds_suffix}"
        admin_attrs = {
            'gidNumber': '100'.encode('utf-8') + number.encode('utf-8'),
            'objectClass': [b'top', b'extensibleObject', b'groupOfNames'],
            'cn': 'admin'.encode('utf-8') + number.encode('utf-8'),
            'member': f'uid=sudo_test_user,{ds_suffix}'.encode('utf-8')}
        ldap_obj.add_entry(admin_attrs, admin_dn)
        # facilities
        facilities_dn = f"cn=facilities{number},ou=Groups,{ds_suffix}"
        facilities_attrs = {
            'gidNumber': '101'.encode('utf-8') + number.encode('utf-8'),
            'objectClass': [b'top', b'extensibleObject', b'groupOfNames'],
            'cn': 'facilities'.encode('utf-8') + number.encode('utf-8'),
            'member': f'uid=sudo_test_user,{ds_suffix}'.encode('utf-8')}
        ldap_obj.add_entry(facilities_attrs, facilities_dn)
        # hr
        hr_dn = f"cn=hr{number},ou=Groups,{ds_suffix}"
        hr_attrs = {
            'gidNumber': '102'.encode('utf-8') + number.encode('utf-8'),
            'objectClass': [b'top', b'extensibleObject', b'groupOfNames'],
            'cn': 'hr'.encode('utf-8') + number.encode('utf-8'),
            'member': f'uid=sudo_test_user,{ds_suffix}'.encode('utf-8')}
        ldap_obj.add_entry(hr_attrs, hr_dn)


def del_large_user_groups(ldap_obj: LdapOperations, start: int, end: int):
    for i in range(start, end):
        number = str(i)
        (admin_ret, _) = ldap_obj.del_dn(f"cn=admin{number},ou=Groups,"
                                         f"{ds_suffix}")
        (facilities_ret, _) = ldap_obj.del_dn(f"cn=facilities{number},"
                                              f"ou=Groups,{ds_suffix}")
        (hr_ret, _) = ldap_obj.del_dn(f"cn=hr{number},ou=Groups,{ds_suffix}")
        assert admin_ret == "Success"
        assert facilities_ret == "Success"
        assert hr_ret == "Success"


def add_large_sudo_rules(ldap_obj: LdapOperations, start: int, end: int):
    for i in range(start, end):
        number = str(i)
        # admin
        admin_attrs = {
            'objectClass': [b'top', b'sudoRole'],
            'cn': 'admin_rule'.encode('utf-8') + number.encode('utf-8'),
            'sudoUser': r'%admin'.encode('utf-8') + number.encode('utf-8'),
            'sudoHost': 'ALL'.encode('utf-8'),
            'sudoCommand': '/sbin/accton, /sbin/addpart, /sbin/agetty,'
                           ' /sbin/arp, /sbin/arping, /sbin/audispd,'
                           ' /sbin/auditctl, /sbin/auditd, /sbin/aureport,'
                           ' /sbin/ausearch, /sbin/autrace,'
                           ' /sbin/badblocks, /sbin/biosdevname,'
                           ' /sbin/blkdeactivate, /sbin/blkid,'
                           ' /sbin/blockdev, /sbin/busybox, /sbin/cbq,'
                           ' /sbin/cfdisk, /sbin/chcpu, /sbin/chkconfig,'
                           ' /sbin/clock, /sbin/consoletype, /sbin/crda,'
                           ' /sbin/cryptsetup, /sbin/ctrlaltdel,'
                           ' /sbin/debugfs, /sbin/delpart, /sbin/depmod,'
                           ' /sbin/dhclient, /sbin/dhclient-script,'
                           ' /sbin/dm_dso_reg_tool,'
                           ' /sbin/dmeventd'.encode('utf-8')
        }
        admin_dn = f"cn=admin_rule{number},ou=sudoers,{ds_suffix}"
        ldap_obj.add_entry(admin_attrs, admin_dn)
        # facilities
        facilities_attrs = {
            'objectClass': [b'top', b'sudoRole'],
            'cn': 'facilities_rule'.encode('utf-8') +
                  number.encode('utf-8'),
            'sudoUser': r'%facilities'.encode('utf-8') +
                        number.encode('utf-8'),
            'sudoHost': 'ALL'.encode('utf-8'),
            'sudoCommand': '/sbin/dmraid, /sbin/dmraid.static,'
                           ' /sbin/dmsetup, /sbin/dosfsck,'
                           ' /sbin/dosfslabel, /sbin/dracut,'
                           ' /sbin/dumpe2fs, /sbin/e2fsck, /sbin/e2image,'
                           ' /sbin/e2label, /sbin/e2undo, /sbin/ether-wake,'
                           ' /sbin/ethtool, /sbin/faillock, /sbin/fdisk,'
                           ' /sbin/findfs, /sbin/fixfiles, /sbin/fsadm,'
                           ' /sbin/fsck, /sbin/fsck.cramfs, /sbin/fsck.ext2,'
                           ' /sbin/fsck.ext3, /sbin/fsck.ext4,'
                           ' /sbin/fsck.ext4dev, /sbin/fsck.msdos,'
                           ' /sbin/fsck.vfat, /sbin/fsfreeze,'
                           ' /sbin/fstab-decode, /sbin/fstrim, /sbin/fuser,'
                           ' /sbin/genhostid, /sbin/getkey,'
                           ' /sbin/grub'.encode('utf-8')
        }
        facilities_dn = f"cn=facilities_rule{number},ou=sudoers,{ds_suffix}"
        ldap_obj.add_entry(facilities_attrs, facilities_dn)
        # hr
        hr_attrs = {
            'objectClass': [b'top', b'sudoRole'],
            'cn': 'hr_rule'.encode('utf-8') + number.encode('utf-8'),
            'sudoUser': r'%hr'.encode('utf-8') + number.encode('utf-8'),
            'sudoHost': 'ALL'.encode('utf-8'),
            'sudoCommand': '/sbin/route, /sbin/ifconfig, /bin/ping,'
                           ' /sbin/dhclient, /usr/bin/net, /sbin/iptables,'
                           ' /usr/bin/rfcomm, /usr/bin/wvdial,'
                           ' /sbin/iwconfig, /sbin/mii-tool, /bin/rpm,'
                           ' /usr/bin/up2date, /usr/bin/yum, /sbin/service,'
                           ' /sbin/chkconfig, /sbin/fdisk, /sbin/sfdisk,'
                           ' /sbin/parted, /sbin/partprobe, /bin/mount,'
                           ' /bin/umount, /usr/sbin/visudo, /bin/chown,'
                           ' /bin/chmod, /bin/chgrp, /bin/nice, /bin/kill,'
                           ' /usr/bin/kill, /usr/bin/killall'.encode('utf-8')
        }
        hr_dn = f"cn=hr_rule{number},ou=sudoers,{ds_suffix}"
        ldap_obj.add_entry(hr_attrs, hr_dn)


def del_large_sudo_rules(ldap_obj: LdapOperations, start: int, end: int):
    for i in range(start, end):
        number = str(i)
        (admin_rule_ret, _) = ldap_obj.del_dn(f"cn=admin_rule{number},"
                                              f"ou=sudoers,{ds_suffix}")
        (facilities_rule_ret, _) = ldap_obj.del_dn(f"cn=facilities_rule"
                                                   f"{number},"
                                                   f"ou=sudoers,{ds_suffix}")
        (hr_rule_ret, _) = ldap_obj.del_dn(f"cn=hr_rule{number},"
                                           f"ou=sudoers,{ds_suffix}")
        assert admin_rule_ret == "Success"
        assert facilities_rule_ret == "Success"
        assert hr_rule_ret == "Success"


def add_user(ldap_obj: LdapOperations, attrs: dict, user_dn):
    comman_name = attrs['cn']
    uid_number = attrs['uidNumber']
    gid_number = attrs['gidNumber']
    try:
        login_shell = attrs['loginShell']
    except KeyError:
        login_shell = '/bin/bash'
    try:
        user_password = attrs['userPassword']
    except KeyError:
        user_password = 'Secret123'
    try:
        home_directory = attrs['homeDirectory']
    except KeyError:
        home_directory = f"/home/{user_dn.split(',')[0].split('=')[1]}"
    try:
        gecos = attrs['gecos']
    except KeyError:
        gecos = '%s User' % comman_name
    user_attrs = {
        'objectClass': [b'Account', b'posixAccount', b'extensibleObject'],
        'cn': comman_name.encode('utf-8'),
        'uidNumber': uid_number.encode('utf-8'),
        'gidNumber': gid_number.encode('utf-8'),
        'gecos': gecos.encode('utf-8'),
        'homeDirectory': home_directory.encode('utf-8'),
        'loginShell': login_shell.encode('utf-8'),
        'userPassword': user_password.encode('utf-8')
    }
    ldap_obj.add_entry(user_attrs, user_dn)


def del_user(ldap_obj: LdapOperations, user_dn):
    (del_user_ret, _) = ldap_obj.del_dn(user_dn)
    assert del_user_ret == "Success"


def add_500_sudo_rules(ldap_obj: LdapOperations, sudouser, sudohost,
                       sudocommand):
    for i in range(1, 501):
        number = str(i)
        rule_attrs = {
            'objectClass': [b'top', b'sudoRole'],
            'cn': 'rule_'.encode('utf-8') + number.encode('utf-8'),
            'sudoUser': sudouser.encode('utf-8'),
            'sudoHost': sudohost.encode('utf-8'),
            'sudoCommand': sudocommand.encode('utf-8')
        }
        rule_dn = f"cn=rule_{number},ou=sudoers,{ds_suffix}"
        ldap_obj.add_entry(rule_attrs, rule_dn)


def del_500_sudo_rules(ldap_obj: LdapOperations):
    for i in range(1, 501):
        number = str(i)
        (rule_ret, _) = ldap_obj.del_dn(f"cn=rule_{number},ou=sudoers,"
                                        f"{ds_suffix}")
        assert rule_ret == "Success"


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'enable_sss_sudo_nsswitch')
@pytest.mark.sudo
class TestSudo(object):
    """ Sudo test suite """

    @staticmethod
    @pytest.mark.usefixtures('backupsssdconf')
    @pytest.mark.tier1_2
    def test_bz1294670(multihost, localusers):
        """
        :title: sudo: Local users with local sudo rules causes LDAP queries
        :id: e8c5c396-e5e5-4eff-84f8-feff01defda1
        """
        # enable sudo with authselect
        authselect_cmd = 'authselect select sssd with-sudo'
        multihost.client[0].run_command(authselect_cmd)

        # stop sssd service
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db/')
        ldap_uri = 'ldap://%s' % multihost.master[0].sys_hostname
        sssd_params = {'services': 'nss, pam, sudo'}
        tools.sssd_conf('sssd', sssd_params)
        ldap_params = {'ldap_uri': ldap_uri}
        tools.sssd_conf('domain/%s' % (ds_instance_name), ldap_params)
        multihost.client[0].service_sssd('restart')
        sudo_pcapfile = '/tmp/bz1294670.pcap'
        ldap_host = multihost.master[0].sys_hostname
        tcpdump_cmd = 'tcpdump -s0 host %s -w %s' % (ldap_host, sudo_pcapfile)
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        for user in localusers.keys():
            add_rule1 = "echo '%s  ALL=(ALL) NOPASSWD:ALL,!/bin/sh'"\
                        " >> /etc/sudoers.d/%s" % (user, user)
            multihost.client[0].run_command(add_rule1)
            add_rule2 = "echo 'Defaults:%s !requiretty'"\
                        " >> /etc/sudoers.d/%s" % (user, user)
            multihost.client[0].run_command(add_rule2)

            ssh = pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                                       "UserKnownHostsFile": "/dev/null"})
            ssh.force_password = True
            try:
                ssh.login(multihost.client[0].sys_hostname, user, 'Secret123')
                for _ in range(1, 10):
                    ssh.sendline('sudo fdisk -l')
                    ssh.prompt(timeout=5)
                    ssh.sendline('sudo ls -l /usr/sbin/')
                    ssh.prompt(timeout=5)
                ssh.logout()
            except pxssh.ExceptionPxssh:
                pytest.fail(f"Authentication Failed as user {user}")
        pkill = 'pkill tcpdump'
        multihost.client[0].run_command(pkill)
        for user in localusers.keys():
            rm_sudo_rule = "rm -f /etc/sudoers.d/%s" % (user)
            multihost.client[0].run_command(rm_sudo_rule)
        tshark_cmd = 'tshark -r %s -R ldap.filter -V -2' % sudo_pcapfile
        cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
        print("output = ", cmd.stderr_text)
        assert cmd.returncode == 0
        rm_pcap_file = 'rm -f %s' % sudo_pcapfile
        multihost.client[0].run_command(rm_pcap_file)

    @staticmethod
    @pytest.mark.usefixtures('backupsssdconf')
    @pytest.mark.tier2
    def test_timed_sudoers_entry(multihost, timed_sudoers):
        """
        :title: sudo: sssd accepts timed entries without minutes and or
         seconds to attribute
        :id: 5103a796-6c7f-4af0-b7b8-64c7338f0934
        """
        # pylint: disable=unused-argument
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db/')
        sudo_base = 'ou=sudoers,dc=example,dc=test'
        sudo_uri = "ldap://%s" % multihost.master[0].sys_hostname
        params = {'ldap_sudo_search_base': sudo_base,
                  'ldap_uri': sudo_uri, 'sudo_provider': "ldap"}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, params, action='update')
        section = "sssd"
        sssd_params = {'services': 'nss, pam, sudo'}
        tools.sssd_conf(section, sssd_params, action='update')
        multihost.client[0].service_sssd('start')

        ssh = pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                          "UserKnownHostsFile": "/dev/null"})
        ssh.force_password = True
        try:
            ssh.login(multihost.client[0].sys_hostname,
                      'foo1@example.test', 'Secret123')
            ssh.sendline('id')
            ssh.prompt(timeout=5)
            id_out = str(ssh.before)
            ssh.sendline('sudo -l')
            ssh.prompt(timeout=5)
            sudo_out = str(ssh.before)
            ssh.logout()
        except pxssh.ExceptionPxssh:
            pytest.fail("Failed to login via ssh.")
        assert 'foo1' in id_out, "id command did not work."
        assert 'NOTBEFORE=' in sudo_out or 'NOTAFTER=' in sudo_out,\
            "Expected sudo rule not found!"
        # Make sure that the rule validity time works without minutes
        # and seconds 0000Z is at the end of the NOTAFTER part of rule
        rule_time = re.search(
            r"(NOTBEFORE|NOTAFTER)=[0-9]{10}0000Z NOPASSWD: /usr/bin/head",
            sudo_out)
        if not rule_time:
            journalctl_cmd = 'journalctl -x -n 100 --no-pager'
            multihost.master[0].run_command(journalctl_cmd)
            pytest.fail("sudo -l cmd failed for user foo1")

    @staticmethod
    @pytest.mark.usefixtures('backupsssdconf', 'sudo_rule')
    @pytest.mark.tier2
    def test_randomize_sudo_timeout(multihost):
        """
        :title: sudo: randomize sudo refresh timeouts
        :id: 57720975-29ba-4ed7-868a-f9b784bbfed2
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1925514
        :customerscenario: True
        :steps:
          1. Edit sssdconfig and specify sssd smart, full timeout option
          2. Restart sssd with cleared logs and cache
          3. Wait for 120 seconds
          4. Parse logs and confirm sudo refresh timeouts are random
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        sudo_base = 'ou=sudoers,%s' % (ds_suffix)
        sudo_uri = "ldap://%s" % multihost.master[0].sys_hostname
        params = {'ldap_sudo_search_base': sudo_base,
                  'ldap_uri': sudo_uri,
                  'sudo_provider': "ldap",
                  'ldap_sudo_full_refresh_interval': '25',
                  'ldap_sudo_smart_refresh_interval': '15',
                  'ldap_sudo_random_offset': '5'}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, params, action='update')
        section = "sssd"
        sssd_params = {'services': 'nss, pam, sudo'}
        tools.sssd_conf(section, sssd_params, action='update')
        multihost.client[0].service_sssd('start')
        time.sleep(120)
        logfile = '/var/log/sssd/sssd_%s.log' % ds_instance_name
        tmout_ptrn = r"(SUDO.*\:\sscheduling task \d+ seconds)"
        regex_tmout = re.compile("%s" % tmout_ptrn)
        smart_tmout = []
        full_tmout = []
        log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
        for line in log.split('\n'):
            if line:
                if regex_tmout.findall(line):
                    rfrsh_type = regex_tmout.findall(line)[0].split()[1]
                    timeout = regex_tmout.findall(line)[0].split()[5]
                    if rfrsh_type == 'Smart':
                        smart_tmout.append(timeout)
                    elif rfrsh_type == 'Full':
                        full_tmout.append(timeout)
        rand_intvl, same_intvl = 0, 0
        for timeout in smart_tmout, full_tmout:
            index = 1
            rand_intvl, same_intvl = 0, 0
            while index < len(timeout):
                if timeout[index] != timeout[index - 1]:
                    rand_intvl += 1
                else:
                    same_intvl += 1
                index += 1
            assert rand_intvl > same_intvl

    @staticmethod
    @pytest.mark.usefixtures('backupsssdconf', 'sudo_rule', 'sssd_sudo_conf')
    @pytest.mark.tier2
    def test_improve_refresh_timers_sudo_timeout(multihost):
        """
        :title: sudo: improve sudo full and smart refresh timeouts
        :id: 3860d1b9-28fc-4d44-9537-caf28ab033c8
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1925505
        :customerscenario: True
        :steps:
          1. Edit sssdconfig and specify sssd smart, full timeout option
          2. Restart sssd with cleared logs and cache
          3. Wait for 40 seconds
          4. Parse logs and confirm sudo full refresh and smart refresh
             timeout are not running at same time
          5. If sudo full refresh and smart refresh timer are scheduled at
             same time then smart refresh is rescheduled to the next cycle
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        params = {'ldap_sudo_full_refresh_interval': '10',
                  'ldap_sudo_random_offset': '0',
                  'ldap_sudo_smart_refresh_interval': '5'}
        domain_section = f'domain/{ds_instance_name}'
        tools.sssd_conf(domain_section, params, action='update')
        multihost.client[0].service_sssd('start')
        time.sleep(40)
        logfile = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        tmout_ptrn = '(SUDO.*Refresh.*executing)'
        rschdl_ptrn = '(SUDO.*Refresh.*rescheduling)'
        regex_tmout = re.compile(f'{tmout_ptrn}')
        rgx_rs_tstmp = re.compile(f'{rschdl_ptrn}')
        full_rfsh_tstmp = []
        smrt_rfsh_tstmp = []
        rschdl_tstmp = []
        log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
        for line in log.split('\n'):
            if regex_tmout.findall(line):
                dt_time = line.split('):')[0]
                tstmp = dt_time.split()[1]
                ref_type = line.split()[7]
                if ref_type == 'Smart':
                    smrt_rfsh_tstmp.append(tstmp)
                elif ref_type == 'Full':
                    full_rfsh_tstmp.append(tstmp)
            if rgx_rs_tstmp.findall(line):
                dt_time = line.split('):')[0]
                tstmp = dt_time.split()[1]
                rschdl_tstmp.append(tstmp)
        for tm_stamp in full_rfsh_tstmp:
            if tm_stamp in smrt_rfsh_tstmp:
                assert tm_stamp in rschdl_tstmp
            else:
                assert tm_stamp not in smrt_rfsh_tstmp

    @pytest.mark.tier2
    def test_defaults(self, multihost, backupsssdconf):
        """
        :title: sudo: Test with and without 'sudoOption: !authenticate'
         in sudo rule.
        :description: Check sudo with rule 'test' without
         'sudoOption: !authenticate' and then again check
         sudo by adding rule that has 'sudoOption: !authenticate'.
        :id: a759ebd6-a31e-4bf5-874e-98e2f9a81572
        :customerscenario: False
        :steps:
            1. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout and ldap_sudo_smart_refresh_interval.
            2. Restart SSSD with cleared logs and cache.
            3. Add a sudo rule and test if password prompt is given when
               sudo command is ran.
            4. Add a sudo rule with sudoOption: !authenticate and test
               if sudo is allowed to run without password prompt.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
        """
        refresh_wait = 2
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        ssh = pexpect_ssh(multihost.client[0].sys_hostname, username=user1,
                          password=user1_password,
                          enable_sync_original_prompt=False,
                          enable_auto_prompt_reset=False)
        # Load config
        params = {"ldap_sudo_search_base": sudo_ou,
                  "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                  "entry_cache_nowait_percentage": 0,
                  "entry_cache_timeout": 0,
                  "ldap_sudo_smart_refresh_interval": smart_interval}
        domain_section = f"domain/{ds_instance_name}"
        tools.sssd_conf(domain_section, params, action="update")
        section = "sssd"
        sssd_params = {"services": "nss, pam, sudo"}
        tools.sssd_conf(section, sssd_params, action="update")
        multihost.client[0].service_sssd("restart")
        (_, sudo_check1) = ssh.sudo_requires_auth(sudo_command_echo,
                                                  user1_password)
        # add test rule and sudoers ou
        add_sudoers_ou(ldap_server)
        extra_attributes = {"sudoRunAsUser": "ALL"}
        add_sudo_rule(ldap_server, sudo_rule_test, sudo_host, sudo_command,
                      sudo_user, None, extra_attributes)
        time.sleep(refresh_wait)
        (_, sudo_check2) = ssh.sudo_requires_auth(sudo_command_echo,
                                                  user1_password)
        sudo_options = ["!authenticate"]
        # add defaults rule
        add_sudo_rule(ldap_server, sudo_rule_defaults, "", "", "",
                      sudo_options)
        time.sleep(refresh_wait)
        (_, _, sudo_check3) = perform_sudo_command(multihost)
        # teardown
        del_sudo_rule(ldap_server, sudo_rule_test)
        del_sudo_rule(ldap_server, sudo_rule_defaults)
        del_sudoers_ou(ldap_server)
        tools.clear_sssd_cache(start=True)
        # test result evaluation
        assert sudo_check1 == 0, "Authentication is not required " \
                                 "unexpectedly"
        assert sudo_check2 == 0, "Authentication is not required " \
                                 "unexpectedly"
        assert sudo_check3 == 0, "Authentication is required unexpectedly"

    def test_order(self, multihost, backupsssdconf):
        """
        :title: sudo: Test sudo with different orders of sudo rules.
        :description: Add 2 sudo rules, first one with 'sudoOption:
         !authenticate' and second one without it. Change order of
         sudo rules and test sudo command with 2 users.
        :id: ba01961a-c0b2-48b5-97ce-d154eebf74c2
        :customerscenario: False
        :steps:
            1. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout and
               ldap_sudo_smart_refresh_interval.
            2. Restart SSSD with cleared logs and cache
            3. wait 2 seconds
            4. test sudo command with altering sudoOrder
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        refresh_wait = smart_interval + 1
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        # Load low-delay configuration
        params = {"ldap_sudo_search_base": sudo_ou,
                  "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                  "entry_cache_nowait_percentage": 0,
                  "entry_cache_timeout": 0,
                  "ldap_sudo_smart_refresh_interval": smart_interval}
        domain_section = f"domain/{ds_instance_name}"
        tools.sssd_conf(domain_section, params, action="update")
        section = "sssd"
        sssd_params = {"services": "nss, pam, sudo"}
        tools.sssd_conf(section, sssd_params, action="update")
        tools.clear_sssd_cache(start=True)
        try:
            # add sudo rules
            add_sudoers_ou(ldap_server)
            extra_attributes = {"sudoRunAsUser": "ALL"}
            add_sudo_rule(ldap_server, sudo_rule_test1, sudo_host,
                          sudo_command, sudo_user, None,
                          extra_attributes)
            add_sudo_rule(ldap_server, sudo_rule_test2, sudo_host,
                          sudo_command, sudo_user, None,
                          extra_attributes)
            time.sleep(refresh_wait)
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username=user1,
                              password=user1_password)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            modify_attribute(ldap_server, sudo_rule_test1, ldap.MOD_REPLACE,
                             "sudoOrder", "0")
            modify_attribute(ldap_server, sudo_rule_test2, ldap.MOD_REPLACE,
                             "sudoOrder", "0")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when order is " \
                                   "set to allow both sudo rules"
            modify_attribute(ldap_server, sudo_rule_test2, ldap.MOD_REPLACE,
                             "sudoCommand", "!ALL")
            modify_attribute(ldap_server, sudo_rule_test1, ldap.MOD_REPLACE,
                             "sudoOrder", "0")
            modify_attribute(ldap_server, sudo_rule_test2, ldap.MOD_REPLACE,
                             "sudoOrder", "1")
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted unexpectedly, " \
                                   "order is not set to allow second sudo rule"
            modify_attribute(ldap_server, sudo_rule_test1, ldap.MOD_REPLACE,
                             "sudoOrder", "1")
            modify_attribute(ldap_server, sudo_rule_test2, ldap.MOD_REPLACE,
                             "sudoOrder", "0")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly, " \
                                   "order is set to allow first sudo rule"
        finally:
            # teardown
            del_sudo_rule(ldap_server, sudo_rule_test1)
            del_sudo_rule(ldap_server, sudo_rule_test2)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_offline(self, multihost, backupsssdconf):
        """
        :title: sudo: Test sudo rule works in offline mode.
        :description: Add a sudo rule that authenticates user to perform sudo
         then go offline by adding a jump rule in iptables and testing user
         again to confirm that user is able to sudo with cached credentials
         then making change to sudoCommand : !ALL to check if user is denied
         and then constantly make calls to SSSD to come online and then
         verify it.
        :id: 2b9dd8ac-5084-49a8-8d33-b785a509fcb9
        :customerscenario: False
        :steps:
            1. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout.
            2. Add sudo rule named "test".
            3. Add rule to iptables to break SSSD link.
            4. Check user sudo access with cached credentials.
            5. wait 95 seconds.
            6. Test sudo command with altered sudoCommand.
            7. Make sure SSSD didn't quit.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
        """
        multihost.client[0].run_command("dnf install nmap-ncat -y")
        offline_timeout = 90
        online_wait = offline_timeout + 5
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        try:
            # Add the rule
            add_sudoers_ou(ldap_server)
            extra_attribute = {"sudoRunAsUser": "ALL"}
            add_sudo_rule(ldap_server, sudo_rule_test, sudo_host, sudo_command,
                          sudo_user, None, extra_attribute)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username=user1,
                              password=user1_password)
            # Check allowed offline access
            # Cache necessary data and verify that access is granted
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            client_sssd_break_link(multihost)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly, " \
                                   "offline sudo permission should be " \
                                   "granted"
            client_sssd_restore_link(multihost)
            time.sleep(online_wait)
            # Check denied offline access
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "!ALL")
            # Cache necessary data and verify that access is denied
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted unexpectedly"
            client_sssd_break_link(multihost)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted unexpectedly, " \
                                   "offline sudo permission should be denied"
            client_sssd_restore_link(multihost)
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "ALL")
            # Verify that repeated failures to come online don't crash SSSD.
            params = {"ldap_default_bind_dn": ds_rootdn,
                      "ldap_default_authtok": "NOT" + ds_rootpw}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            multihost.client[0].run_command("rm -rf /var/log/sssd/*")
            multihost.client[0].service_sssd("restart")
            time.sleep(5)
            # Repeatedly request SSSD to attempt to come online
            get_pid = multihost.client[0].run_command("cat /var/"
                                                      "run/sssd.pid",
                                                      raiseonerr=False)
            if get_pid.returncode != 0:
                raise Exception("No pid found due to ", get_pid.stderr_text)
            else:
                pid = str(get_pid.stdout_text)
                kill_cmd = f"kill -SIGUSR2 {pid}"
                for i in range(60, 0, -1):
                    multihost.client[0].run_command(kill_cmd)
                    time.sleep(0.5)
                # Verify that SSSD didn't quit and there were no segfaulted
                # child processes
                sssd_quit_cmd = "cat /var/log/sssd/sssd.log | grep -v '" \
                                "terminated with signal'"
                check_sssd_quit = multihost.client[0].run_command(
                    sssd_quit_cmd, raiseonerr=False)
                assert check_sssd_quit.returncode == 0, "sssd is terminated"
        finally:
            # teardown
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_refresh(self, multihost, backupsssdconf):
        """
        :title: sudo: Test sudo with refreshes at timely intervals.
        :description: Check sudo with sudo user and sudo group after
         OVERLAP_INTERVAL and SMART_INTERVAL with modifying values of
         sudoUser, sudoHost, sudoCommand, sudoRunAsUser, sudoRunAsGroup
         and sudoOption.
        :id: edbd4dd4-eebf-4f3b-bd82-8ac5176d254e
        :customerscenario: False
        :steps:
            1. Add user group named ldapuser1 with 10 users
            2. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout, ldap_sudo_smart_refresh_interval and
               ldap_sudo_full_refresh_interval.
            3. Add sudo rule named "test"
            4. Perform SMART_INTERVALs to check if sudo user is
               allowed/denied.
            5. Check sudo using sudo user by modifying options sudoUser,
               sudoHost, sudoCommand, sudoRunAsUser, sudoRunAsGroup
               and sudoOption.
            6. Check sudo with sudo group with options sudoRunAsGroup:
               group_user1 and sudoRunAsGroup: ALL.
            7. Check sudo with sudo user using sudoOption: authenticate.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
        """
        OVERLAP_INTERVAL = 2
        SMART_INTERVAL = 20
        FULL_INTERVAL = SMART_INTERVAL * 3
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        params = {"ldap_sudo_search_base": sudo_ou,
                  "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                  "entry_cache_nowait_percentage": 0,
                  "entry_cache_timeout": 0,
                  "ldap_sudo_smart_refresh_interval": SMART_INTERVAL,
                  "ldap_sudo_full_refresh_interval": FULL_INTERVAL}
        domain_section = f"domain/{ds_instance_name}"
        tools.sssd_conf(domain_section, params, action="update")
        section = "sssd"
        sssd_params = {"services": "nss, pam, sudo"}
        tools.sssd_conf(section, sssd_params, action="update")
        tools.clear_sssd_cache(start=True)
        try:
            ssh = pexpect_ssh(multihost.client[0].sys_hostname, username=user1,
                              password=user1_password)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted unexpectedly"
            time.sleep(OVERLAP_INTERVAL)
            unique_member = f"uid=foo0,ou=People,{ds_suffix}"
            add_group(ldap_server, ldapusers1, "14564101",
                      unique_member=unique_member)
            add_sudoers_ou(ldap_server)
            extra_attributes = {"sudoRunAsUser": "ALL",
                                "sudoRunAsGroup": "ALL"}
            add_sudo_rule(ldap_obj=ldap_server, rule_dn=sudo_rule_test,
                          sudoHost=sudo_host, sudoCommand=sudo_command,
                          sudoUser=sudo_user, sudo_extra=extra_attributes)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted before smart" \
                                   " interval refresh for initially added" \
                                   " sudo rule"
            time.sleep(SMART_INTERVAL)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied after smart " \
                                   "interval refresh for initially added" \
                                   " sudo rule"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoUser", user2)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted for sudoUser: " \
                                   "foo2@example1"
            multihost.client[0].service_sssd("restart")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoUser", "ALL")
            time.sleep(OVERLAP_INTERVAL)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted before smart" \
                                   " interval refresh for sudoUser: ALL"
            time.sleep(SMART_INTERVAL)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied after smart" \
                                   " interval refresh for sudoUser: ALL"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoHost",
                             "NOT-" + multihost.client[0].sys_hostname)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted with mismatched" \
                                   " sudoHost"
            multihost.client[0].service_sssd("restart")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoHost", "ALL")
            time.sleep(OVERLAP_INTERVAL)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted before smart" \
                                   " interval refresh for sudoHost: ALL"
            time.sleep(SMART_INTERVAL)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied after smart" \
                                   " interval refresh for sudoHost: ALL"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "!ALL")
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted for " \
                                   "sudoCommand:!ALL"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "ALL")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied for " \
                                   "sudoCommand: ALL"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoRunAsUser", user1)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted for " \
                                   "sudoRunAsUser:foo1@example"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoRunAsUser", "ALL")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied for " \
                                   "sudoRunAsUser: ALL"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoRunAsGroup", group_user1)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_group,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted for " \
                                   "sudoRunAsGroup:ldapusers@example1"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoRunAsGroup", "ALL")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_group,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied for " \
                                   "sudoRunAsGroup: ALL"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoOption", "authenticate")
            (_, exit_code) = ssh.sudo_requires_auth(sudo_command_echo,
                                                    user1_password)
            assert exit_code == 0, "sudo auth not requited unexpectedly"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoOption", "authenticate")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
        finally:
            # teardown
            del_group(ldap_server, ldapusers1)
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_host_filter(self, multihost, backupsssdconf):
        """
        :title: sudo: Test sudo with different values of host_filter.
        :description: Value of host_filter can be true or false,
         ldap_sudo_hostnames, ldap_sudo_ip, ldap_sudo_include_netgroups
         and ldap_sudo_include_regexp.
        :id: 187b380c-a807-4d00-a9b8-58aadbae33fe
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=883408
        :customerscenario: False
        :steps:
            1. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout, ldap_sudo_smart_refresh_interval and
               ldap_sudo_full_refresh_interval.
            2. Add sudo rule named "test"
            3. Test ldap_sudo_use_host_filter.
            4. Test ldap_sudo_hostnames.
            5. Test ldap_sudo_ip.
            6. Test ldap_sudo_include_netgroups.
            7. Test ldap_sudo_include_regexp, Bug 883408.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
        """
        SMART_INTERVAL = 10
        FULL_INTERVAL = SMART_INTERVAL * 3
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        netgroup_dn = f"cn=netgroup_client,ou=Netgroups,{ds_suffix}"
        nisNetgroupTriple = f"({multihost.client[0].sys_hostname},,)"
        tools = sssdTools(multihost.client[0])
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        # setup sssd
        params = {"ldap_sudo_search_base": sudo_ou,
                  "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                  "entry_cache_nowait_percentage": 0,
                  "entry_cache_timeout": 0,
                  "ldap_sudo_smart_refresh_interval": SMART_INTERVAL,
                  "ldap_sudo_full_refresh_interval": FULL_INTERVAL}
        domain_section = f"domain/{ds_instance_name}"
        tools.sssd_conf(domain_section, params, action="update")
        section = "sssd"
        sssd_params = {"services": "nss, pam, sudo"}
        tools.sssd_conf(section, sssd_params, action="update")
        tools.clear_sssd_cache(start=True)
        try:
            # insert sudoers ou
            add_sudoers_ou(ldap_server)
            # add sudo rule "test"
            extra_attribute = {"sudoRunAsUser": "ALL"}
            add_sudo_rule(ldap_server, sudo_rule_test, sudo_host, sudo_command,
                          sudo_user, None, extra_attribute)
            # insert Netgroups OU
            add_netgroup_ou(ldap_server)
            # insert netgroup_client
            add_netgroup(ldap_server, netgroup_dn, nisNetgroupTriple)
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username=user1,
                              password=user1_password,
                              enable_sync_original_prompt=False,
                              enable_auto_prompt_reset=False)
            load_filter_conf(multihost, tools, "true")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when" \
                                   " ldap_sudo_use_host_filter = true"
            load_filter_conf(multihost, tools, "false")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when" \
                                   " ldap_sudo_use_host_filter = false"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoHost", multihost.client[0].sys_hostname)
            load_filter_conf(multihost, tools, "true", "hostnames",
                             multihost.client[0].sys_hostname)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is on and hostname matches"
            load_filter_conf(multihost, tools, "true", "hostnames",
                             multihost.client[0].sys_hostname + "_NOT")
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted when " \
                                   "host_filter is on and hostname " \
                                   "doesn't match"
            load_filter_conf(multihost, tools, "false", "hostnames",
                             multihost.client[0].sys_hostname)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is off and hostname matches"
            load_filter_conf(multihost, tools, "false", "hostnames",
                             multihost.client[0].sys_hostname + "_NOT")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is off and hostname " \
                                   "doesn't match"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoHost", multihost.client[0].ip)
            load_filter_conf(multihost, tools, "true", "ip",
                             multihost.client[0].ip)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is on and ip matches"
            load_filter_conf(multihost, tools, "true", "ip",
                             multihost.client[0].ip + "_NOT")
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted when " \
                                   "host_filter is on and ip doesn't match"
            load_filter_conf(multihost, tools, "false", "ip",
                             multihost.client[0].ip)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is off and ip matches"
            load_filter_conf(multihost, tools, "false", "ip",
                             multihost.client[0].ip + "_NOT")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is off and ip doesn't match"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoHost", "+netgroup_client")
            load_filter_conf(multihost, tools, "true", "include_netgroups",
                             "true")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is on and " \
                                   "include_netgroups = true"
            load_filter_conf(multihost, tools, "true", "include_netgroups",
                             "false")
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted when " \
                                   "host_filter is on and " \
                                   "include_netgroups = false"
            load_filter_conf(multihost, tools, "false", "include_netgroups",
                             "true")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is off and " \
                                   "include_netgroups = true"
            load_filter_conf(multihost, tools, "false",
                             "include_netgroups", "false")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is off and " \
                                   "include_netgroups = false"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoHost",
                             f"{multihost.client[0].sys_hostname}*")
            load_filter_conf(multihost, tools, "true", "include_regexp",
                             "true")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is on and " \
                                   "include_regexp matches"
            load_filter_conf(multihost, tools, "true", "include_regexp",
                             "false")
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted when " \
                                   "host_filter is on and " \
                                   "include_regexp doesn't match"
            load_filter_conf(multihost, tools, "false", "include_regexp",
                             "true")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is off and " \
                                   "include_regexp matches"
            load_filter_conf(multihost, tools, "false", "include_regexp",
                             "false")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "host_filter is off and " \
                                   "include_regexp doesn't match"
        finally:
            # teardown
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_netgroup(ldap_server, netgroup_dn)
            del_sudoers_ou(ldap_server)
            del_netgroup_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_full_refresh(self, multihost, backupsssdconf):
        """
        :title: sudo: Check sudo with a full refresh of sudo rules.
        :id: 689e50c6-f33e-445b-b6da-e612f02e230a
        :customerscenario: False
        :steps:
            1. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout, ldap_sudo_smart_refresh_interval,
               ldap_sudo_full_refresh_interval and cache_credentials.
            2. Add sudo rule named "test"
            3. Break the link to the server.
            4. Try "getent passwd user1" and user should not exist.
            5. Restore the link to the server.
            4. Wait for retry timeout.
            5. Test that sudo rules are automatically downloaded to
               the sssd cache.
            6. Check initial full refresh retry occurred.
            7. Verify that access is denied and cache the rule.
            8. Modify sudoRunAsUser and sudoRunAsGroup.
            9. Break the link to the server.
            10. Verify access is allowed.
            11. Restore the link to the server.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
            8. Should succeed
            9. Should succeed
            10. Should succeed
            11. Should succeed
        """
        multihost.client[0].run_command("dnf install nmap-ncat -y")
        OVERLAP_INTERVAL = 2
        SMART_INTERVAL = 1
        FULL_INTERVAL = 5
        REFRESH_WAIT = FULL_INTERVAL + OVERLAP_INTERVAL
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        params = {"ldap_sudo_search_base": sudo_ou,
                  "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                  "entry_cache_nowait_percentage": 0,
                  "entry_cache_timeout": 0,
                  "ldap_sudo_smart_refresh_interval": SMART_INTERVAL,
                  "ldap_sudo_full_refresh_interval": FULL_INTERVAL,
                  "cache_credentials": "true"}
        domain_section = f"domain/{ds_instance_name}"
        tools.sssd_conf(domain_section, params, action="update")
        section = "sssd"
        sssd_params = {"services": "nss, pam, sudo"}
        tools.sssd_conf(section, sssd_params, action="update")
        tools.clear_sssd_cache(start=True)
        try:
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username=user1,
                              password=user1_password,
                              enable_sync_original_prompt=False,
                              enable_auto_prompt_reset=False)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted unexpectedly"
            # insert ldapusers1 group
            unique_member = f"uid=foo0,ou=People,{ds_suffix}"
            add_group(ldap_server, ldapusers1, "14564101",
                      unique_member=unique_member)
            # setup sudo rule
            add_sudoers_ou(ldap_server)
            extra_attributes = {"sudoRunAsUser": "ALL"}
            add_sudo_rule(ldap_server, sudo_rule_test, sudo_host, sudo_command,
                          sudo_user, None, extra_attributes)
            time.sleep(REFRESH_WAIT)
            # break sssd link
            client_sssd_break_link(multihost)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied after breaking" \
                                   " client sssd link"
            # restore link
            client_sssd_restore_link(multihost)
            full_refresh_init_retry(multihost)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_group,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted unexpectedly"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoRunAsUser", "ALL")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoRunAsGroup", "ALL")
            time.sleep(REFRESH_WAIT)
            client_sssd_break_link(multihost)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_group,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied after full " \
                                   "refresh change"
            client_sssd_restore_link(multihost)
        finally:
            # teardown
            del_group(ldap_server, ldapusers1)
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_stress_refresh(self, multihost, backupsssdconf):
        """
        :title: sudo: Test sudo with stress refreshes.
        :description: Check sudo by stressing attribute refreshes and test
         rule-matching/non-rule-matching attributes.
        :id: 7d89b03d-1349-4c32-9930-7084d706170c
        :customerscenario: False
        :steps:
            1. Add sudo rule named "test"
            2. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout, ldap_sudo_smart_refresh_interval,
               and ldap_sudo_full_refresh_interval.
            3. Stress test using sudoUser.
            4. Stress test using sudoHost.
            5. Stress test using sudoCommand.
            6. Stress test using sudoRunAsUser.
            7. Stress test using sudoRunAsGroup.
            8. Stress test using sudoOption.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
            8. Should succeed
        """
        OVERLAP_INTERVAL = 2
        SMART_INTERVAL = 1
        FULL_INTERVAL = SMART_INTERVAL * 10
        REFRESH_WAIT = SMART_INTERVAL + OVERLAP_INTERVAL
        tools = sssdTools(multihost.client[0])
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        unique_member = f"uid=foo0,ou=People,{ds_suffix}"
        try:
            add_group(ldap_server, ldapusers1, "14564101",
                      unique_member=unique_member)
            # add sudoers ou and sudo rule test
            add_sudoers_ou(ldap_server)
            extra_attributes = {"sudoRunAsUser": "ALL",
                                "sudoRunAsGroup": "ALL"}
            add_sudo_rule(ldap_server, sudo_rule_test, sudo_host,
                          sudo_command, sudo_user,
                          sudo_extra=extra_attributes)
            # load config
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": SMART_INTERVAL,
                      "ldap_sudo_full_refresh_interval": FULL_INTERVAL}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username=user1,
                              password=user1_password,
                              enable_sync_original_prompt=False,
                              enable_auto_prompt_reset=False)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            stress_test_user = stress_attr(multihost, ldap_server, "User",
                                           user2, 3, "user_is_denied",
                                           user1, REFRESH_WAIT,
                                           "user_is_allowed")
            assert stress_test_user == 0
            stress_test_host = stress_attr(multihost, ldap_server, "Host",
                                           "NOT-" +
                                           multihost.client[0].sys_hostname,
                                           0, "user_is_denied", "ALL",
                                           REFRESH_WAIT, "user_is_allowed")
            assert stress_test_host == 0
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            stress_test_command = stress_attr(multihost, ldap_server,
                                              "Command", "!ALL", 0,
                                              "user_is_denied", "ALL", 0,
                                              "user_is_allowed")
            assert stress_test_command == 0
            stress_test_runasuser = stress_attr(multihost, ldap_server,
                                                "RunAsUser", user1, 0,
                                                "user_is_denied", "ALL", 0,
                                                "user_is_allowed")
            assert stress_test_runasuser == 0
            stress_test_runasgroup = stress_attr(multihost, ldap_server,
                                                 "RunAsGroup", user1, 0,
                                                 "group_is_denied", "ALL",
                                                 0, "group_is_allowed")
            assert stress_test_runasgroup == 0
            stress_test_option = stress_attr(multihost, ldap_server,
                                             "Option", "authenticate", 0,
                                             "user_requires_auth",
                                             "!authenticate", 0,
                                             "user_is_allowed_no_prompt")
            assert stress_test_option == 0
        finally:
            # teardown
            del_group(ldap_server, ldapusers1)
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_attrs_command(self, multihost, backupsssdconf):
        """
        :title: sudo: Test sudo with various attribute commands.
        :description: Check sudo by changing 'sudoCommand' with several
         attributes.
        :id: 4dd8e83b-f091-4e27-ba89-2414c3d33877
        :customerscenario: False
        :steps:
            1. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout and ldap_sudo_smart_refresh_interval.
            2. Add sudo rule named "test"
            3. Create a temp directory client_attrs_command.XXXXXX, store
               it's path in a variable TMPDIR.
            4. Test sudo with sudoCommand: All.
            5. Test sudo with sudoCommand: !ALL.
            6. Test sudo with sudoCommand: /bin/true.
            7. Test sudo with sudoCommand: !/bin/true.
            8. Test sudo with sudoCommand: TMPDIR.
            9. Test sudo with sudoCommand: !TMPDIR.
            10. Test sudo with paranoid behaviour where there are two
                entries of sudoCommand in the same sudo rule.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
            8. Should succeed
            9. Should succeed
            10. Should succeed
        """
        SMART_INTERVAL = 1
        REFRESH_WAIT = SMART_INTERVAL + 1
        TMPDIR_PATH = ""
        tools = sssdTools(multihost.client[0])
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        # Load low-delay configuration
        params = {"ldap_sudo_search_base": sudo_ou,
                  "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                  "entry_cache_nowait_percentage": 0,
                  "entry_cache_timeout": 0,
                  "ldap_sudo_smart_refresh_interval": SMART_INTERVAL}
        domain_section = f"domain/{ds_instance_name}"
        tools.sssd_conf(domain_section, params, action="update")
        section = "sssd"
        sssd_params = {"services": "nss, pam, sudo"}
        tools.sssd_conf(section, sssd_params, action="update")
        tools.clear_sssd_cache(start=True)
        try:
            # add sudo rule
            add_sudoers_ou(ldap_server)
            extra_attribute = {"sudoRunAsUser": "ALL"}
            add_sudo_rule(ldap_server, sudo_rule_test, sudo_host, sudo_command,
                          sudo_user, sudo_extra=extra_attribute)
            time.sleep(REFRESH_WAIT)
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username=user1,
                              password=user1_password,
                              enable_sync_original_prompt=False,
                              enable_auto_prompt_reset=False)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            TMPDIR = multihost.client[0].run_command("mktemp --tmpdir "
                                                     "--directory client_"
                                                     "attrs_command.XXXXXX")
            TMPDIR_PATH = str(TMPDIR.stdout_text).strip()
            multihost.client[0].run_command(f"chmod 755 {TMPDIR_PATH}")
            # ALL
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "ALL")
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied when " \
                                   "sudoCommand: ALL"
            # !ALL
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "!ALL")
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted when " \
                                   "sudoCommand: !ALL"
            # Command
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "/bin/true")
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_bin_true, user1_password)
            assert exit_code == 0, f"sudo permission denied when " \
                                   f"sudoCommand: /bin/true for " \
                                   f"{sudo_command_bin_true}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_bin_echo, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: /bin/true for " \
                                   f"{sudo_command_bin_echo}"
            # !Command
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "!/bin/true")
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_bin_true, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !/bin/true for " \
                                   f"{sudo_command_bin_true}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_bin_echo, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !/bin/true for " \
                                   f"{sudo_command_bin_echo}"
            # Directory
            insert_shebang = f"echo '#! /bin/bash' > {TMPDIR_PATH}/a"
            multihost.client[0].run_command(insert_shebang)
            chmod_tmpdir_ax = f"chmod a+x {TMPDIR_PATH}/a"
            multihost.client[0].run_command(chmod_tmpdir_ax)
            cp_preserve = f"cp -p {TMPDIR_PATH}/{{a,b}}"
            multihost.client[0].run_command(cp_preserve)
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", TMPDIR_PATH + "/")
            sudo_command_tmpdir_a = f"sudo -u {user2} {TMPDIR_PATH}/a"
            sudo_command_tmpdir_b = f"sudo -u {user2} {TMPDIR_PATH}/b"
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_tmpdir_a, user1_password)
            assert exit_code == 0, f"sudo permission denied when " \
                                   f"sudoCommand: {TMPDIR_PATH}/ " \
                                   f"for {sudo_command_tmpdir_a}"
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_tmpdir_b, user1_password)
            assert exit_code == 0, f"sudo permission denied when " \
                                   f"sudoCommand: {TMPDIR_PATH}/ " \
                                   f"for {sudo_command_tmpdir_b}"
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: {TMPDIR_PATH}/ " \
                                   f"for {sudo_command_echo}"
            # !Directory
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "!" + TMPDIR_PATH + "/")
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_tmpdir_a, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !{TMPDIR_PATH}/ " \
                                   f"for {sudo_command_tmpdir_a}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_tmpdir_b, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !{TMPDIR_PATH}/ " \
                                   f"for {sudo_command_tmpdir_b}"
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !{TMPDIR_PATH}/ " \
                                   f"for {sudo_command_echo}"
            # Paranoid behavior
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoCommand", "/bin/true")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoCommand", "!/bin/true")
            sudo_command_env_true = f"sudo -u {user2} env true"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_bin_true, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: /bin/true and " \
                                   f"sudoCommand: !/bin/true for" \
                                   f" {sudo_command_bin_true}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_env_true, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: /bin/true and " \
                                   f"sudoCommand: !/bin/true for" \
                                   f" {sudo_command_env_true}"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoCommand", "/bin/true")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoCommand", "!/bin/true")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoCommand", "!/bin/true")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoCommand", "/bin/true")
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_bin_true, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !/bin/true and " \
                                   f"sudoCommand: /bin/true for" \
                                   f" {sudo_command_bin_true}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_env_true, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !/bin/true and " \
                                   f"sudoCommand: /bin/true for" \
                                   f" {sudo_command_env_true}"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoCommand", "!/bin/true")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoCommand", "/bin/true")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoCommand", "/bin/true")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoCommand", "!/bin/echo")
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_bin_true, user1_password)
            assert exit_code == 0, f"sudo permission denied when " \
                                   f"sudoCommand: /bin/true and " \
                                   f"sudoCommand: !/bin/echo for" \
                                   f" {sudo_command_bin_true}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_bin_echo, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: /bin/true and " \
                                   f"sudoCommand: !/bin/echo for" \
                                   f" {sudo_command_bin_echo}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_env_true, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: /bin/true and " \
                                   f"sudoCommand: !/bin/echo for" \
                                   f" {sudo_command_env_true}"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoCommand", "/bin/true")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoCommand", "!/bin/echo")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoCommand", "!/bin/echo")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoCommand", "/bin/true")
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_bin_true, user1_password)
            assert exit_code == 0, f"sudo permission denied when " \
                                   f"sudoCommand: !/bin/echo and " \
                                   f"sudoCommand: /bin/true for" \
                                   f" {sudo_command_bin_true}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_bin_echo, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !/bin/echo and " \
                                   f"sudoCommand: /bin/true for" \
                                   f" {sudo_command_bin_echo}"
            (_, exit_code) = ssh.sudo_permission_denied(
                sudo_command_env_true, user1_password)
            assert exit_code == 0, f"sudo permission granted when " \
                                   f"sudoCommand: !/bin/echo and " \
                                   f"sudoCommand: /bin/true for" \
                                   f" {sudo_command_env_true}"
        finally:
            # teardown
            multihost.client[0].run_command(f"rm -Rf {TMPDIR_PATH}")
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_attrs(self, multihost, backupsssdconf):
        """
        :title: sudo: Test sudo with empty attributes and attributes with
         value.
        :id: 27cb4f3b-c563-41e3-a40e-5080f91cb78c
        :customerscenario: False
        :steps:
            1. Edit sssd.conf and specify entry_cache_nowait_percentage,
               entry_cache_timeout and ldap_sudo_smart_refresh_interval.
            2. Add sudo rule named "test"
            3. Test empty attribute value for sudoUser.
            4. Test attribute values for sudoUser.
            5. Test empty attribute value for sudoRunAsUser.
            6. Test attribute values for sudoRunAsUser.
            7. Test empty attribute value for sudoRunAsGroup.
            8. Test attribute values for sudoRunAsGroup.
            9. Test empty attribute value for sudoNotBefore.
            10. Test attribute values for sudoNotBefore.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
            8. Should succeed
            9. Should succeed
            10. Should succeed
        """
        SMART_INTERVAL = 1
        REFRESH_WAIT = SMART_INTERVAL + 1
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        tools = sssdTools(multihost.client[0])
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        # Load low-delay configuration
        params = {"ldap_sudo_search_base": sudo_ou,
                  "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                  "entry_cache_nowait_percentage": 0,
                  "entry_cache_timeout": 0,
                  "ldap_sudo_smart_refresh_interval": SMART_INTERVAL}
        domain_section = f"domain/{ds_instance_name}"
        tools.sssd_conf(domain_section, params, action="update")
        section = "sssd"
        sssd_params = {"services": "nss, pam, sudo"}
        tools.sssd_conf(section, sssd_params, action="update")
        tools.clear_sssd_cache(start=True)
        try:
            # add ldapusers1
            unique_member = f"uid=foo0,ou=People,{ds_suffix}"
            add_group(ldap_server, ldapusers1, "14564101",
                      unique_member=unique_member, add_unique_members=False)
            # add Netgroups OU
            add_netgroup_ou(ldap_server)
            # add netgroup_client and netgroup_client_not
            add_netgroup(ldap_server, netgroup_client,
                         f"({multihost.client[0].sys_hostname},,)")
            add_netgroup(ldap_server, netgroup_client_not,
                         f"(not-{multihost.client[0].sys_hostname},,)")
            # add netgroup_user1 and netgroup_user2
            for i in range(1, 3):
                netgroup_dn = f"cn=netgroup_user{i},ou=Netgroups,{ds_suffix}"
                nisNetgroupTriple = f"(,foo{i}@example1,)"
                add_netgroup(ldap_server, netgroup_dn, nisNetgroupTriple)
            # add sudo rule
            add_sudoers_ou(ldap_server)
            extra_attribute = {"sudoRunAsUser": "ALL"}
            add_sudo_rule(ldap_server, sudo_rule_test, sudo_host, sudo_command,
                          sudo_user, sudo_extra=extra_attribute)
            time.sleep(REFRESH_WAIT)
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username=user1,
                              password=user1_password,
                              enable_sync_original_prompt=False,
                              enable_auto_prompt_reset=False)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            attr_empty_user = attr_empty(multihost, ldap_server, "User",
                                         REFRESH_WAIT, "user")
            assert attr_empty_user == 0
            test_list = [r"foo2@example1 denied", r"foo1@example1 allowed",
                         r"foo1@example1\\ denied", r"#14583102 denied",
                         r"#14583101 allowed", r"#14583101# denied",
                         r"%ldapusers1 denied", r"%ldapusers allowed",
                         r"%ldapusers% denied", r"+netgroup_user2 denied",
                         r"+netgroup_user1 allowed",
                         r"+netgroup_user1+ denied"]
            attr_values_user = attr_values(multihost, ldap_server, "User",
                                           REFRESH_WAIT, "user", test_list)
            assert attr_values_user == 0
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoUser", "ALL")
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            attr_empty_runasuser = attr_empty(multihost, ldap_server,
                                              "RunAsUser", 0, "user")
            assert attr_empty_runasuser == 0
            test_list = [r"foo1@example1 denied", r"foo2@example1 allowed",
                         r"foo2@example1\\ denied", r"#14583101 denied",
                         r"#14583102 allowed", r"%ldapusers denied",
                         r"%ldapusers1% denied", r"+netgroup_user1 denied",
                         r"+netgroup_user2 allowed",
                         r"+netgroup_user2+ denied",
                         r"#14583102# denied"]
            attr_values_runasuser = attr_values(multihost, ldap_server,
                                                "RunAsUser", 0, "user",
                                                test_list)
            assert attr_values_runasuser == 0
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoRunAsUser", "ALL")
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoRunAsUser", "ALL")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoRunAsGroup", "ALL")
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_group,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            attr_empty_runasgroup = attr_empty(multihost, ldap_server,
                                               "RunAsGroup", 0, "group")
            assert attr_empty_runasgroup == 0
            test_list = [r"ldapusers@example1 denied",
                         r"ldapusers1@example1 allowed",
                         r"ldapusers1@example2\\ denied",
                         r"#14564100 denied",
                         r"#14564101 allowed",
                         r"#14564101# denied"]
            attr_values_runasgroup = attr_values(multihost, ldap_server,
                                                 "RunAsGroup", 0, "group",
                                                 test_list)
            assert attr_values_runasgroup == 0
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoRunAsGroup", "#14564101#")
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_ADD,
                             "sudoRunAsUser", "ALL")
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            attr_empty_host = attr_empty(multihost, ldap_server, "Host",
                                         REFRESH_WAIT, "user")
            assert attr_empty_host == 0
            test_list = [fr"{multihost.client[0].sys_hostname} allowed",
                         fr"not-{multihost.client[0].sys_hostname} denied",
                         fr"{multihost.client[0].sys_hostname}\\ denied",
                         fr"{multihost.client[0].ip} allowed",
                         fr"not-{multihost.client[0].ip} denied",
                         fr"{multihost.client[0].ip}. denied",
                         r"+netgroup_client allowed",
                         r"+netgroup_client_not denied",
                         r"+netgroup_client+ denied"]
            attr_values_host = attr_values(multihost, ldap_server, "Host",
                                           REFRESH_WAIT, "user",
                                           test_list)
            assert attr_values_host == 0
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoHost", "ALL")
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied unexpectedly"
            incremented_time = future_time(10)
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoNotBefore", incremented_time)
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted before" \
                                   " sudoNotBefore time"
            time.sleep(19)
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_DELETE,
                             "sudoNotBefore", incremented_time)
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoNotAfter", future_time(10))
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_granted(sudo_command_echo,
                                                         user1_password)
            assert exit_code == 0, "sudo permission denied before" \
                                   " sudoNotAfter time"
            time.sleep(9)
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoNotBefore", future_time(10))
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoNotAfter", future_time(20))
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted before" \
                                   " sudoNotBefore: current_time + 10 " \
                                   "seconds sudoNotAfter: current_time " \
                                   "+ 20 seconds"
            time.sleep(19)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted after" \
                                   " sudoNotBefore: current_time + 10 " \
                                   "seconds sudoNotAfter: current_time " \
                                   "+ 20 seconds"
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoNotAfter", future_time(10))
            modify_attribute(ldap_server, sudo_rule_test, ldap.MOD_REPLACE,
                             "sudoNotBefore", future_time(20))
            time.sleep(REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted before" \
                                   " sudoNotAfter: current_time + 10 " \
                                   "seconds sudoNotBefore: current_time " \
                                   "+ 20 seconds"
            time.sleep(11 - REFRESH_WAIT)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted within" \
                                   " sudoNotAfter: current_time + 10 " \
                                   "seconds sudoNotBefore: current_time " \
                                   "+ 20 seconds"
            time.sleep(10)
            (_, exit_code) = ssh.sudo_permission_denied(sudo_command_echo,
                                                        user1_password)
            assert exit_code == 0, "sudo permission granted after" \
                                   " sudoNotAfter: current_time + 10 " \
                                   "seconds sudoNotBefore: current_time " \
                                   "+ 20 seconds"
        finally:
            # teardown
            for i in range(1, 3):
                netgroup_dn = f"cn=netgroup_user{i},ou=Netgroups,{ds_suffix}"
                del_netgroup(ldap_server, netgroup_dn)
            del_netgroup(ldap_server, netgroup_client)
            del_netgroup(ldap_server, netgroup_client_not)
            del_netgroup_ou(ldap_server)
            del_group(ldap_server, ldapusers1)
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_bz996020(self, multihost, backupsssdconf):
        """
        :title: sudo: sssd fails instead of skipping when a sudo ldap
         filter returns entries with multiple CN.
        :id: 3338acac-7f93-4b4e-ab0d-6df4db265894
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=996020
        :customerscenario: false
        :steps:
          1. Add a sudo rule with single CN and a sudo rule with multiple
             CN.
          2. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout, ldap_sudo_smart_refresh_interval.
          3. Test if user can execute sudo command.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        single_cn_rule = f"cn=single_cn,{sudo_ou}"
        multiple_cn_rule = f"cn=multiple_cn,{sudo_ou}"
        try:
            add_sudoers_ou(ldap_server)
            add_user(ldap_server, sudo_test_user_attrs, sudo_test_user_dn)
            add_sudo_rule(ldap_server, single_cn_rule, "ALL", "ALL",
                          "sudo_test_user@example1")
            extra_cn = {"cn": "extra_cn"}
            add_sudo_rule(ldap_server, multiple_cn_rule, "ALL", "ALL",
                          "non_existent_user@example1", sudo_extra=extra_cn)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            multihost.client[0].service_sssd("restart")
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username="sudo_test_user@example1",
                              password="Secret123")
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_dev_null, sudo_password)
            assert exit_code == 0, "sssd fails instead of skipping when" \
                                   " a sudo ldap filter returns entries" \
                                   " with multiple CN bz996020"
        finally:
            # teardown
            del_sudo_rule(ldap_server, multiple_cn_rule)
            del_sudo_rule(ldap_server, single_cn_rule)
            del_user(ldap_server, sudo_test_user_dn)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_bz1003567(self, multihost, backupsssdconf):
        """
        :title: sudo: large number of sudo rules results in error.
        :id: eb891e19-cbea-4249-86ab-6dbc07c6cc40
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1003567
        :customerscenario: false
        :steps:
          1. Add sudo rule named "test".
          2. Add large number of user groups - admins, facilities and hr.
          3. Add large number of sudo rules - admin_rule, facilities_rule
             and hr_rule.
          4. Add a user "sudo_test_user".
          5. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout, ldap_sudo_smart_refresh_interval,
             ldap_schema and ldap_group_object_class.
          6. Test if user can execute and list all sudo commands.
          7. Check "Unable to create response: Invalid argument" is not
             present in /var/log/sssd/sssd_sudo.log.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        try:
            add_sudoers_ou(ldap_server)
            add_sudo_rule(ldap_server, sudo_rule_test, "ALL", "ALL",
                          "sudo_test_user@example1")
            add_large_user_groups(ldap_server, 21, 100)
            add_large_sudo_rules(ldap_server, 21, 100)
            add_user(ldap_server, sudo_test_user_attrs, sudo_test_user_dn)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1,
                      "ldap_schema": "rfc2307bis",
                      "ldap_group_object_class": "groupOfNames"}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            multihost.client[0].service_sssd("restart")
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username="sudo_test_user@example1",
                              password="Secret123")
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_dev_null, sudo_password)
            assert exit_code == 0, "large number of sudo rules results " \
                                   "in error bz1003567"
            cat_sudo_log = multihost.client[0].run_command("cat /var/log"
                                                           "/sssd/"
                                                           "sssd_sudo.log")
            sssd_log = str(cat_sudo_log.stdout_text).strip()
            if "Invalid argument" in sssd_log:
                raise Exception("unable to compute the response packet "
                                "length properly, check sssd log:",
                                sssd_log)
        finally:
            # teardown
            del_user(ldap_server, sudo_test_user_dn)
            del_large_sudo_rules(ldap_server, 21, 100)
            del_large_user_groups(ldap_server, 21, 100)
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_bz995737(self, multihost, backupsssdconf):
        """
        :title: sudo: sudo backed by sssd ldap denies all access.
        :id: e99987b0-ddfa-436f-a24e-97b315005e77
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=995737
        :customerscenario: false
        :steps:
          1. Add sudo rule named "test".
          2. Add a user "sudo_test_user".
          3. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout, ldap_sudo_smart_refresh_interval and
             ldap_schema.
          4. Test if user can execute and list all sudo commands.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        try:
            add_sudoers_ou(ldap_server)
            add_sudo_rule(ldap_server, sudo_rule_test, "ALL", "ALL",
                          "sudo_test_user@example1")
            add_user(ldap_server, sudo_test_user_attrs, sudo_test_user_dn)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1,
                      "ldap_schema": "IPA"}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            multihost.client[0].service_sssd("restart")
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username="sudo_test_user@example1",
                              password="Secret123")
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_dev_null, sudo_password)
            assert exit_code == 0, "BZ995737 sudo backed by sssd ldap " \
                                   "denies all access"
        finally:
            # teardown
            del_user(ldap_server, sudo_test_user_dn)
            del_sudo_rule(ldap_server, sudo_rule_test)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_bz1042922(self, multihost, backupsssdconf):
        """
        :title: sudo: Add fallback to sudoRunAs when sudoRunasUser is
         not defined.
        :id: 90dee16c-0c7d-4f31-a5eb-dfd3cf613eb5
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1042922
        :customerscenario: false
        :steps:
          1. Add sudo rule named "testrule".
          2. Add users "sudo_test_user", "sudo_test_user2", "tuser".
          3. Create a touch binary using "which touch" command.
          4. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout and ldap_sudo_smart_refresh_interval.
          5. Using "tuser" user, test sudo with "sudo_test_user" user and
             "sudo_test_user2" user.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        sudo_options = ["!authenticate", "!requiretty"]
        sudo_extra = {'sudoRunAs': 'sudo_test_user@example1',
                      'sudoRunAsUser': 'sudo_test_user2@example1'}
        try:
            touch_cmd = multihost.client[0].run_command("which touch")
            TOUCH_BINARY = str(touch_cmd.stdout_text).strip()
            add_sudoers_ou(ldap_server)
            add_sudo_rule(ldap_server, sudo_rule_testrule, "ALL", TOUCH_BINARY,
                          "tuser@example1", sudo_option=sudo_options,
                          sudo_extra=sudo_extra)
            add_user(ldap_server, sudo_test_user_attrs, sudo_test_user_dn)
            add_user(ldap_server, sudo_test_user2_attrs, sudo_test_user2_dn)
            add_user(ldap_server, sudo_tuser_attrs, sudo_tuser_dn)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 10}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            time.sleep(11)
            (_, _, exit_code) = perform_sudo_command(multihost,
                                                     user="tuser@example1",
                                                     user_password="Secret"
                                                                   "123",
                                                     command="sudo -u sudo_"
                                                             "test_user@"
                                                             "example1 touch"
                                                             " /tmp/foo1")
            assert exit_code == 1, "sudo permission granted unexpectedly"
            (_, _, exit_code) = perform_sudo_command(multihost,
                                                     user="tuser@example1",
                                                     user_password="Secret"
                                                                   "123",
                                                     command="sudo -u sudo_"
                                                             "test_user2@"
                                                             "example1 touch"
                                                             " /tmp/foo1")
            assert exit_code == 0, "sudo permission denied unexpectedly"
            modify_attribute(ldap_server, sudo_rule_testrule,
                             ldap.MOD_DELETE, "sudoRunAsUser",
                             "sudo_test_user2@example1")
            tools.clear_sssd_cache(start=True)
            time.sleep(11)
            (_, _, exit_code) = perform_sudo_command(multihost,
                                                     user="tuser@example1",
                                                     user_password="Secret"
                                                                   "123",
                                                     command="sudo -u sudo_"
                                                             "test_user@"
                                                             "example1 touch"
                                                             " /tmp/foo3")
            assert exit_code == 0, "sudo permission denied, fallback to " \
                                   "sudoRunAs not defined"
            (_, _, exit_code) = perform_sudo_command(multihost,
                                                     user="tuser@example1",
                                                     user_password="Secret"
                                                                   "123",
                                                     command="sudo -u sudo_"
                                                             "test_user2@"
                                                             "example1 touch"
                                                             " /tmp/foo4")
            assert exit_code == 1, "sudo permission granted unexpectedly"
        finally:
            # teardown
            multihost.client[0].run_command("rm -f /tmp/foo*")
            del_sudo_rule(ldap_server, sudo_rule_testrule)
            del_user(ldap_server, sudo_tuser_dn)
            del_user(ldap_server, sudo_test_user2_dn)
            del_user(ldap_server, sudo_test_user_dn)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_bz1422183(self, multihost, backupsssdconf):
        """
        :title: sudo: Duplicate usernames with difference of upper and
         lower case.
        :id: 4c1ab05e-9567-4529-8e00-d44755725a4f
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1422183
        :customerscenario: false
        :steps:
          1. Add sudo rule named "testrule".
          2. Add user "tuser".
          3. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout and ldap_sudo_smart_refresh_interval.
          4. Using "tuser" user, test sudo with "root" user.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        sudo_options = ["!authenticate", "!requiretty"]
        sudo_extra = {'sudoRunAs': 'root',
                      'sudoRunAsUser': 'root',
                      'sudoUser': 'TUSER@example1'}
        try:
            add_sudoers_ou(ldap_server)
            add_sudo_rule(ldap_server, sudo_rule_testrule,
                          "ALL", "/usr/bin/id", "tuser@example1",
                          sudo_option=sudo_options, sudo_extra=sudo_extra)
            add_user(ldap_server, sudo_tuser_attrs, sudo_tuser_dn)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            time.sleep(10)
            (_, _, exit_code) = perform_sudo_command(multihost,
                                                     user="tuser@example1",
                                                     user_password="Secret"
                                                                   "123",
                                                     command="sudo -u root "
                                                             "id | egrep "
                                                             "'uid=0'")
            assert exit_code == 0, "User rules are not stored correctly"
        finally:
            # teardown
            del_sudo_rule(ldap_server, sudo_rule_testrule)
            del_user(ldap_server, sudo_tuser_dn)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_bz1590603(self, multihost, backupsssdconf):
        """
        :title: sudo: information leak from sssd sudo responder.
        :id: df903d6f-42e6-40cb-b6dd-94e40a8f2bbe
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1590603
        :customerscenario: false
        :steps:
          1. Add sudo rule named "testrule".
          2. Add user "testuser".
          3. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout and ldap_sudo_smart_refresh_interval.
          4. Check Socket File ownership and permissions are correct in
             /var/lib/sss/pipes/sudo.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        sudo_options = ["!authenticate", "!requiretty"]
        sudo_extra = {'sudoRunAs': 'root',
                      'sudoRunAsUser': 'root'}
        try:
            add_sudoers_ou(ldap_server)
            add_user(ldap_server, sudo_testuser_attrs, sudo_testuser_dn)
            add_sudo_rule(ldap_server, sudo_rule_testrule, "ALL",
                          "/usr/bin/id", "testuser@example1",
                          sudo_option=sudo_options, sudo_extra=sudo_extra)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            time.sleep(10)
            sudo_socket = multihost.client[0].run_command("ls -l /var/lib"
                                                          "/sss/pipes/sudo",
                                                          raiseonerr=False)
            assert sudo_socket.returncode == 0
            PIPE_PERMISSION = str(multihost.client[0].run_command("stat -c "
                                                                  "'%a' /var"
                                                                  "/lib/sss"
                                                                  "/pipes"
                                                                  "/sudo").
                                  stdout_text).strip()
            PIPE_OWNERSHIP = str(multihost.client[0].run_command("stat -c "
                                                                 "'%U %G' "
                                                                 "/var/lib"
                                                                 "/sss/pipes"
                                                                 "/sudo").
                                 stdout_text).strip()
            if "600" not in PIPE_PERMISSION or "root root" not in \
                    PIPE_OWNERSHIP:
                raise Exception(f"Socket File ownership and/or permissions"
                                f" are INCORRECT: {PIPE_PERMISSION} and "
                                f"{PIPE_OWNERSHIP}")
        finally:
            # teardown
            del_sudo_rule(ldap_server, sudo_rule_testrule)
            del_user(ldap_server, sudo_testuser_dn)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_bz1607313(self, multihost, backupsssdconf):
        """
        :title: sudo: private pipe ownership when sssd is running as
         non root user.
        :id: 15922018-8d84-474d-9173-fd4eaaba0e8e
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1607313
        :customerscenario: false
        :steps:
          1. Add sudo rule named "testrule".
          2. Add user "testuser".
          3. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout and ldap_sudo_smart_refresh_interval.
          4. Check Socket File ownership and permissions are correct in
             /var/lib/sss/pipes/sudo.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        sudo_options = ["!authenticate", "!requiretty"]
        sudo_extra = {'sudoRunAs': 'root',
                      'sudoRunAsUser': 'root'}
        try:
            add_sudoers_ou(ldap_server)
            add_user(ldap_server, sudo_testuser_attrs, sudo_testuser_dn)
            add_sudo_rule(ldap_server, sudo_rule_testrule, "ALL",
                          "/usr/bin/id", "testuser@example1",
                          sudo_option=sudo_options, sudo_extra=sudo_extra)
            passwd = str(multihost.client[0].run_command("cat /etc/passwd")
                         .stdout_text).strip().split("\n")
            sssd_line = ""
            for line in passwd:
                if "sssd" in line:
                    sssd_line = line
                    break
            sssd_user = sssd_line.split(":")[0]
            # Load low-delay configuration
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo",
                           "user": sssd_user}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            time.sleep(10)
            sudo_socket = multihost.client[0].run_command("ls -l /var/lib"
                                                          "/sss/pipes/sudo",
                                                          raiseonerr=False)
            assert sudo_socket.returncode == 0
            PIPE_PERMISSION = str(multihost.client[0].run_command("stat -c "
                                                                  "'%a' /var"
                                                                  "/lib/sss"
                                                                  "/pipes"
                                                                  "/sudo").
                                  stdout_text).strip()
            PIPE_OWNERSHIP = str(multihost.client[0].run_command("stat -c "
                                                                 "'%U %G'"
                                                                 " /var/lib"
                                                                 "/sss/"
                                                                 "pipes"
                                                                 "/sudo").
                                 stdout_text).strip()
            if "600" not in PIPE_PERMISSION or f"{sssd_user} root" \
                    not in PIPE_OWNERSHIP:
                raise Exception(f"Socket File ownership and/or permissions"
                                f" are INCORRECT: {PIPE_PERMISSION} and "
                                f"{PIPE_OWNERSHIP}")
        finally:
            # teardown
            del_sudo_rule(ldap_server, sudo_rule_testrule)
            del_user(ldap_server, sudo_testuser_dn)
            del_sudoers_ou(ldap_server)
            tools.clear_sssd_cache(start=True)

    def test_bz1132264(self, multihost, backupsssdconf, localusers):
        """
        :title: sudo: allow sssd to retrieve sudo rules of local users
         whose sudo rules stored in ldap server.
        :id: 353da806-40ba-4913-84e2-dce52fc51cda
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1132264
        :customerscenario: false
        :steps:
          1. Add sudo rule named "testrule".
          2. Add local user "user5000".
          3. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout, ldap_sudo_smart_refresh_interval,
             id_provider, sudo_provider, ldap_tls_cacert and
             ldap_search_base.
          4. Using "user5000" localuser, test sudo with "root" user.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        sudo_options = ["!authenticate", "!requiretty"]
        sudo_extra = {'sudoRunAs': 'root',
                      'sudoRunAsUser': 'root'}
        try:
            add_sudoers_ou(ldap_server)
            add_sudo_rule(ldap_server, sudo_rule_testrule, "ALL",
                          "/usr/bin/id", "user5000",
                          sudo_option=sudo_options, sudo_extra=sudo_extra)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_search_base": sudo_ou,
                      "id_provider": "files",
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "ldap_tls_cacert": "/etc/openldap/certs/cacert.asc",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1}
            domain_section = "domain/files"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo",
                           "domains": f"{ds_instance_name},files"}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            grep_uid_0 = multihost.client[0].run_command("su user5000 -c "
                                                         "'sudo -u root id' "
                                                         "| egrep 'uid=0'",
                                                         raiseonerr=False)
            assert grep_uid_0.returncode == 0, "User rules are not stored" \
                                               " correctly"
        finally:
            # teardown
            del_sudo_rule(ldap_server, sudo_rule_testrule)
            del_sudoers_ou(ldap_server)

    def test_bz1208507(self, multihost, backupsssdconf):
        """
        :title: sudo: sysdb sudo search does not escape special characters.
        :id: 9d47d568-b1b1-4347-b853-1efb143b75b5
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1208507
        :customerscenario: false
        :steps:
          1. Add users "t(u)ser".
          2. Add group group(_u)ser1.
          3. Add sudo rule named "testrule".
          4. Create a touch binary using "which touch" command.
          5. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout and ldap_sudo_smart_refresh_interval.
          6. Sleep for a bit to let SSSD reload the sudo rules after startup.
          7. Using "t\\(u\\)ser" user, test sudo with "root" user and
             "group\\(_u\\)ser1" group.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        TOUCH_BINARY = str(multihost.client[0].run_command("which touch")
                           .stdout_text).strip()
        sudo_extra = {'sudoRunAsUser': 'root',
                      'sudoRunAsGroup': 'group(_u)ser1@example1'}
        try:
            add_user(ldap_server, sudo_tuser1_attrs, sudo_tuser1_dn)
            add_group(ldap_server, "group(_u)ser1", "20000",
                      memberUid="t(u)ser@example1", add_unique_members=False)
            add_sudoers_ou(ldap_server)
            add_sudo_rule(ldap_server, sudo_rule_testrule, "ALL",
                          TOUCH_BINARY, "t(u)ser@example1",
                          sudo_extra=sudo_extra)
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            multihost.client[0].run_command(r"getent passwd t\(u\)"
                                            r"ser@example1")
            multihost.client[0].run_command(r"getent group group\(_u\)"
                                            r"ser1@example1")
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username=r"t\(u\)ser@example1",
                              password="Secret123")
            (_, exit_code) = ssh.sudo_permission_granted(r"sudo -u root -g "
                                                         r"group\(_u\)ser1"
                                                         r"@example1 touch "
                                                         r"/tmp/foo1",
                                                         "Secret123")
            assert exit_code == 0
            (_, exit_code) = ssh.sudo_permission_granted(r"sudo touch "
                                                         r"/tmp/foo2",
                                                         "Secret123")
            assert exit_code == 0
        finally:
            # teardown
            multihost.client[0].run_command("rm -f /tmp/foo*")
            del_sudo_rule(ldap_server, sudo_rule_testrule)
            del_sudoers_ou(ldap_server)
            del_group(ldap_server, "group(_u)ser1")
            del_user(ldap_server, sudo_tuser1_dn)
            tools.clear_sssd_cache(start=True)

    def test_bz1084532(self, multihost, backupsssdconf):
        """
        :title: sudo: sssd sudo process segfaults.
        :id: 506d1cba-d0fb-4339-8992-7a6d74227f9b
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1084532
        :customerscenario: false
        :steps:
          1. Add sudo rule named "testrule".
          2. Add user "sudo_test_user2".
          3. Edit sssd.conf and specify ldap_sudo_search_base, ldap_uri,
             sudo_provider, entry_cache_nowait_percentage,
             entry_cache_timeout and ldap_sudo_smart_refresh_interval.
          4. Add 500 sudo rules: rule_1 to rule_500.
          5. Check user can execute and list all sudo commands.
          6. Check "segfault\\ at" is not present in /var/log/messages.
          7. Check "segfault" is not present in /var/log/sssd/sssd_sudo.log.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        ldap_uri = f"ldap://{multihost.master[0].sys_hostname}"
        ldap_server = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        try:
            add_user(ldap_server, sudo_test_user2_attrs, sudo_test_user2_dn)
            add_sudoers_ou(ldap_server)
            add_500_sudo_rules(ldap_server, "sudo_test_user2@example1",
                               "ALL", "ALL")
            params = {"ldap_sudo_search_base": sudo_ou,
                      "ldap_uri": ldap_uri, "sudo_provider": "ldap",
                      "entry_cache_nowait_percentage": 0,
                      "entry_cache_timeout": 0,
                      "ldap_sudo_smart_refresh_interval": 1}
            domain_section = f"domain/{ds_instance_name}"
            tools.sssd_conf(domain_section, params, action="update")
            section = "sssd"
            sssd_params = {"services": "nss, pam, sudo"}
            tools.sssd_conf(section, sssd_params, action="update")
            tools.clear_sssd_cache(start=True)
            time.sleep(11)
            ssh = pexpect_ssh(multihost.client[0].sys_hostname,
                              username="sudo_test_user2@example1",
                              password="Secret123")
            (_, exit_code) = ssh.sudo_permission_granted(
                sudo_command_dev_null, sudo_password)
            assert exit_code == 0
            log_messages = str(multihost.client[0].run_command("cat /var/log"
                                                               "/messages").
                               stdout_text).strip()
            if r"segfault\ at" in log_messages:
                raise Exception("traces of segfault found at /var/log"
                                "/messages")
            sssd_sudo_log = str(multihost.client[0].run_command("cat /var"
                                                                "/log/sssd"
                                                                "/sssd_"
                                                                "sudo.log").
                                stdout_text).strip()
            if "segfault" in sssd_sudo_log:
                raise Exception("trace of segfault found at "
                                "/var/log/sssd/sssd_sudo.log")
        finally:
            # teardown
            del_500_sudo_rules(ldap_server)
            del_sudoers_ou(ldap_server)
            del_user(ldap_server, sudo_test_user2_dn)
            tools.clear_sssd_cache(start=True)
