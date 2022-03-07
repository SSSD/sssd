# Constants
ds_instance_name = 'example1'
ds_instance_name1 = 'example2'
ds_instance_name2 = 'example3'
ds_suffix = 'dc=example,dc=test'
krb_realm = 'EXAMPLE.TEST'
ds_rootdn = 'cn=Directory Manager'
ds_rootpw = 'Secret123'
user1 = 'foo1@example1'
user2 = 'foo2@example1'
group_user1 = "ldapusers@example1"
group_user2 = "ldapusers1@example1"
user1_password = ds_rootpw
netgroups_ou = f"ou=Netgroups,{ds_suffix}"
ou_name = "sudoers"
sudo_ou = f"ou={ou_name},{ds_suffix}"
sudo_host = "ALL"
sudo_command = "ALL"
sudo_user = "ALL"
sudo_command_echo = f"sudo -u {user2} echo SSSD"
sudo_command_bin_true = f"sudo -u {user2} /bin/true"
sudo_command_bin_echo = f"sudo -u {user2} /bin/echo"
sudo_command_dev_null = "sudo -l > /dev/null"
sudo_command_group = f"sudo -g {group_user2} echo SSSD"
sudo_rule_test = f"cn=test,{sudo_ou}"
sudo_rule_test1 = f"cn=test1,{sudo_ou}"
sudo_rule_test2 = f"cn=test2,{sudo_ou}"
sudo_rule_testrule = f"cn=testrule,{sudo_ou}"
sudo_rule_defaults = f"cn=defaults,{sudo_ou}"
sudo_password = ds_rootpw
smart_interval = 1
ldapusers1 = "ldapusers1"
netgroup_client = f"cn=netgroup_client,ou=Netgroups,{ds_suffix}"
netgroup_client_not = f"cn=netgroup_client_not,ou=Netgroups,{ds_suffix}"
sudo_test_user_dn = f"uid=sudo_test_user,{ds_suffix}"
sudo_test_user_attrs = {
    'cn': 'Temp',
    'uidNumber': '13111',
    'gidNumber': '10021',
    'gecos': 'random strings',
    'homeDirectory': '/home/sudo_test_user',
    'loginShell': '/bin/bash',
    'userPassword': 'Secret123'
}
sudo_test_user2_dn = f"uid=sudo_test_user2,{ds_suffix}"
sudo_test_user2_attrs = {
    'cn': 'Temp2',
    'uidNumber': '13112',
    'gidNumber': '10022',
    'gecos': 'Test user for 500 rules',
    'homeDirectory': '/home/sudo_test_user2',
    'loginShell': '/bin/bash',
    'userPassword': 'Secret123'
}
sudo_tuser_dn = f"uid=tuser,{ds_suffix}"
sudo_tuser_attrs = {
    'cn': 'example tuser',
    'uidNumber': '1000013',
    'gidNumber': '1000013',
    'homeDirectory': '/home/tuser',
    'loginShell': '/bin/bash',
    'userPassword': 'Secret123'
}

sudo_testuser_dn = f"uid=testuser,{ds_suffix}"
sudo_testuser_attrs = {
    'cn': 'example testuser',
    'uidNumber': '1000014',
    'gidNumber': '1000014',
    'homeDirectory': '/home/testuser',
    'loginShell': '/bin/bash',
    'userPassword': 'Secret123'
}

sudo_tuser1_dn = f"uid=t(u)ser,ou=People,{ds_suffix}"
sudo_tuser1_attrs = {
    'cn': 'example t(u)ser',
    'uidNumber': '10013',
    'gidNumber': '10013',
    'homeDirectory': '/home/tuser',
    'loginShell': '/bin/bash',
    'userPassword': 'Secret123'
}
