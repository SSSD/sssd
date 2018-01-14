""" This module defines classes regarding sssd tools,
AD Operations and LDAP Operations"""
from __future__ import print_function
import os
import tempfile
import subprocess
import array
import random
import socket
import shlex
import ConfigParser
from subprocess import CalledProcessError
from StringIO import StringIO
import ldap
import ldif
import paramiko
from ldap import modlist
from .authconfig import RedHatAuthConfig
from .exceptions import PkiLibException


PARAMIKO_VERSION = (int(paramiko.__version__.split('.')[0]),
                    int(paramiko.__version__.split('.')[1]))


class sssdTools(object):
    """ Collection of assorted functions which is used in fixtures

        Attributes:
            Host(obj: `Multihost object type`): Multihost Object
            authbackup(str): Backup directory of authconfig
    """
    def __init__(self, Host):
        self.multihost = Host
        self.authbackup = "/root/authconfig_backup"

    def update_resolv_conf(self, ip_addr):
        """ Update /etc/resolv.conf with Windows AD IP address

            :param str ip_addr: IP Address to be added in resolv.conf
            :return: None
            :Exception: Raises exception of builtin type Exception
        """
        self.multihost.log.info("Taking backup of /etc/resolv.conf")
        output = self.multihost.run_command(['cp', '-f', '/etc/resolv.conf',
                                             '/etc/resolv.conf.backup'],
                                            set_env=False, raiseonerr=False)
        if output.returncode == 0:
            self.multihost.log.info("/etc/resolv.conf successfully backed up")
            self.multihost.log.info("Add ip addr %s in resolv.conf" % ip_addr)
            nameserver = 'nameserver %s\n' % ip_addr
            contents = self.multihost.get_file_contents('/etc/resolv.conf')
            if not contents.startswith(nameserver):
                contents = nameserver + contents.replace(nameserver, '')
                self.multihost.put_file_contents('/etc/resolv.conf', contents)
        else:
            raise Exception("Updating resolv.conf with ip %s failed" % ip_addr)

    def config_authconfig(self, hostname, domainname):
        """ Run authconfig to configure Kerberos and SSSD auth on remote host

            :param str hostname: Hostname of server(AD) to
             which client is configured to auth
            :param domainname: domain name of IPA/AD
            :return: None
            :Exceptions: None
        """
        authconfig = RedHatAuthConfig(self.multihost)
        self.multihost.log.info("Take backup of current authconfig")
        authconfig.backup(self.authbackup)
        self.multihost.run_command(['domainname'], raiseonerr=False)
        authconfig.enable("sssd")
        authconfig.enable("sssdauth")
        authconfig.add_parameter("krb5kdc", hostname)
        authconfig.add_parameter("krb5adminserver", hostname)
        authconfig.add_parameter("krb5realm", domainname.upper())
        authconfig.execute()

    def restore_authconfig(self):
        """ Restore the default authconfig """
        authconfig = RedHatAuthConfig(self.multihost)
        authconfig.restore(self.authbackup)

    def config_smb_net_ads_join(self, domainname):
        """ Configure smb.conf as Domain Member to Windows AD
            :param str domainname: domain name of AD/IPA
            :return: None
            :Exception: None
        """
        workgroup_name = domainname.strip().split('.')[0].upper()
        realm = domainname.strip().upper()
        sambaconfig = ConfigParser.RawConfigParser()
        sambaconfig.optionxform = str
        sambaconfig.add_section('global')
        sambaconfig.set("global", "workgroup", workgroup_name)
        sambaconfig.set("global", "security", "ads")
        sambaconfig.set("global", "realm", realm)
        sambaconfig.set("global", "kerberos method", "secrets and keytab")
        sambaconfig.set("global", "client signing", "yes")
        sambaconfig.set("global", "client use spnego", "yes")
        tmp_fd, tmp_file_path = tempfile.mkstemp(suffix='conf', prefix='smb')
        with open(tmp_file_path, "wb") as outfile:
            sambaconfig.write(outfile)
        self.multihost.transport.put_file(tmp_file_path, '/etc/samba/smb.conf')
        os.close(tmp_fd)

    def realm_join(self, domainname, admin_password,
                   client_software='sssd',
                   server_software='active-directory',
                   membership_software='adcli'):
        """ Join system to AD/IPA Domain using realmOA
            :param str domainname: domain name of AD/IPA
            :param str admin_password: Administrator password required to join
            :param str client_software: client software to be used (sssd/samba)
            :param str server_software: server software (active-directory/ipa)
            :param str membership_software: membership software (samba/adcli)
            :return bool: True if successfully joined to AD/IPA
                          else raises Exception
            :Exception: Raises exception(builtin)
        """

        cmd = self.multihost.run_command(['realm', 'join', domainname,
                                          '--client-software=%s' %
                                          (client_software),
                                          '--server-software=%s' %
                                          (server_software),
                                          '--membership-software=%s' %
                                          (membership_software), '-v'],
                                         stdin_text=admin_password,
                                         raiseonerr=False)

        if cmd.returncode != 0:
            raise Exception("Error: %s" % cmd.stderr_text)
        else:
            return True

    def realm_leave(self, domainname):
        """ Leave system from AD/IPA Domain

            :param str domainname: domain name of AD/IPA
            :return bool: True if successfully dis-joined to AD/IPA
             else raises Exception
            :Exception: Raises exception(builtin)
        """

        cmd = self.multihost.run_command(['realm', 'leave',
                                          domainname, '-v'],
                                         raiseonerr=False)
        if cmd.returncode != 0:
            raise Exception("Error: %s", cmd.stderr_text)
        else:
            return True

    def export_nfs_fs(self, path_list, nfs_client):
        """ Add local file systems directories to /etc/exports

        Todo: We are not checking if the directories added
        to /etc/exports already exist.

            :param str path_list: list of directories to be created
            :param str nfs_client: hostname/ip-address of nfs client
            :return bool: True if successfully added values in /etc/exports
            :Exception: Raises exception(builtin) if not successfully added
        """
        self.multihost.transport.get_file('/etc/exports', '/tmp/exports')
        for local_dir in path_list:
            cmd = self.multihost.run_command(['mkdir', '-p', local_dir],
                                             raiseonerr=False)
            if cmd.returncode != 0:
                raise Exception("Unable to create %s directory" % local_dir)
            exp_share = '{}{}{}{}'.format(local_dir, ' ', nfs_client,
                                          '(rw,sync,fsid=0)')

            with open('/tmp/exports', "a+") as outfile:
                outfile.write(exp_share + "\n")
        self.multihost.transport.put_file('/tmp/exports', '/etc/exports')
        return True

    def remove_sss_cache(self, cache_path):
        """ Remove the sssd cache
            :param str cache_path: The relative path of cache
            :return bool: True if deletion and mkdir is successful
            :Exception: Raises exception(builtin)
        """
        cmd = self.multihost.run_command(['ls', cache_path], raiseonerr=False)
        if cmd.returncode == 0:
            db_list = cmd.stdout_text.split()
            # for index in range(len(db_list)):
            for index in enumerate(db_list):
                # sss_db = db_list[index]
                sss_db = index[1]
                relative_path = '{}/{}'.format(cache_path, sss_db)
                rm_file = self.multihost.run_command(['rm', '-f',
                                                      relative_path],
                                                     raiseonerr=False)
                if rm_file.returncode != 0:
                    raise Exception("Error: %s", cmd.stderr_text)
                else:
                    print("Successfully deleted %s" % (relative_path))
                    return True

    def domain_from_suffix(self, suffix):
        """ Domain name from the suffix
        :param suffix: The suffix of 389 RHDS instance
        :return: domain name in upper case
        :Exception: Raises exception(builtin)
        """
        if suffix is None:
            raise Exception("Error: suffix should be passed")
        else:
            l1 = suffix.split("dc=")
            elist = []
            for i in l1:
                d1 = i.strip(',')
                elist.append(d1)
            str1 = '.'.join(elist)
            l_domain = str1.lstrip('.')
            u_domain = l_domain.upper()
            return u_domain

    def delete_sssd_domain_log(self, domainname):
        """ Remove the sssd domain log

            :param str cache_path: domain name from default configuration file
            :return bool: True if deletion is successful
            :Exception: Raises exception(builtin)
        """
        path = ("/var/log/sssd/sssd_%s.log" % domainname)
        cmd = self.multihost.run_command(['rm', '-rf', path], raiseonerr=False)
        if cmd.returncode != 0:
            raise Exception("Error: %s", cmd.stderr_text)
        else:
            return True

    def get_ad_user_info(self, username, ad_host):
        """ Get the ad user information through 'net ads dn' command

            :param str username: The name of ad user
            :param str ad_host: Host of active directory
            :return bool: True is command is successful
            :return: output of command
            :Exception: Raises exception(builtin)
        """
        user_dn = "CN=%s,CN=Users,%s" % (username, ad_host.domain_basedn_entry)
        cmd = self.multihost.run_command(['net', 'ads', 'dn', user_dn],
                                         raiseonerr=False)
        if cmd.returncode != 0:
            raise Exception("Error: %s", cmd.stderr_text)
        else:
            return(True, cmd.stdout_text)

    def auth_from_client(self, username, password):
        """ ssh to user from client environment
        :param str username: The name of user
        :param str password: Login password of user
        :return: exit status
        if timeout the return status is 0
        if user successfully login then return status is 3
        if not then return status is 10
        """
        expect_script = 'spawn ssh -o NumberOfPasswordPrompts=1 ' \
                        '-o StrictHostKeyChecking=no '\
                        '-o UserKnownHostsFile=/dev/null ' \
                        '-l ' + username + ' localhost whoami' + '\n'
        expect_script += 'expect "*assword: "\n'
        expect_script += 'send "' + password + '\r"\n'
        expect_script += 'expect {\n'
        expect_script += '\ttimeout { set result_code 0 }\n'
        expect_script += '\t"' + username + '" { set result_code 3 }\n'
        expect_script += '\teof {}\n'
        expect_script += '\t"Permission denied " { set result_code 10 }\n'
        expect_script += '}\n'
        expect_script += 'exit $result_code\n'
        print(expect_script)
        rand_tag = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789')
                           for _ in range(10))
        exp_file = "/tmp/qe_pytest_expect_file" + rand_tag
        self.multihost.put_file_contents(exp_file, expect_script)
        print(("remote side expect script filename: %s") % exp_file)

        # Next run expect
        cmd = self.multihost.run_command(['expect', '-f', exp_file],
                                         raiseonerr=False)
        print("----expect output start----")
        print(cmd.stdout_text)
        print(cmd.stderr_text)
        print("----expect output end----")
        return cmd.returncode

    def config_etckrb5(self, realm, krb5_server=None):
        """ Configure /etc/krb5.conf with realm specified
            :param str realm: Kerberos realm
            :param krb5_server: kerberos server
            :return: None
            :Exception: Raise exception(builtin)
        """
        if krb5_server is None:
            krb5_server = self.multihost.sys_hostname
        if realm is None:
            raise Exception("Error: realm should be passed")
        else:
            realm_def = ("{\n"
                         "kdc = %s\n"
                         "admin_server = %s\n"
                         "}") % (krb5_server, krb5_server)
            krb5config = ConfigParser.RawConfigParser()
            krb5config.optionxform = str
            krb5config.add_section('logging')
            krb5config.set("logging", "default", "FILE:/var/log/krb5libs.log")
            krb5config.set("logging", "kdc", "FILE:/var/log/krb5kdc.log")
            krb5config.set("logging", "admin_server",
                           "FILE:/var/log/kadmind.log")
            krb5config.add_section('libdefaults')
            krb5config.set("libdefaults", "ticket_lifetime", "3600")
            krb5config.set("libdefaults", "default_realm", realm.upper())
            krb5config.set("libdefaults", "dns_lookup_realm", "false")
            krb5config.set("libdefaults", "dns_lookup_kdc", "false")
            krb5config.set("libdefaults", "allow_weak_crypto", "yes")
            krb5config.set("libdefaults", "forwardable", "true")
            krb5config.set("libdefaults", "rdns", "false")
            krb5config.add_section("realms")
            krb5config.set("realms", "realm", realm_def)
            krb5config.add_section("domain_realm")
            krb5config.set("domain_realm", realm.lower(), realm.upper())
            krb5config.set("domain_realm", ".%s" % (realm.lower()),
                           realm.upper())
            krb5config.add_section("appdefaults")
            krb5config.set("appdefaults", "validate", "true")
            krb5config.add_section("kdc")
            krb5config.set("kdc", "profile", "/var/kerberos/krb5kdc/kdc.conf")
            krb5config.add_section("pam")
            krb5config.set("pam", "debug", "false")
            krb5config.set("pam", "ticket_lifetime", "3600")
            krb5config.set("pam", "renew_lifetime", "3600")
            krb5config.set("pam", "forwardable", "true")
            temp_fd, temp_file_path = tempfile.mkstemp(suffix='conf',
                                                       prefix='krb5conf')
            with open(temp_file_path, "wb") as outfile:
                krb5config.write(outfile)
            self.multihost.run_command(['cp', '-f', '/etc/krb5.conf',
                                        '/etc/krb5.conf.orig'])
            self.multihost.transport.put_file(temp_file_path, '/etc/krb5.conf')
            os.close(temp_fd)

    def enable_kcm(self):
        """ Enable kcm
            :param: None
            :Return: None
            :Exception: Raise Exception("message")
        """
        kcm_cache_file = '/etc/krb5.conf.d/kcm_default_ccache'
        config = ConfigParser.SafeConfigParser()
        config.optionxform = str
        config.add_section('libdefaults')
        config.set('libdefaults', 'default_ccache_name', "KCM:")
        temp_fd, temp_file_path = tempfile.mkstemp(suffix='conf',
                                                   prefix='krb5cc')
        with open(temp_file_path, 'wb') as kcmfile:
            config.write(kcmfile)
        self.multihost.transport.put_file(temp_file_path, kcm_cache_file)
        os.close(temp_fd)
        enable_sssd_kcm_socket = 'systemctl enable sssd-kcm.socket'
        cmd = self.multihost.run_command(enable_sssd_kcm_socket,
                                         raiseonerr=False)
        symlink = '/etc/systemd/system/sockets.target.wants/sssd-kcm.socket'
        try:
            self.multihost.run_command(['ls', '-l', symlink])
        except subprocess.CalledProcessError:
            self.multihost.log.info("kcm socket not enabled")
            raise Exception("kcm socket not enabled")
        start_ssd_kcm_socket = 'systemctl start sssd-kcm.socket'
        cmd = self.multihost.run_command(start_ssd_kcm_socket,
                                         raiseonerr=False)
        if cmd.returncode != 0:
            raise Exception("sssd-kcm.socket service not started")
        start_sssd_kcm_service = 'systemctl enable sssd-kcm.service'
        cmd = self.multihost.run_command(start_sssd_kcm_service,
                                         raiseonerr=False)
        symlink = '/etc/systemd/system/sockets.target.wants/sssd-kcm.socket'
        if cmd.returncode != 0:
            raise Exception("sssd-kcm.service not enabled")
        try:
            self.multihost.run_command(['ls', '-l', symlink])
        except subprocess.CalledProcessError:
            self.multihost.log.info("kcm socket not enabled")
            raise Exception("kcm socket not enabled")


class LdapOperations(object):
    """
    LDapOperations consists of functions related to ldap operations, like
    adding entry, adding a DN, modifying DN, search entries.

    Attributes:
        uri(str): ldap server uri(ldap(s):///<hostname/ipaddress>
        binddn(str): Binddn required to bind
        bindpw(str): Bind password
        conn: ldap bind object (already  initialized)
    """

    def __init__(self, uri, binddn, bindpw):
        self.uri = uri
        self.binddn = binddn
        self.bindpw = bindpw
        self.conn = ldap.initialize(uri)
        self.conn = self.bind()
        if type(self.conn).__name__ != "instance":
            raise self.conn[0]

    def bind(self):
        """ Bind to ldap server
            :param: None
            :return: None
            :Exceptions: None
        """
        try:
            self.conn.simple_bind_s(self.binddn, self.bindpw)
        except ldap.SERVER_DOWN as err:
            return self._parseException(err)
        except ldap.INVALID_CREDENTIALS as err:
            return self._parseException(err)
        else:
            return self.conn

    def add_entry(self, entry, ldap_dn):
        """ Add an entry to ldap server
            :param dict entry: attributes/objectclass to be added to dn
            :param str dn: Entry dn to be added
        """
        print("Adding entry: %s" % (ldap_dn))
        ldif = modlist.addModlist(entry)
        try:
            self.conn.add_s(ldap_dn, ldif)
        except:
            raise
        else:
            return "Success", True

    def _parseException(self, err):
        """ Parsing Exception """
        return_value = False
        return err, return_value

    def del_dn(self, ldap_dn):
        """Delete dn
           :param str ldap_dn: DN to be deleted
           :return tupele: "Success", return_value
           :Exception: ldap exception
        """
        try:
            ret = self.conn.delete(ldap_dn)
        except:
            raise
        else:
            return "Success", ret

    def search(self, basedn, criteria, attributes, scope=ldap.SCOPE_SUBTREE):
        """ Search ldap server and return results

            :param str base: basedn of ldap server
            :param str criteria: Search criteria(ex:
                   "(&(objectClass=user)(sAMAccountName=Administrator))"
            :param str attributes: Attributes to be returned in the result
            :scope obj : scope to be used when search default:
                         ldap.SCOPE_SUBTREE
            :return tuple: Success/Fail, bool(True,False)
        """

        self.conn.set_option(ldap.OPT_REFERRALS, 0)
        result = self.conn.search_s(basedn, ldap.SCOPE_SUBTREE,
                                    criteria, attributes)
        result_set = [entry for _, entry in result if isinstance(entry, dict)]
        return result_set

    def modify_ldap(self, ldap_dn, modify_list):
        """ Modify ldap dn """
        try:
            self.conn.modify_s(ldap_dn, modify_list)
        except ldap.NO_SUCH_ATTRIBUTE:
            return "Fail", False
        except ldap.NO_SUCH_OBJECT as err:
            return self._parseException(err)
        except ldap.OBJECT_CLASS_VIOLATION as err:
            return self._parseException(err)
        except ldap.TYPE_OR_VALUE_EXISTS as err:
            return self._parseException(err)
        except ldap.UNWILLING_TO_PERFORM:
            return self._parseException(err)
        else:
            return 'Success', True

    def posix_user(self, org_unit, basedn, user_attr):
        """ Add POSIX Users
            :param str ou: Organizational unit (ou=Users)
            :param str basedn: Base dn ('dc=example,dc=test')
            :param dict user_attr: Entry attributes
            :Return bool: Return True
            :Exception: Raise Exception if unable to add user
        """
        common_name = user_attr['cn']
        uid = user_attr['uid']
        uidnumber = user_attr['uidNumber']
        gidnumber = user_attr['gidNumber']
        try:
            surname = user_attr['sn']
        except KeyError:
            surname = common_name
        try:
            shell = user_attr['loginShell']
        except KeyError:
            shell = '/bin/bash'
        try:
            password = user_attr['userPassword']
        except KeyError:
            password = 'Secret123'
        try:
            home_directory = user_attr['homeDirectory']
        except KeyError:
            home_directory = '/home/%s' % (uid)
        try:
            mail = user_attr['mail']
        except KeyError:
            mail = '%s@example.test' % (uid)
        try:
            gecos = user_attr['gecos']
        except KeyError:
            gecos = '%s User' % common_name
        try:
            location = user_attr['location']
        except KeyError:
            location = 'US'

        attr = {
            'objectClass': ['top', 'posixAccount', 'inetOrgPerson'],
            'cn': common_name, 'uid': uid, 'sn': surname, 'loginShell': shell,
            'homeDirectory': home_directory, 'uidNumber': uidnumber,
            'gidNumber': gidnumber, 'userPassword': password,
            'mail': mail, 'gecos': gecos, 'l': location}

        user_dn = 'uid=%s,%s,%s' % (uid, org_unit, basedn)
        (ret, _) = self.add_entry(attr, user_dn)
        if ret == 'Success':
            return True
        else:
            raise Exception('Unable to add User to ldap')

    def posix_group(self, org_unit, basedn, group_attr):
        """ Add POSIX group
            :param str ou: Organizational unit (ou=Groups)
            :param str basedn: Base dn ('dc=example,dc=test')
            :param dict group_attr: Entry attributes
            :Return bool: Return True
            :Exception: Raise Exception if unable to add user
        """
        group_cn = group_attr['cn']
        gidnumber = group_attr['gidNumber']
        member_dn = group_attr['uniqueMember']
        user_password = '{crypt}x'
        attr = {
            'objectClass': ['posixGroup', 'top', 'groupOfUniqueNames'],
            'gidNumber': gidnumber, 'cn': group_cn,
            'userPassword': user_password, 'uniqueMember': member_dn}

        group_dn = 'cn=%s,%s,%s' % (group_cn, org_unit, basedn)
        (ret, _) = self.add_entry(attr, group_dn)
        if ret != 'Success':
            raise Exception('Unable to add group to ldap')

    def enable_autofs_schema(self, basedn):
        """ Enable autofs schema

            :param str basedn: base dn of the ldap server
            :return: None
            :Exceptions: None
        """

        autofs_schema = ("""
dn: ou=automount,%s
ou: automount
objectClass: organizationalUnit

dn: CN=auto.master,OU=automount,%s
objectClass: top
objectClass: nisMap
cn: auto.master
nisMapName: auto.master

dn: cn=/-,cn=auto.master,ou=automount,%s
objectClass: nisObject
objectClass: top
cn: /-
nisMapEntry: auto.direct
nisMapName: auto.master

dn: cn=/home,cn=auto.master,ou=automount,%s
objectClass: nisObject
objectClass: top
cn: /home
nisMapEntry: auto.home
nisMapName: auto.master

dn: cn=auto.direct,ou=automount,%s
objectClass: nisMap
objectClass: top
cn: auto.direct
nisMapName: auto.direct

dn: cn=auto.home,ou=automount,%s
objectClass: nisMap
objectClass: top
nisMapName: auto.home""") % (basedn, basedn, basedn, basedn, basedn, basedn)
        ldif_file = StringIO(autofs_schema)
        parser = ldif.LDIFRecordList(ldif_file)
        parser.parse()

        for ldap_dn, entry in parser.all_records:
            self.add_entry(entry, ldap_dn)


class PkiTools(object):
    """
        PkiTools consists of functions related to creation of
        certificate requests, updating profile XML with certificate
        requests.
    """

    def __init__(self, nssdir=None, nssdir_pwd=None):

        if nssdir is None:
            self.nssdb = tempfile.mkdtemp('nssdir')
        else:
            self.nssdb = nssdir
        if nssdir_pwd is None:
            self.nssdb_pwd = 'Secret123'
        else:
            self.nssdb_pwd = nssdir_pwd
        self.pwdfilename = 'pwfile'
        self.noisefilename = 'noiseFile'
        self.pwdfilepath = os.path.join(self.nssdb, self.pwdfilename)
        self.noise = array.array('B', os.urandom(128))
        self.noisefilepath = os.path.join(self.nssdb, self.noisefilename)

    def create_nssdb(self):
        """
        Create a NSS Database on a temporary Directory

            :return:
            str nssdb: path of the NSS DB Directory
        """
        with open(self.pwdfilepath, 'w') as outfile:
            outfile.write(self.nssdb_pwd)
        certutil_cmd = 'certutil -N -d %s -f %s' % (self.nssdb,
                                                    self.pwdfilepath)
        _, _, ret = self.execute(shlex.split(certutil_cmd))
        if ret != 0:
            raise PkiLibException('Could not setup NSS DB on %s' % self.nssdb)
        else:
            return self.nssdb

    def execute(self,
                args,
                stdin=None,
                capture_output=True,
                raiseonerr=False,
                env=None,
                cwd=None):
        """
        Execute a command and return stdout, stderr and return code

        :param str args: List of arguments for the command
        :param str stdin: Optional input
        :param bool: capture_output: Capture output of the command
                     (default True)
        :param bool raiseonerr: Raise exception if command fails
        :param str env: Env variables to be set before the command is run
        :param str cwd: Current working Directory

        :return stdout, stderr and returncode: if command return code is 0
        :Exception: raises exception if raiseonerr is True
        """

        p_in = None
        p_out = None
        p_err = None
        if env is None:
            env = os.environ.copy()
        if capture_output:
            p_out = subprocess.PIPE
            p_err = subprocess.PIPE
        try:
            proc = subprocess.Popen(args, stdin=p_in, stdout=p_out,
                                    stderr=p_err, close_fds=True,
                                    env=env, cwd=cwd)
            stdout, stderr = proc.communicate(stdin)
        except KeyboardInterrupt:
            proc.wait()
            raise
        if proc.returncode != 0 and raiseonerr:
            raise subprocess.CalledProcessError(proc.returncode, args, stdout)
        else:
            return (stdout, stderr, proc.returncode)

    def createselfsignedcerts(self,
                              serverlist,
                              ca_dn=None,
                              passphrase='Secret123',
                              canickname='Example CA'):
        """
        Creates a NSS DB in /tmp/nssDirxxxx where self signed Root CA
        and Server Certs are created

        :param str CA_DN: Distinguished Name for CA Cert
        :param str Server_DN: Distinguished Name for Server Cert
        """
        if ca_dn is None:
            ca_dn = 'CN=Example CA,O=Example,L=Raleigh,C=US'
        nss_passphrase = passphrase
        pin_filename = 'pin.txt'
        nss_dir = self.create_nssdb()
        pin_filepath = os.path.join(nss_dir, pin_filename)
        ca_certpath = os.path.join(nss_dir, 'cacert.der')
        ca_pempath = os.path.join(nss_dir, 'cacert.pem')
        server_pempath = os.path.join(nss_dir, 'server.pem')
        with open(self.noisefilepath, 'w') as outfile:
            outfile.write(str(self.noise))
        ca_args = 'certutil -d %s -f %s -S -n "%s" -s %s' \
                  ' -t "CT,," -x -z %s' % (nss_dir, self.pwdfilepath,
                                           canickname, ca_dn,
                                           self.noisefilepath)

        ca_pem = 'certutil -d %s -f %s -L -n "%s"' \
                 '-a -o %s' % (nss_dir, self.pwdfilepath,
                               canickname, ca_pempath)

        with open(pin_filepath, 'w') as outfile:
            outfile.write('Internal (Software) Token:%s' % nss_passphrase)
        _, _, return_code = self.execute(shlex.split(ca_args))
        if return_code != 0:
            raise PkiLibException('Could not create Self signed CA Cert')
        else:
            self.execute(shlex.split(ca_pem))

        for server in serverlist:
            server_cn = 'CN=%s' % (server)
            server_nickname = 'Server-Cert-%s' % (server)
            server_pem = 'certutil -d %s -f %s -L '\
                         '-n "%s" -a -o %s' % (nss_dir,
                                               self.pwdfilepath,
                                               server_nickname,
                                               server_pempath)
            rand_var = str(random.randint(1000, 2000))
            server_args = 'certutil -d %s -f %s -S -n "%s" -s %s -c "%s"'\
                          ' -t u,u,u -v 720 -m %s -z %s' % (nss_dir,
                                                            self.pwdfilepath,
                                                            server_nickname,
                                                            server_cn,
                                                            canickname,
                                                            rand_var,
                                                            self.noisefilepath)
            _, _, return_code = self.execute(shlex.split(server_args))
            if return_code != 0:
                raise PkiLibException('Could not create Server-Cert')
            else:
                _, _, return_code = self.execute(shlex.split(server_pem))
                if return_code != 0:
                    raise PkiLibException('Could not create Server pem file')
                return nss_dir


class ADOperations(object):
    """
    ADOperations class consists of methods related to managing AD User With
    Unix properties.
    """
    def __init__(self, ad_host):
        self.ad_host = ad_host
        self.ad_uri = 'ldap://%s' % ad_host.external_hostname
        host_domain_basedn_entry = self.ad_host.domain_basedn_entry
        self.ad_users_dn_entry = '{},{}'.format('CN=Users',
                                                host_domain_basedn_entry)
        self.ad_dn = 'CN={},{}'.format("Administrator", self.ad_users_dn_entry)
        self.ad_admin_passwd = self.ad_host.ssh_password
        cmd = ['powershell.exe',
               '-inputformat',
               'none',
               '-noprofile',
               '(Get-ADDomain -Current LocalComputer).NetBIOSName']
        self._ad_netbionsname = self.ad_host.run_command(cmd).stdout_text

    def ad_conn(self):
        """ Create a LDAP Connection with AD

        :param None
        :Return obj: Object of LdapOperations
        :Exceptions: None
        """

        ad_conn_inst = LdapOperations(self.ad_uri, self.ad_dn,
                                      self.ad_admin_passwd)
        return ad_conn_inst

    def create_ad_unix_user_group(self, username, groupname,
                                  password='Secret123'):
        """ Create a AD User with Unix Attributes

        :param str username: AD User Name
        :param str groupname: AD Group Name
        :param str password: User password (default: Secret123)
        :Return bool: if user/group added correctly return True else False
        :Exceptions: False
        """

        uid = random.randint(9999, 999999)
        user_dn = "CN=%s,%s" % (username, self.ad_users_dn_entry)
        group_dn = "CN=%s,%s" % (groupname, self.ad_users_dn_entry)
        cmd = self.ad_host.run_command(['dsadd.exe', 'user', user_dn, '-samid',
                                        username, '-pwd', password])
        cmd = self.ad_host.run_command(['dsadd.exe', 'group', group_dn])
        cmd = self.ad_host.run_command(['dsmod', 'group', group_dn, '-addmbr',
                                        user_dn])
        ad_conn_inst = self.ad_conn()
        if cmd.returncode == 0:
            mod_dn = [(ldap.MOD_ADD, 'msSFU30NisDomain', self.ad_netbiosname)]
            (_, _) = ad_conn_inst.modify_ldap(user_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'uidNumber', str(uid))]
            (_, _) = ad_conn_inst.modify_ldap(user_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'gidNumber', str(uid))]
            (_, _) = ad_conn_inst.modify_ldap(user_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'unixHomeDirectory',
                       '/home/%s' % (username))]
            (_, _) = ad_conn_inst.modify_ldap(user_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'loginShell', '/bin/bash')]
            (_, _) = ad_conn_inst.modify_ldap(user_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'msSFU30Name', username)]
            (_, _) = ad_conn_inst.modify_ldap(user_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'msSFU30NisDomain', self.ad_netbiosname)]
            (_, _) = ad_conn_inst.modify_ldap(group_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'gidNumber', str(uid))]
            (_, _) = ad_conn_inst.modify_ldap(group_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'msSFU30Name', groupname)]
            (_, _) = ad_conn_inst.modify_ldap(group_dn, mod_dn)
        else:
            return False
        return True

    def create_ad_unix_group(self, groupname):
        """ Create AD Group with UNIX Attributes

        :param str groupname: Windows AD Group name
        :Return bool : True if AD group was created with Unix Attributes
        :Exceptions: None
        """

        gid = random.randint(9999, 999999)
        group_dn = "CN=%s,%s" % (groupname, self.ad_users_dn_entry)
        cmd = self.ad_host.run_command(['dsadd.exe', 'group', group_dn])
        ad_conn_inst = self.ad_conn()
        if cmd.returncode == 0:
            mod_dn = [(ldap.MOD_ADD, 'msSFU30NisDomain', self.ad_netbiosname)]
            (_, _) = ad_conn_inst.modify_ldap(group_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'gidNumber', str(gid))]
            (_, _) = ad_conn_inst.modify_ldap(group_dn, mod_dn)
            mod_dn = [(ldap.MOD_ADD, 'msSFU30Name', groupname)]
            (_, _) = ad_conn_inst.modify_ldap(group_dn, mod_dn)
        else:
            return False
        return True

    def delete_ad_user_group(self, user_group):
        """ Delete AD user

        :param str user_group: User or Group Name to be deleted
        :Return bool: True if delete is successful else false
        :Exceptions: None
        """

        ad_entry = 'CN=%s,%s' % (user_group, self.ad_users_dn_entry)
        try:
            self.ad_host.run_command(['dsrm.exe', ad_entry, '-noprompt'])
        except CalledProcessError:
            return False
        else:
            return True

    def add_user_member_of_group(self, group, user):
        """ Add user member of a group

        :param str group: Name of Windows AD Group
        :param str user: Name of Windows AD user
        :Return bool: True if user is added as member to group
        :Exceptions: None
        """

        group_dn = 'CN=%s,%s' % (group, self.ad_users_dn_entry)
        user_dn = 'CN=%s,%s' % (user, self.ad_users_dn_entry)
        try:
            self.ad_host.run_command(['dsmod', 'group', group_dn, '-addmbr',
                                      user_dn])
        except CalledProcessError:
            return False
        else:
            return True

    def remove_user_from_group(self, group, user):
        """ Remove User from Group membership

        :param str group: Name of Windows AD Group
        :param str user: Name of Windows AD user
        :Return bool: True if user is removed from group else False
        :Exceptions: None
        """

        group_dn = 'CN=%s,%s' % (group, self.ad_users_dn_entry)
        user_dn = 'CN=%s,%s' % (user, self.ad_users_dn_entry)
        try:
            self.ad_host.run_command(['dsmod', 'group', group_dn, '-rmmbr',
                                      user_dn])
        except CalledProcessError:
            return False
        return True


class SSHClient(paramiko.SSHClient):
    """ This class Inherits paramiko.SSHClient and implements client.exec_commands
    channel.exec_command """

    def __init__(self, hostname=None, port=None, username=None, password=None):
        """ Initialize connection to Remote Host using Paramiko SSHClient. Can be
        initialized with hostname, port, username and password.
        """
        self.hostname = hostname
        self.username = username
        self.password = password

        if port is None:
            self.port = 22
        else:
            self.port = port

        paramiko.SSHClient.__init__(self)
        self.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.connect(self.hostname, port=self.port,
                         username=self.username,
                         password=self.password,
                         timeout=30)
        except (paramiko.AuthenticationException,
                paramiko.SSHException,
                socket.error):
            raise

    def execute_cmd(self, args, stdin=None):
        """ This Function executes commands using SSHClient.exec_commands().
        :param str args: actual command to run
        :param str stdin: stdin for the command
        :Return tuple: stdin stdout stderr
        :Exception: paramiko.SSHException
        """
        if PARAMIKO_VERSION >= (1, 15, 0):
            try:
                std_in, std_out, std_err = self.exec_command(args, timeout=30)
            except paramiko.SSHException:
                raise
            else:
                if stdin:
                    std_in.write("%s\n" % (stdin))
                    std_in.flush()
                exit_status = std_out.channel.recv_exit_status()
                return std_out, std_err, exit_status
        else:
            try:
                std_in, std_out, std_err = self.exec_command(args)
            except paramiko.SSHException:
                raise
            else:
                if stdin:
                    std_in.write("%s\n" % (stdin))
                    std_in.flush()
                exit_status = std_out.channel.recv_exit_status()
                return std_out, std_err, exit_status
