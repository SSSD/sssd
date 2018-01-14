"""This module contains methods to create Directory Server Instance."""
from __future__ import print_function
import os
import ConfigParser
import tempfile
import subprocess
import socket
import time
import ldap
from sssd.testlib.common.exceptions import DirSrvException
from sssd.testlib.common.exceptions import LdapException
from sssd.testlib.common.utils import LdapOperations

DS_USER = 'nobody'
DS_GROUP = 'nobody'
DS_ADMIN = 'admin'
DS_ROOTDN = 'CN=Directory Manager'


class DirSrv(object):
    """Base class to setup DS Instances

    For setting up Directory Server, enabling TLS, and
    removing of Directory Server instance.
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self, **kwargs):
        """Initialize name, suffix, host, ports, Directory Manager password."""
        self.instance_name = kwargs.get('name')
        self.dsinstance_host = kwargs.get('host')
        self.dsinstance_suffix = kwargs.get('suffix')
        self.multihost = kwargs.get('multihost')
        self.dsrootdn_pwd = kwargs.get('root_dn_password')
        self.dsldap_port = kwargs.get('ldap_port', None)
        self.dstls_port = kwargs.get('ldap_tls_port', None)
        self.dsrootdn = DS_ROOTDN
        self.ds_inst_name = 'slapd-%s' % self.instance_name
        self.dsrootdir = '/etc/dirsrv'
        self.dsinst_path = os.path.join(self.dsrootdir, self.ds_inst_name)

    def __str__(self):
        return "%s.%s('%r')" % (self.__module__, self.__class__.__name__,
                                self.__dict__)

    def __repr__(self):
        return '%s(%s, %r)' % (self.__module__, self.__class__.__name__,
                               self.__dict__)

    def create_config(self):
        """create config file for setup-ds.pl to setup DS instances.

        Args:
            param1 (None):

        Returns:
            str: Returns path of the config file

        Exceptions:
            None
        """
        config = ConfigParser.RawConfigParser()
        config.optionxform = str
        config.add_section('General')
        config.set('General', 'FullMachineName', self.dsinstance_host)
        config.set('General', 'SuiteSpotUserID', DS_USER)
        config.set('General', 'SuiteSpotGroup', DS_GROUP)
        config.set('General', 'ConfigDirectoryAdminID', DS_ADMIN)
        config.add_section('slapd')
        config.set('slapd', 'ServerIdentifier', self.instance_name)
        config.set('slapd', 'ServerPort', self.dsldap_port)
        config.set('slapd', 'Suffix', self.dsinstance_suffix)
        config.set('slapd', 'RootDN', self.dsrootdn)
        config.set('slapd', 'RootDNPwd', self.dsrootdn_pwd)

        (ds_config, ds_config_file_path) = tempfile.mkstemp(suffix='cfg')
        os.close(ds_config)
        with open(ds_config_file_path, "wb") as outfile:
            config.write(outfile)
        return ds_config_file_path

    def setup_ds(self, ds_cfg_file):
        """create DS instance by running setup-ds.pl.

        Args:
             ds_config_file (str): ds_config_file: Configuration File path

        Returns:
             bool: True if setup-ds.pl ran successfully else False

        Exceptions:
             subprocess.CalledProcessError:
        """
        self.multihost.transport.put_file(ds_cfg_file, '/tmp/test.cfg')
        setup_args = ['setup-ds.pl', '--silent',
                      '--file=/tmp/test.cfg', '--debug']
        try:
            self.multihost.run_command(setup_args)
        except subprocess.CalledProcessError:
            raise
        else:
            os.remove(ds_cfg_file)
            return True

    def remove_ds(self, inst_name=None):
        """Remove Directory Server instance

        Args:
            inst_name (str): DS Instance name

        Returns:
            None

        Exceptions:
            subprocess.CalledProcessError
        """
        if inst_name is None:
            inst_name = self.ds_inst_name
        remove_args = ['remove-ds.pl', '-i', inst_name, '-d']
        try:
            self.multihost.run_command(remove_args)
        except subprocess.CalledProcessError:
            raise

    def setup_certs(self, ssl_dir):
        """copy CA and Server certs to all DS instances.

        Args:
            ssl_dir (str): NSS Directory containing CA and Server-Certs

        Returns:
            bool: True if files are copied

        Exceptions:
            DirSrvException
        """
        # We stop directory server before we copy files. This is required
        # because it's seen that at times, if ns-slapd process is reading
        # the db files, copying of files is successful but not all data
        # is written causing the files to go corrupt.
        stop_ds = ['systemctl', 'stop', 'dirsrv@%s' % (self.instance_name)]
        try:
            self.multihost.run_command(stop_ds)
        except subprocess.CalledProcessError:
            return True
        else:
            self.multihost.log.info('DS instance stopped successfully')
        nss_db_files = ['cert8.db', 'key3.db', 'secmod.db', 'pin.txt']
        dirsrv_cert_path = '/etc/dirsrv/' + self.ds_inst_name + '/cacert.pem'
        cacert_file_path = '%s/cacert.pem' % ('/etc/openldap/cacerts')
        for db_file in nss_db_files:
            source = os.path.join(ssl_dir, db_file)
            destination = os.path.join(self.dsinst_path, db_file)
            self.multihost.transport.put_file(source, destination)
        target_pin_file = os.path.join(self.dsinst_path, 'pin.txt')
        change_ownership = ['chown', DS_USER, target_pin_file]
        change_group = ['chgrp', DS_GROUP, target_pin_file]
        chmod_file = ['chmod', '600', target_pin_file]
        # copy the cacert file to test_dir
        create_cert_dir = 'mkdir -p /etc/openldap/cacerts'
        self.multihost.run_command(create_cert_dir)
        self.multihost.transport.put_file(os.path.join(
            ssl_dir, 'cacert.pem'), cacert_file_path)
        try:
            self.multihost.run_command(change_ownership)
        except subprocess.CalledProcessError:
            raise DirSrvException(
                'fail to user change ownership of pin.txt fail')
        try:
            self.multihost.run_command(change_group)
        except subprocess.CalledProcessError:
            raise DirSrvException(
                'fail to change group ownership of pin.txt file')
        try:
            self.multihost.run_command(chmod_file)
        except subprocess.CalledProcessError:
            raise DirSrvException('fail to change permissions of pin.txt file')
        start_ds = ['systemctl', 'start', 'dirsrv@%s' % (self.instance_name)]
        try:
            self.multihost.run_command(start_ds)
        except subprocess.CalledProcessError:
            raise DirSrvException('Could not Start DS Instance')
        else:
            self.multihost.log.info('DS instance started successfully')
            ca = self.multihost.get_file_contents(cacert_file_path)
            self.multihost.transport.put_file_contents(dirsrv_cert_path, ca)

    def enable_ssl(self, binduri, tls_port):
        """sets TLS Port and enabled TLS on Directory Server.

        Args:
            binduri (str): LDAP uri to bind with
            tls_port (str): TLS port to be setup

        Returns:
            bool: True if successfully setup TLS port

        Exceptions:
            LdapException
        """
        ldap_obj = LdapOperations(uri=binduri, binddn=self.dsrootdn,
                                  bindpw=self.dsrootdn_pwd)
        # Enable TLS
        mod_dn1 = 'cn=encryption,cn=config'
        add_tls = [(ldap.MOD_ADD, 'nsTLS1', 'on')]
        (ret, return_value) = ldap_obj.modify_ldap(mod_dn1, add_tls)
        if not return_value:
            raise LdapException('fail to enable TLS, Error:%s' % (ret))
        else:
            print('Enabled nsTLS1=on')

        entry1 = {
            'objectClass': ['top', 'nsEncryptionModule'],
            'cn': 'RSA',
            'nsSSLtoken': 'internal (software)',
            'nsSSLPersonalitySSL': 'Server-Cert-%s' % (self.dsinstance_host),
            'nsSSLActivation': 'on'
            }
        dn1 = 'cn=RSA,cn=encryption,cn=config'
        (ret, return_value) = ldap_obj.add_entry(entry1, dn1)
        if not return_value:
            raise LdapException('fail to set Server-Cert nick:%s' % (ret))
        else:
            print('Enabled Server-Cert nick')

        # Enable security
        mod_dn2 = 'cn=config'
        enable_security = [(ldap.MOD_REPLACE, 'nsslapd-security', 'on')]
        (ret, return_value) = ldap_obj.modify_ldap(mod_dn2, enable_security)
        if not return_value:
            raise LdapException(
                'fail to enable nsslapd-security, Error:%s' % (ret))
        else:
            print('Enabled nsslapd-security')

        # set the appropriate TLS port
        mod_dn3 = 'cn=config'
        enable_ssl_port = [(ldap.MOD_REPLACE, 'nsslapd-securePort',
                            str(tls_port))]
        (ret, return_value) = ldap_obj.modify_ldap(mod_dn3, enable_ssl_port)
        if not return_value:
            raise LdapException(
                'fail to set nsslapd-securePort, Error:%s' % (ret))
        else:
            print('Enabled nsslapd-securePort=%r' % tls_port)


class DirSrvWrap(object):
    """This is a wrapper class for DirSrv.

    This is a wrapper class of DirSrv class which validates
    all the inputs sent to Dirsrv object. Specifies ports for
    LDAP and TLS ports, specifies default suffix.
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self, multihost_obj, ssl=None, ssldb=None):
        """
        Create a DirSrv object for a specific Host. Specify the ports,
        instance details to the Dirsrv object

        Args:
            multihost_obj (obj): Multihost object
            ssl (bool): set True to enable SSL else none/False
            ssldb (str): Directory containing CA and server certs
        """
        self.ds_used_ports = {}
        self.dirsrv_info = {}
        self.dirsrv_obj = None
        self.ds_instance_name = None
        self.multihost = multihost_obj
        self.ds_instance_host = self.multihost.sys_hostname
        self.ds_instance_suffix = None
        self.ds_rootdn_pwd = None
        self.ds_ldap_port = None
        self.ds_tls_port = None
        self.ssl = ssl
        if self.ssl:
            self.ssl_dir = ssldb

    def __iter__(self):
        """ iter values of each instance """
        return self.dirsrv_info.itervalues()

    def __getitem__(self, key):
        """ Return values of each instance """
        return self.dirsrv_info[key]

    def _set_options(self,
                     instance_name,
                     instance_suffix,
                     root_dn_pwd,
                     ldap_port,
                     tls_port):
        """set Default values.

        Args:
            instance_name (str): DS Instance Name
            instance_suffix (str): DS Instance Suffix
            root_dn_pwd (str): Directory Manager password
            ldap_port (str): LDAP port
            tls_port (str): TLS Port

        Returns:
              A tuple containing 'Success', 0 or Failed Message and 1
              for failure to setup ports

        Exceptions:
              None
        """
        self.ds_instance_name = instance_name
        if instance_suffix:
            self.ds_instance_suffix = instance_suffix
        else:
            self.ds_instance_suffix = 'dc=example,dc=org'

        if root_dn_pwd:
            self.ds_rootdn_pwd = root_dn_pwd
        else:
            self.ds_rootdn_pwd = 'Secret123'
        # Get ports
        try:
            self.ds_ldap_port, self.ds_tls_port = self._set_ports(
                ldap_port, tls_port)
        except IndexError:
            return "No more ports available", 1
        else:
            self.ds_used_ports[self.ds_instance_name] = [
                self.ds_ldap_port, self.ds_tls_port]

        # validate instance
        try:
            self._validate_options()
        except DirSrvException as err:
            return err.msg, err.rval
        else:
            return "Success", 0

    def _set_ports(self, u_port, e_port):
        """return ports required to setup DS Instance.

        Idea behind this is when a directory server instance needs
        to be created we need ports for LDAP and SSL ports.
        1. check if LDAP port and SSL port is given
        1.1 If given, verify if the ports are available(not used)
        1.1.1 Bind that port to ldap_port_t using semanage command
        1.1.2 Use the ports and add it to the self.UsedPorts list
        1.2 else raise exception
        2. If LDAP port and SSL port is not given
        2.1 Check if the ports are available(not used)
        2.1.1 Bind the port to ldap_port_t using semanage command
        2.1.2 Use the ports and add it to self.ds_used_ports list

        Args:
           u_port (str): unencrypted LDAP port
           e_port (str): Encrypted port to be used for TLS

        Returns:
              sorted_available_ports[0] (list): LDAP and TLS ports
        """
        ds_ports = [389, 1389, 2389, 3389, 4389, 30389, 31389, 32389, 33389,
                    34389, 35389, 36389, 37389, 38389, 39389]
        tls_ports = [636, 1636, 2636, 3636, 4636, 30636, 31636, 32636, 33636,
                     34636, 35636, 36636, 37636, 38636, 39636]

        if u_port is None and e_port is None:
            for ldap_port, ldaps_port in zip(ds_ports, tls_ports):
                if (self._check_remote_port(ldap_port) or
                        self._check_remote_port(ldaps_port)):
                    pass
                else:
                    return ldap_port, ldaps_port
        else:
            list_a = []
            for ports in self.ds_used_ports.values():
                list_a.append(ports)

            list_b = []
            for l_port, s_port in zip(ds_ports, tls_ports):
                list_b.append((l_port, s_port))

            if len(set(list_a)) > len(set(list_b)):
                available_ports = set(list_a) - set(list_b)
            else:
                available_ports = set(list_b) - set(list_a)
            sorted_available_ports = sorted(available_ports)
            return sorted_available_ports[0]

    def _check_remote_port(self, port):
        """check if the port on the remote host is free.

        Args:
            port (int): check if port is available

        Returns:
            bool: True if port is free else False.
        """
        sock_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_obj.settimeout(1)
        try:
            sock_obj.connect((self.ds_instance_host, port))
        except socket.error as err:
            print("fail to connect to port %s due to error %r" % (port,
                                                                  err.errno))
            return False
        else:
            sock_obj.close()
            return True

    def _validate_options(self):
        """verify if the instance directory already exists.

        Args:
            None

        Returns:
            None

        Exceptions:
            DirSrvException: if instance directory already exists
        """
        check_instance = ['/usr/bin/ls', '/etc/dirsrv/slapd-%s' %
                          self.ds_instance_name]
        output = self.multihost.run_command(check_instance, raiseonerr=False)
        if output.returncode == 0:
            raise DirSrvException('%s Instance already exists' %
                                  self.ds_instance_name)

    def create_ds_instance(self,
                           inst_name,
                           inst_suffix=None,
                           root_dn_pwd=None,
                           ldap_port=None,
                           tls_port=None):
        """create Directory server instance.

        Args:
            inst_name (str): Instance Name
            inst_suffix (str): Instance suffix
            root_dn_pwd (str): Directory Manager password
            ldap_port (str): LDAP port to be used
            tls_port (str): TLS port to be used

        Returns:
            result (str) and return code (str): Result containing message and
            return code containing 0 or 1 (1 indicating failure)

        Exceptions:
            DirSrvException: if DS instance could not be created.
        """
        result, return_code = self._set_options(inst_name,
                                                inst_suffix,
                                                root_dn_pwd,
                                                ldap_port,
                                                tls_port)
        if return_code == 0:
            self.dirsrv_obj = DirSrv(name=self.ds_instance_name,
                                     host=self.ds_instance_host,
                                     suffix=self.ds_instance_suffix,
                                     multihost=self.multihost,
                                     root_dn_password=self.ds_rootdn_pwd,
                                     ldap_port=self.ds_ldap_port,
                                     tls_port=self.ds_tls_port)
            cfg_file = self.dirsrv_obj.create_config()
            try:
                self.dirsrv_obj.setup_ds(cfg_file)
            except subprocess.CalledProcessError:
                raise DirSrvException('fail to DS config file to setup')
            self.dirsrv_info[self.ds_instance_name] = self.dirsrv_obj.__dict__
            if self.ssl:
                try:
                    self.dirsrv_obj.setup_certs(self.ssl_dir)
                except DirSrvException as err:
                    return err.msg, err.rval
                else:
                    (result, return_code) = self.enablessl()
            return result, return_code
        else:
            raise DirSrvException('fail to setup Directory Server instance')

    def enablessl(self):
        """Enable SSL/TLS on instance.

        Enable by adding TLS port to ldap_port_t SELinux label and restart
        Directory Server.

        Args:
            None

        Returns:
            Tuple: Success, 0 or Error, 1

        Exceptions:
            None:
        """
        # add TLS port to ldap_port_t SELinux label

        add_tls_port = ['semanage', 'port', '-a', '-t',
                        'ldap_port_t', '-p', 'tcp', str(self.ds_tls_port)]

        restart_ds = ['systemctl', 'restart', 'dirsrv@%s' %
                      self.ds_instance_name]
        if self.ds_tls_port != 636:
            try:
                self.multihost.run_command(add_tls_port)
            except subprocess.CalledProcessError:
                return "Unable to set tls_port as ldap_port_t", 1
            else:
                self.multihost.log.info('Added %s port to ldap_port_t' %
                                        self.ds_tls_port)
        try:
            self.dirsrv_obj.enable_ssl('ldap://%s:%r' % (self.ds_instance_host,
                                                         self.ds_ldap_port),
                                       self.ds_tls_port)
        except LdapException:
            return "Error", 1

        try:
            self.multihost.run_command(restart_ds)
        except subprocess.CalledProcessError:
            return "Error", 1
        else:
            self.multihost.log.info('DS instance restarted successfully')
            # sleep for 10 seconds
            time.sleep(10)
            tail_cmd = ['tail', '-n', '100',
                        '/var/log/dirsrv/slapd-%s/errors' % self.
                        ds_instance_name]
            output = self.multihost.run_command(tail_cmd, raiseonerr=False)
            if output.returncode != 0:
                return "Error", 1
            else:
                return "Success", 0

    def remove_ds_instance(self, instance_name):
        """remove Directory server instance.

        Args:
            instance_name (str): Instance Name

        Returns:
            bool: True if successfully removed

        Exceptions:
            DirSrvException: if DS instance cannot be removed
        """
        ret = self.dirsrv_info[instance_name]
        if ret['instance_name'] == instance_name:
            ds_inst_name = ret['ds_inst_name']
            try:
                self.dirsrv_obj.remove_ds(ds_inst_name)
            except subprocess.CalledProcessError:
                raise DirSrvException('Could not remove DS Instance',
                                      ds_inst_name)
            else:
                del self.ds_used_ports[instance_name]
                return True
        else:
            raise DirSrvException('%s Instance could not found' %
                                  (instance_name))
