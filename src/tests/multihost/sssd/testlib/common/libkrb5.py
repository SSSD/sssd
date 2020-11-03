from __future__ import print_function

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import tempfile
import os
import subprocess


class krb5srv(object):
    """ Base class to setup MIT Kerberos server
        Default Kerberos Server realm is "EXAMPLE.TEST"
        Default Admin password is "Secret123"
    """

    def __init__(self, multihost, krb_realm=None):
        """ Initialize realm, host, ports, Kerberos admin password """
        if krb_realm is None:
            self.krb_realm = 'EXAMPLE.TEST'
        else:
            self.krb_realm = krb_realm.upper()
        self.multihost = multihost
        self.kdc_port = '88'
        self.kadmin_port = '749'
        self.admin_password = 'Secret123'
        self.krb5_kdc_data_dir = '/var/kerberos/krb5kdc'
        self.krb5_kdc_sysconfig = '/etc/sysconfig/krb5kdc'
        self.krb5_log_file = '/var/log/krb5kdc.log'
        self.admin_keytab = '%s/kadm5.keytab' % (self.krb5_kdc_data_dir)
        self.kadmin_log_file = '/var/log/kadmind.log'
        self.krb_acl_file = '%s/kadm5.acl' % (self.krb5_kdc_data_dir)
        self.admin_keytab = '%s/kadm5.keytab' % (self.krb5_kdc_data_dir)
        self.kdc_conf = '%s/kdc.conf' % (self.krb5_kdc_data_dir)

    def _config_krb5kdc(self):
        """ Configure kdc.conf and kadm5.acl
            :param: None
            :return str: Return Kerberos kdc.conf file path
        """
        realm_def = """ {
        acl_file = %s
        admin_keytab = %s
        } """ % (self.krb_acl_file,
                 self.admin_keytab)
        config = ConfigParser.RawConfigParser()
        config.optionxform = str
        config.add_section('kdcdefaults')
        config.set('kdcdefaults', 'kdc_ports', self.kdc_port)
        config.set('kdcdefaults', 'kdc_tcp_ports', self.kdc_port)
        config.add_section('logging')
        config.set('logging', 'kdc', 'FILE:%s' % (self.krb5_log_file))
        config.set('logging', 'admin_server', 'File:%s' %
                   (self.kadmin_log_file))
        config.add_section('realms')
        config.set('realms', self.krb_realm, realm_def)

        (krb_config, krb_config_path) = tempfile.mkstemp(suffix='cfg')
        os.close(krb_config)
        with open(krb_config_path, "w") as outfile:
            config.write(outfile)
        return krb_config_path

    def _krb_acl_config(self):
        """ Create ACL file
            :param: None
            :return: Config file path
        """
        acl = "*/%s@%s *" % ('admin', self.krb_realm)
        (acl_config, acl_config_path) = tempfile.mkstemp(suffix='cfg')
        os.close(acl_config)
        with open(acl_config_path, "w") as outfile:
            outfile.write(acl)
        return acl_config_path

    def krb_setup_new(self):
        """ Setup new Kerberos REALM
            :param: None
            :return: None
            :Exception: Raises subprocess.CalledProcessError
        """
        krb_config_path = self._config_krb5kdc()
        acl_file = self._krb_acl_config()
        self.multihost.transport.put_file(krb_config_path, self.kdc_conf)
        self.multihost.transport.put_file(acl_file, self.krb_acl_file)
        kdb5_util_create = ['kdb5_util', 'create', '-W', '-r',
                            self.krb_realm, '-s', '-P', '""']

        try:
            self.multihost.run_command(kdb5_util_create)
        except subprocess.CalledProcessError:
            raise

        try:
            self.add_principal(p_type='admin',
                               password=self.admin_password,
                               service='admin',
                               service_name='admin')
        except subprocess.CalledProcessError:
            raise
        else:
            self.multihost.log.info("created REALM %s" % (self.krb_realm))

        try:
            self.add_principal(p_type='admin',
                               password=self.admin_password,
                               service='root')
        except subprocess.CalledProcessError:
            raise

        try:
            self.add_principal(p_type=None, service='host',
                               service_name=self.multihost.sys_hostname)
        except subprocess.CalledProcessError:
            raise
        else:
            self.multihost.log.info("host principal added")

        try:
            self.multihost.run_command(['kadmin.local', '-r', self.krb_realm,
                                        '-q', "ktadd host/%s" %
                                        (self.multihost.sys_hostname)])
        except subprocess.CalledProcessError:
            raise
        try:
            self.multihost.run_command(['kadmin.local', '-r', self.krb_realm,
                                        '-q', "ktadd -k %s kadmin/admin" %
                                        (self.admin_keytab)])
        except subprocess.CalledProcessError:
            raise

        try:
            self.multihost.run_command(['kadmin.local', '-r', self.krb_realm,
                                        '-q', "ktadd -k %s kadmin/changepw" %
                                        (self.admin_keytab)])
        except subprocess.CalledProcessError:
            raise

        try:
            self.multihost.run_command(['systemctl', 'start', 'krb5kdc'])
        except subprocess.CalledProcessError:
            raise
        else:
            self.multihost.log.info("krb5kdc service start successful")
        try:
            self.multihost.run_command(['systemctl', 'start', 'kadmin'])
        except subprocess.CalledProcessError:
            raise
        else:
            self.multihost.log.info("kadmin service started successfully")

    def add_principal(self, principal=None,
                      p_type='user',
                      password=None,
                      service=None,
                      service_name=None,
                      etype=None):
        """ Add server/user principals to Kerberos server
            :param str principal: principal name (foobar)
            :param str p_type: principal type (user/admin/None)
            :param str password: password ('Secret123')
            :param str service: service principal (host/http/nfs)
            :param str service_name: Hostname where service is run
            :return bool: True if principal is added
            :Exception: Raise subprocess.CalledProcessError
        """
        # Todo: Need to check if a principal already exists before adding.
        if service is None:
            service = 'host'

        if p_type is 'user':
            add_principal = "add_principal -clearpolicy"\
                            " -pw %s %s@%s" % (password, principal,
                                               self.krb_realm)
            if etype:
                add_principal = "add_principal -clearpolicy"\
                                " -e %s -pw %s %s@%s" % (etype, password,
                                                         principal,
                                                         self.krb_realm)
            kadmin_local_cmd = ['kadmin.local', '-r',
                                self.krb_realm, '-q', add_principal]
        elif p_type is 'admin':
            add_principal = "add_principal -clearpolicy"\
                            " -pw %s %s/%s" % (password, service, 'admin')
            kadmin_local_cmd = ['kadmin.local', '-r', self.krb_realm,
                                '-q', add_principal]
        else:
            add_principal = "add_principal -clearpolicy"\
                            " -randkey %s/%s" % (service, service_name)
            kadmin_local_cmd = ['kadmin.local', '-r', self.krb_realm,
                                '-q', add_principal]
        try:
            self.multihost.run_command(kadmin_local_cmd)
        except subprocess.CalledProcessError:
            raise
        else:
            return True

    def delete_principal(self, principal):
        """ Delete kerberos principal
        :param str principal: principal name (foobar)
        :return bool: True if principal is deleted
        :Exception: Raise subprocess.CalledProcessError
        """
        del_principal = "delete_principal -force principal"
        kadmin_local_cmd = ['kadmin.local', '-r',
                            self.krb_realm, '-q', del_principal]
        try:
            self.multihost.run_command(kadmin_local_cmd)
        except subprocess.CalledProcessError:
            raise
        else:
            return True

    def add_remove_keytab(self, comp_principal=None,
                          location=None,
                          operation=None):
        """ Add or Remove keytab  to Kerberos principal
            :param str com_principal: complete comp_principal
             example(abc@EXAMPLE.COM)
            :param str location: location of keytab file with
             .keytab extension ('/etc/krb5.keytab)
            :param str operation: Value must add or remove
            :return bool: True if keytab is added
            :Exception: Raise subprocess.CalledProcessError
        """

        if operation == 'add':
            ops = 'ktadd'

        elif operation == 'remove':
            ops = 'ktremove'

        else:
            return False

        if location is None:
            location = '/etc/krb5.keytab'

        add_keytab = "%s -k "\
            "%s %s@%s" % (ops, location, comp_principal,
                          self.krb_realm)
        kadmin_local_cmd = ['kadmin.local', '-r',
                            self.krb_realm, '-q', add_keytab]

        try:
            self.multihost.run_command(kadmin_local_cmd)
        except subprocess.CalledProcessError:
            raise
        else:
            return True

    def destroy_krb5server(self):
        """ Destroy Kerberos database
            :param: None
            :Exception: subprocess.CalledProcessError
        """
        # stop the Kerberos server
        for service in ('krb5kdc', 'kadmin'):
            stop_cmd = 'systemctl stop %s' % service
            try:
                self.multihost.run_command(stop_cmd)
            except subprocess.CalledProcessError:
                raise
            else:
                self.multihost.log.info("stopped %s service ")

        # destroy Kerberos database
        try:
            self.multihost.run_command(['kdb5_util', 'destroy', '-f',
                                        self.krb_realm])
        except subprocess.CalledProcessError:
            raise
        else:
            self.multihost.log.info("Removed krb realm %s" % self.krb_realm)
