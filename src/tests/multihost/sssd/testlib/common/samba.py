""" This module defines classes regarding
functions/methods related to samba/winbind """

import os
import time
import subprocess
import pytest
import configparser as ConfigParser
import tempfile
from .utils import ADOperations
from .utils import sssdTools
from .paths import SMB_DEFAULT_CONF
from .exceptions import SSSDException


class sambaTools(object):
    """ Functions related to samba/winbind setup """
    def __init__(self, host, adhost):
        """ Initialize host """
        self.host = host
        self.adhost = adhost
        self.adhost_ip = self.adhost.ip
        self.adhost_ops = ADOperations(self.adhost)
        self.adhost_conn = self.adhost_ops.ad_conn()
        self.adhost_realm = self.adhost.realm
        self.adhost_password = self.adhost.ssh_password
        self.adhost_hostname = self.adhost.external_hostname
        self.adhost_basedn = self.adhost.domain_basedn_entry
        self.adhost_adminuser = 'Administrator'
        self.host_tools = sssdTools(self.host, self.adhost)

    def smbadsconf(self):
        """ Setup smbconf with security = ads """
        bkup = 'cp -a /etc/samba/smb.conf /etc/samba/smb.conf.orig'
        self.host.run_command(bkup, raiseonerr=False)
        client_hostname = self.host.sys_hostname
        client_short_name = client_hostname.strip().split('.')[0]
        tmpconf = tempfile.NamedTemporaryFile(suffix='smb.conf', delete=False)
        workgroup = self.adhost_realm.split('.')[0]
        global_parameters = {'workgroup': workgroup,
                             'security': 'ads',
                             'realm': self.adhost_realm}
        if len(client_short_name) > 15:
            client_short_name = client_short_name[:15]
            global_parameters['netbios name'] = client_short_name
        global_parameters['kerberos method'] = "secrets and keytab"
        global_parameters['client signing'] = "yes"
        global_parameters['client use spnego'] = "yes"
        global_parameters['log file'] = "/var/log/samba/log.%m"
        global_parameters['max log size'] = "50"
        global_parameters['log level'] = "9"
        try:
            self.host_tools.update_conf(tmpconf.name,
                                        'global',
                                        global_parameters)
        except SSSDException:
            raise
        else:
            self.host.transport.put_file(tmpconf.name, '/etc/samba/smb.conf')
            os.unlink(tmpconf.name)

    def enable_idmapsss(self, idmap_range=None, tdb_range=None):
        """ Enable sssd backend for idmap """
        tmpconf = tempfile.NamedTemporaryFile(suffix='smb.conf', delete=False)
        self.host.transport.get_file(SMB_DEFAULT_CONF, tmpconf.name)
        netbiosname = self.adhost.netbiosname.strip()
        idmap_backend = "idmap config %s : backend" % netbiosname
        idmap_sss_range = "idmap config %s : range" % netbiosname
        idmap_tdb = "idmap config * : backend"
        idmap_tdb_range = "idmap config * : range"
        if not idmap_range:
            idmap_range = '200000-2147483647'
        if not tdb_range:
            tdb_range = '50000-100000'

        idmap_params = {idmap_tdb: 'tdb',
                        idmap_tdb_range: tdb_range,
                        idmap_backend: 'sss',
                        idmap_sss_range: idmap_range}
        try:
            self.host_tools.update_conf(tmpconf.name, 'global',
                                        idmap_params, action='update')
        except SSSDException:
            raise
        else:
            self.host.transport.put_file(tmpconf.name, SMB_DEFAULT_CONF)
            os.unlink(tmpconf.name)

    def add_share_definition(self, share_name, share_path):
        """ Add samba share in smb.conf """
        tmpconf = tempfile.NamedTemporaryFile(suffix='smb.conf', delete=False)
        self.host.transport.get_file(SMB_DEFAULT_CONF, tmpconf.name)
        share_params = {'path': share_path,
                        'comment': 'test share %s' % share_name,
                        'writable': 'yes',
                        'printable': 'no'}
        try:
            self.host_tools.update_conf(tmpconf.name, 'share1',
                                        share_params, action='update')
        except SSSDException:
            raise
        else:
            self.host.transport.put_file(tmpconf.name, SMB_DEFAULT_CONF)
            os.unlink(tmpconf.name)

    def service_smb(self, action='start'):
        """ Start smb servicer """
        cmd = 'systemctl %s smb' % action
        self.host.run_command(cmd)

    def create_samba_share(self, share_path):
        """ Create samba share directory """
        create_share_dir = 'mkdir -p %s' % share_path
        self.host.run_command(create_share_dir)
        selinux_context = 'chcon -t samba_share_t -R %s' % share_path
        self.host.run_command(selinux_context)
        chgrp = "chgrp 'Domain Users@%s' -R %s" % (self.adhost_realm,
                                                   share_path)
        self.host.run_command(chgrp)
        chmod = 'chmod 770 %s' % share_path
        self.host.run_command(chmod)

    def delete_samba_share(self, share_path):
        """ Delete samba share directory """
        delete_share = 'rm -rf %s' % share_path
        self.host.run_command(delete_share)

    def enable_winbind(self):
        """ Enable winbind with idmap sss backend """
        # disjoin system first
        self.host_tools.update_resolv_conf(self.adhost_ip)
        self.host_tools.create_kdcinfo(self.adhost_realm, self.adhost_ip)
        self.host_tools.systemsssdauth(self.adhost_realm, self.adhost_hostname)
        self.host_tools.disjoin_ad()
        kinit = "kinit Administrator"
        try:
            self.host.run_command(kinit, stdin_text=self.adhost_password)
        except subprocess.CalledProcessError:
            pytest.fail("kinit failed")
        self.host_tools.join_ad(self.adhost_realm, self.adhost_password,
                                mem_sw='samba')
        self.smbadsconf()
        self.enable_idmapsss()
        restart_winbind = 'systemctl restart winbind'
        cmd = self.host.run_command(restart_winbind, raiseonerr=False)
        assert cmd.returncode == 0
        time.sleep(20)

    def disable_winbind(self):
        """ Disable winbind """
        # disjoin system
        self.host_tools.disjoin_ad()
        # stop winbind
        stop_winbind = 'systemctl stop winbind'
        self.host.run_command(stop_winbind)

    def remove_smbconf(self):
        """ Remove smb.conf """
        # remove smb.conf
        cmd = 'rm -f /etc/samba/smb.conf'
        self.host.run_command(cmd)

    def clear_samba_cache(self):
        """ Clear samba cache """
        cache_files = ['group_mapping.tdb',
                       'account_policy.tdb',
                       'registry.tdb',
                       'share_info.tdb',
                       'smbprofile.tdb',
                       'winbindd_idmap.tdb',
                       'netsamlogon_cache.tdb',
                       'winbindd_cache.tdb',
                       'private/netlogon_creds_cli.tdb',
                       'private/secrets.ldb',
                       'private/secrets.tdb',
                       'private/passdb.tdb']
        cache_path = '/var/lib/samba'
        for cache in cache_files:
            cmd = 'rm -f %s/%s' % (cache_path, cache)
            self.host.run_command(cmd)
