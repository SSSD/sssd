#
# MIT Kerberos server class
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
import signal
import shutil
import subprocess

from util import unindent


class KDC(object):
    """
    MIT Kerberos KDC instance
    """

    def __init__(self, basedir, realm,
                 includedir=None,
                 kdc_port=10088,
                 kadmin_port=10749,
                 master_key='master'):
        self.basedir = basedir
        self.realm = realm
        self.kdc_port = kdc_port
        self.kadmin_port = kadmin_port
        self.master_key = master_key

        self.kdc_basedir = self.basedir + "/var/krb5kdc"
        self.includedir = includedir or (self.kdc_basedir + "/include")
        self.kdc_logdir = self.kdc_basedir + "/log"
        self.kdc_conf_path = self.kdc_basedir + "/kdc.conf"
        self.krb5_conf_path = self.kdc_basedir + "/krb5.conf"

        self.kdc_pid_file = self.kdc_basedir + "/kdc.pid"

        self.acl_file = self.kdc_basedir + "/kadm5.acl"

        self.admin_princ = "admin/admin@" + self.realm

    def start_kdc(self, extra_args=[]):
        args = ["krb5kdc", '-P', self.kdc_pid_file] + extra_args
        return self._run_in_env(args, self.get_krb5_env())

    def stop_kdc(self):
        try:
            with open(self.kdc_pid_file, "r") as pid_file:
                os.kill(int(pid_file.read()), signal.SIGTERM)
        except IOError as ioex:
            if ioex.errno == 2:
                pass
            else:
                raise ioex

    def teardown(self):
        self.stop_kdc()
        shutil.rmtree(self.kdc_basedir)

    def set_up(self):
        self._create_config()
        self._create_acl()
        self._create_kdb()

    def get_krb5_env(self):
        my_env = os.environ.copy()
        my_env['KRB5_CONFIG'] = self.krb5_conf_path
        my_env['KRB5_KDC_PROFILE'] = self.kdc_conf_path
        return my_env

    def add_config(self, include_files):
        for name, contents in include_files.items():
            include_fpath = os.path.join(self.includedir, name)
            with open(include_fpath, 'w') as include_file:
                include_file.write(contents)

    def add_principal(self, princ, password=None):
        args = ["kadmin.local", "-q"]
        if password is None:
            args += ["addprinc -randkey %s" % (princ)]
        else:
            args += ["addprinc -pw %s %s" % (password, princ)]
        return self._run_in_env(args, self.get_krb5_env())

    def _run_in_env(self, args, env):
        cmd = subprocess.Popen(args, env=env)
        out, err = cmd.communicate()
        return cmd.returncode, out, err

    def _create_config(self):
        try:
            os.makedirs(self.kdc_basedir)
            os.makedirs(self.kdc_logdir)
            os.makedirs(self.includedir)
        except OSError as osex:
            if osex.errno == 17:
                pass

        kdc_conf = self._format_kdc_conf()
        with open(self.kdc_conf_path, 'w') as kdc_conf_file:
            kdc_conf_file.write(kdc_conf)

        krb5_conf = self._format_krb5_conf()
        with open(self.krb5_conf_path, 'w') as krb5_conf_file:
            krb5_conf_file.write(krb5_conf)

    def _create_acl(self):
        with open(self.acl_file, 'w') as acl_fobject:
            acl_fobject.write(self.admin_princ)

    def _create_kdb(self):
        self._run_in_env(
            ['kdb5_util', 'create', '-W', '-s', '-P', self.master_key],
            self.get_krb5_env()
        )

    def _format_kdc_conf(self):
        database_path = self.kdc_basedir + "/principal"
        key_stash = self.kdc_basedir + "/stash." + self.realm

        kdc_logfile = "FILE:" + self.kdc_logdir + "/krb5kdc.log"
        kadmin_logfile = "FILE:" + self.kdc_logdir + "/kadmin.log"
        libkrb5_logfile = "FILE:" + self.kdc_logdir + "/libkrb5.log"

        kdc_conf = unindent("""
        [kdcdefaults]
        kdc_ports = {self.kdc_port}
        kdc_tcp_ports = {self.kdc_port}

        [realms]
            {self.realm} = {{
                kadmind_port = {self.kadmin_port}
                database_name = {database_path}
                key_stash_file = {key_stash}
                max_life = 7d
                max_renewable_life = 14d
                acl_file = {self.acl_file}
            }}

        [logging]
            kdc = {kdc_logfile}
            admin_server = {kadmin_logfile}
            default = {libkrb5_logfile}
        """).format(**locals())
        return kdc_conf

    def _format_krb5_conf(self):
        kdc_uri = "localhost:%d" % self.kdc_port
        kadmin_uri = "localhost:%d" % self.kadmin_port

        krb5_conf = unindent("""
        includedir {self.includedir}

        [libdefaults]
        default_realm = {self.realm}
        dns_lookup_kdc = false
        dns_lookup_realm = false

        [realms]
            {self.realm} = {{
                kdc = {kdc_uri}
                admin_server = {kadmin_uri}
            }}
        """).format(**locals())
        return krb5_conf
