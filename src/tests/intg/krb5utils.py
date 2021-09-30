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
import subprocess


class NoPrincipals(Exception):
    def __init__(self):
        Exception.__init__(self, 'No principals in the collection')


class PrincNotFound(Exception):
    def __init__(self, principal):
        Exception.__init__(self, 'Principal %s not found' % principal)


class Krb5Utils(object):
    """
    Helper class to test Kerberos command line utilities
    """
    def __init__(self, krb5_conf_path):
        self.krb5_conf_path = krb5_conf_path

    def spawn_in_env(self, args, stdin=None, extra_env=None):
        my_env = os.environ.copy()
        my_env['KRB5_CONFIG'] = self.krb5_conf_path

        if 'KRB5CCNAME' in my_env:
            del my_env['KRB5CCNAME']
        if extra_env is not None:
            my_env.update(extra_env)

        cmd = subprocess.Popen(args,
                               env=my_env,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        return cmd

    def _run_in_env(self, args, stdin=None, extra_env=None):
        cmd = self.spawn_in_env(args, stdin, extra_env)
        out, err = cmd.communicate(stdin)
        return cmd.returncode, out.decode('utf-8'), err.decode('utf-8')

    def kinit(self, principal, password, options=None, env=None):
        args = ["kinit", principal]
        if options:
            args.extend(options)
        return self._run_in_env(args, password.encode('utf-8'), env)

    def kvno(self, principal, env=None):
        args = ["kvno", principal]
        return self._run_in_env(args, env)

    def kdestroy(self, all_ccaches=False, env=None):
        args = ["kdestroy"]
        if all_ccaches is True:
            args += ["-A"]
        retval, _, _ = self._run_in_env(args, env)
        return retval

    def kswitch(self, principal, env=None):
        args = ["kswitch", '-p', principal]
        retval, _, _ = self._run_in_env(args, env)
        return retval

    def _check_klist_l(self, line, exp_principal, exp_cache):
        try:
            princ, cache = line.split()
        except ValueError:
            return False

        if exp_cache is not None and cache != exp_cache:
            return False

        if exp_principal != princ:
            return False

        return True

    def num_princs(self, env=None):
        args = ["klist", "-l"]
        retval, out, err = self._run_in_env(args, extra_env=env)
        if retval != 0:
            return 0

        outlines = [ln for ln in out.split('\n') if len(ln) > 1]
        return len(outlines) - 2

    def list_princs(self, env=None):
        args = ["klist", "-l"]
        retval, out, err = self._run_in_env(args, extra_env=env)
        if retval == 1:
            raise NoPrincipals
        elif retval != 0:
            raise Exception("klist failed: %d: %s\n", retval, err)

        outlines = out.split('\n')
        if len(outlines) < 2:
            raise Exception("Not enough output from klist -l")

        return [ln for ln in outlines[2:] if len(ln) > 0]

    def list_times(self, env=None):
        p = self.spawn_in_env(['klist', '-A'])
        output = p.stdout.read().splitlines()
        for line in output:
            if not line:
                continue

            line_str = line.decode("utf-8")
            if line_str[0].isdigit():
                return line_str

    def has_principal(self, exp_principal, exp_cache=None, env=None):
        try:
            princlist = self.list_princs(env)
        except NoPrincipals:
            return False

        for line in princlist:
            matches = self._check_klist_l(line, exp_principal, exp_cache)
            if matches is True:
                return True

        return False

    def default_principal(self, env=None):
        principals = self.list_princs(env)
        return principals[0].split()[0]

    def _parse_klist_a(self, out):
        dflprinc = None
        thisrealm = None
        ccache_dict = dict()

        for line in [ln for ln in out.split('\n') if len(ln) > 0]:
            if line.startswith("Default principal"):
                dflprinc = line.split()[2]
                thisrealm = '@' + dflprinc.split('@')[1]
            elif thisrealm is not None and line.endswith(thisrealm):
                svc = line.split()[-1]
                if dflprinc in ccache_dict:
                    ccache_dict[dflprinc].append(svc)
                else:
                    ccache_dict[dflprinc] = [svc]

        return ccache_dict

    def list_all_princs(self, env=None):
        args = ["klist", "-A"]
        retval, out, err = self._run_in_env(args, extra_env=env)
        if retval == 1:
            raise NoPrincipals
        elif retval != 0:
            raise Exception("klist -A failed: %d: %s\n", retval, err)

        return self._parse_klist_a(out)
