#!/usr/bin/env python3
from __future__ import print_function
from datetime import datetime
import os
import subprocess
import argparse
import shlex
import errno


class LookupPerf(object):
    def __init__(self, database, name, maxlookup, datadir):
        self.database = database
        self.lookupname = name
        self.lookup_max = maxlookup
        self.perf_data_dir = datadir
        self.mem_cache_data_dir = '%s/memory_cache' % (self.perf_data_dir)
        self.ldb_cache_dir = '%s/ldb_cache' % (self.perf_data_dir)
        if self.database == 'passwd':
            self.identity = 'users'
        elif self.database == 'group':
            self.identity = 'group'
        elif self.database == 'initgroups':
            self.identity = 'initgroups'

    def prepare(self):
        """ Create directory structure """
        dirs = [self.perf_data_dir, self.mem_cache_data_dir,
                self.ldb_cache_dir]
        for directory in dirs:
            try:
                os.makedirs(directory)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise

    def find_nss(self, tracefile, groupname, loop_count):
        """ Find if nss socket in trace file """
        f = open(tracefile, 'r')
        lines = f.read()
        nss = lines.find('/var/lib/sss/pipes/nss')
        if nss != -1:
            move_trace_file = "mv -f %s %s" % (tracefile, self.ldb_cache_dir)
            self.execute(shlex.split(move_trace_file))
            cp_mc = "cp -a /var/lib/sss/mc %s" % (self.perf_data_dir)
            self.execute(shlex.split(cp_mc))
            print("%s was looked through nss socket" % groupname)
            print("Total %s stored in memcache is %d" % (self.identity,
                                                         loop_count))
            return True
        else:
            return False

    def run(self):
        """ Run performance loop """
        if self.database != 'initgroups':
            lookup_cmd = 'getent %s' % (self.database)
        else:
            lookup_cmd = 'id'
        for i in range(1, int(self.lookup_max)):
            print("--------------loop %d---------------" % (i))
            ug_name = '%s%d' % (self.lookupname, i)
            getent_cmd = '%s %s' % (lookup_cmd, ug_name)
            print(getent_cmd)
            now = datetime.now()
            timestamp = now.strftime("%H:%M:%S:%f")[:-3]
            _, _, _ = self.execute(shlex.split(getent_cmd))
            print("i = %d, %s, %s" % (i, ug_name, timestamp))
            for j in range(1, min(10, i)):
                ug_name = '%s%d' % (self.lookupname, j)
                strace_file = '%s/%s.trace' % (self.mem_cache_data_dir,
                                               ug_name)
                strace_cmd = 'strace -fxvto %s %s %s' % (strace_file,
                                                         lookup_cmd, ug_name)
                _, _, rc = self.execute(shlex.split(strace_cmd))
                now = datetime.now()
                timestamp = now.strftime("%H:%M:%S:%f")[:-3]
                print("j = %d, %s, %s" % (j, ug_name, timestamp))
                if self.find_nss(strace_file, ug_name, i):
                    return (i)
            k1 = int(i / 5)
            k2 = int((2 * i) / 5)
            k3 = int((3 * i) / 5)
            k4 = int((4 * i) / 5)
            if i > 10:
                my_list = [k1, k2, k3, k4]
                for k in my_list:
                    ug_name = '%s%d' % (self.lookupname, k)
                    strace_file = '%s/%s.trace' % (self.mem_cache_data_dir,
                                                   ug_name)
                    strace_cmd = 'strace -fxvto %s %s %s' % (strace_file,
                                                             lookup_cmd,
                                                             ug_name)
                    _, _, rc = self.execute(shlex.split(strace_cmd))
                    now = datetime.now()
                    timestamp = now.strftime("%H:%M:%S:%f")[:-3]
                    print("k = %d, %s, %s" % (k, ug_name, timestamp))
                    if self.find_nss(strace_file, ug_name, i):
                        return i
                a1 = max(i - 10, 0)
                a2 = i
                for x in range(a1, a2):
                    ug_name = '%s%d' % (self.lookupname, x)
                    strace_file = '%s/%s.trace' % (self.mem_cache_data_dir,
                                                   ug_name)
                    strace_cmd = 'strace -fxvto %s %s %s' % (strace_file,
                                                             lookup_cmd,
                                                             ug_name)
                    _, _, _ = self.execute(shlex.split(strace_cmd))
                    now = datetime.now()
                    timestamp = now.strftime("%H:%M:%S:%f")[:-3]
                    print("x = %d, %s, %s" % (x, ug_name, timestamp))
                    if self.find_nss(strace_file, ug_name, i):
                        return i
        return i

    def execute(self, args, shell=False, stdin=None, capture_output=True,
                raiseonerr=False, env=None, cwd=None,):
        """ Execute command """
        p_in = None
        p_out = None
        p_err = None
        if env is None:
            env = os.environ.copy()
        if capture_output:
            p_out = subprocess.PIPE
            p_err = subprocess.PIPE
        try:
            proc = subprocess.Popen(args, shell=shell, stdin=p_in,
                                    stdout=p_out,
                                    stderr=p_err, close_fds=True,
                                    env=env, cwd=cwd)
            stdout, stderr = proc.communicate(stdin)
        except KeyboardInterrupt:
            proc.wait()
            raise
        if proc.returncode != 0 and raiseonerr:
            raise subprocess.CalledProcessError(proc.returcode, args, stdout)
        else:
            return (stdout, stderr, proc.returncode)


def main():
    parser = argparse.ArgumentParser("Description=Mem Cache Performance")
    parser.add_argument_group('Mandatory Arguments')
    parser.add_argument('database', type=str,
                        help="Specify database(passwd/group/initgroups)",
                        choices=['passwd', 'group', 'initgroups'])
    parser.add_argument('--name', type=str,
                        help="Pass the user or group name to be looked up.\
                        Ex.If usernames are foobar1..N,\
                        specify foobar as username",
                        required=True)
    parser.add_argument('--datadir', type=str,
                        help="Pass Directory path to save performance data",
                        required=True)
    parser.add_argument('--maxlookup', type=int, help="Maximum lookup",
                        required=True)
    args = parser.parse_args()
    print("args =", args)
    e = LookupPerf(args.database, args.name, args.maxlookup, args.datadir)
    e.prepare()
    loop_count = e.run()
    output_file = "%s/%s" % (args.datadir, 'output')
    with open(output_file, 'w+') as f:
        f.write("%d\n" % loop_count)


if __name__ == '__main__':
    main()
