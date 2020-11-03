""" This module contains functions to do user lookup
and record the Memory consumption """

from subprocess import CalledProcessError
import time
import shlex
import csv
import numpy as np
from sssd.testlib.common.utils import PkiTools
from sssd.testlib.common.utils import sssdTools


class LookupPerf(object):
    """ Lookup Performance """
    def __init__(self, multihost=None, domain=None):
        self.multihost = multihost
        self.domain = domain

    def clear_cache_log(self, host):
        """ Clear sssd cache
        :param multihost object: host
        :Return: None
        """
        sssd_tools_inst = sssdTools(host)
        host.service_sssd('stop')
        sssd_log = "/var/log/sssd/sssd_%s.log" % (self.domain.lower())
        rm_log_cmd = "rm -f %s" % sssd_log
        host.run_command(rm_log_cmd)
        sssd_tools_inst.remove_sss_cache('/var/lib/sss/db')
        host.service_sssd('start')

    def zip_logs(self, host, log_file):
        """ gzip sssd domain logs
        :param multihost object: host
        :param str log_file: Log file name to be zipped
        :Return: None
        """
        gzip_cmd = 'gzip %s' % log_file
        cmd = host.run_command(gzip_cmd, raiseonerr=False)

    def user_lookup(self, host, runs, count, pattern):
        """ Perfor user lookup in a loop
        :param multihost object: host
        :param int runs: No of times the loop should run
        :param int count: No of users to be lookedup
        :param str pattern: The user name pattern
        :Return list ps_file_list: The list containing the file
        names where ps output was captured for sssd_be and sssd_nss process
        """
        ps_list = ['sssd_be', 'sssd_nss']
        ps_file_list = []
        clear_cache = 'sss_cache -E'
        sssd_log = "/var/log/sssd/sssd_%s.log" % (self.domain.lower())
        backup_sssd_log = "/var/log/sssd/sssd_%s_%d_%d.log" % (
            self.domain.lower(), runs, count)
        backup_log_cmd = "cp %s %s" % (sssd_log, backup_sssd_log)
        rpm_cmd = 'rpm -q --qf "%{name}-%{version}-%{release}" sssd'
        cmd = host.run_command(rpm_cmd)
        ver = cmd.stdout_text
        no_activity_count = 50
        self.clear_cache_log(host)
        for _ in range(runs):
            for num in range(1, count):
                id_cmd = 'id %s%d@%s' % (pattern, num, self.domain)
                try:
                    host.run_command(id_cmd)
                except CalledProcessError:
                    print("%s command failed" % id_cmd)
                for proc in ps_list:
                    ps_cmd1 = 'ps -eo pid,etime,pmem,pcpu,rss,vsize,args '\
                              '| grep %s | grep -v grep '\
                              '| grep -v implicit' % proc
                    cmd1 = host.run_command(ps_cmd1)
                    stat_file = 'psoutput-%s-%s-%d-%d.txt' % (ver, proc,
                                                              runs, count)
                    with open(stat_file, 'a+') as mon1:
                        mon1.write(cmd1.stdout_text.lstrip())
            host.run_command(clear_cache)
        # take memory usage when there is no activity
        for _ in range(no_activity_count):
            time.sleep(2)
            for proc in ps_list:
                ps_cmd2 = 'ps -eo pid,etime,pmem,pcpu,rss,vsize,args '\
                          '| grep %s | grep -v grep '\
                          '| grep -v implicit' % proc
                cmd2 = host.run_command(ps_cmd2)
                lookup_stats_file = 'psoutput-%s-%s-%d-%d.txt' % (ver, proc,
                                                                  runs, count)
                with open(lookup_stats_file, 'a+') as mon1:
                    mon1.write(cmd2.stdout_text.lstrip())
        # take backup of sssd domain log
        host.run_command(backup_log_cmd)
        # zip the log file
        self.zip_logs(host, backup_sssd_log)
        # remove the backup sssd domain log
        rm_log = 'rm -f %s' % backup_sssd_log
        host.run_command(rm_log, raiseonerr=False)
        for proc in ps_list:
            lookup_stats_file = 'psoutput-%s-%s-%d-%d.txt' % (ver, proc,
                                                              runs, count)
            ps_file_list.append(lookup_stats_file)
        return ps_file_list

    def get_vsz(self, stats_file):
        """ Compute Standard deviation of Virtual
        Memory size
        :param str stats_file: File name containing the psoutput command
        :Return list vsz: list containing Virtual Memory size
        """
        vsz = []
        with open(stats_file, 'r') as csvfile:
            monreader = csv.reader(csvfile, delimiter=' ')
            for row in monreader:
                try:
                    vsz.append(int(row[13]))
                except ValueError:
                    try:
                        vsz.append(int(row[10]))
                    except ValueError:
                        vsz.append(int(row[12]))
        return vsz

    def serial_lookup(self, host_list, runs, count, pattern):
        """ Do a lookup of users on list of hosts
        :param list host_list: List containing the multihost objects
        on which  id command should be run
        :param int runs: No of times the loop should run
        :param int count: No of users to be lookedup
        :param str pattern: The user name pattern
        :Return list stats_file_list: List containing ps output
        file names
        """
        stats_file_list = []
        for host in host_list:
            stats_file_list.append(self.user_lookup(host, runs,
                                                    count, pattern))
        return stats_file_list

    def std_deviation(self, vsz_list):
        """ Get Standard deviation
        :param list vsz_list: List containing vsz from psoutput
        :Return int: Standard deviation of the list
        """
        return np.std(vsz_list, ddof=1)

    def create_plotfile(self, host_list, stats_file_list, runs, count, proc):
        """ Create GNU Plot file from a
        given file containing ps memory output
        :param list host_list: List contaning multihost objects
        :param list stats_file_list: List containing 2 ps output files
         which needs to be used for plotting.
        :param int runs: No of times the user lookup was run
        :param int count: No of users looked up
        :param str proc: SSSD Process Name
        :Return str plot_file: GNU Plot file
        """
        list_max = []
        list_min = []
        plot_range = []
        ver = []
        for stat_file in stats_file_list:
            vsz_list = self.get_vsz(stat_file)
            list_max.append(max(vsz_list))
            list_min.append(min(vsz_list))
        plot_range.append(int(min(list_min)))
        plot_range.append(int(max(list_max)))
        if 'nss' in proc:
            ytics = abs((plot_range[0] - plot_range[1]) * 15 / 100)
        else:
            ytics = abs((plot_range[0] - plot_range[1]) * 5 / 100)
        rpm_cmd = 'rpm -q --qf "%{name}-%{version}-%{release}" sssd'
        for host in host_list:
            cmd = host.run_command(rpm_cmd)
            ver.append(cmd.stdout_text)
        title = 'Memory consumption(vsz) of %s users for %d ' \
                ' user(%d runs)' % (proc, count, runs)
        plot_file = 'perf_gnuplot_%s_%d_%d.gnuplot' % (proc, runs, count)
        output_png = 'mem_graph_%s_%d_%d.png' % (proc, runs, count)
        with open(plot_file, 'w+') as plotfile:
            plotfile.write('set term png small size 800,600\n')
            plotfile.write('set title "%s\n' % title)
            plotfile.write('set output "%s"\n' % output_png)
            plotfile.write('set ylabel "VSZ"\n')
            plotfile.write('set key right bottom\n')
            plotfile.write('set ytics %d\n' % ytics)
            plotfile.write('set yrange [%s:%s]\n' % (plot_range[0] - 1000,
                                                     plot_range[1] + 3000))
            plotfile.write('plot "%s" using 6 with lines axes '
                           'x1y1 title "%s" lt rgb "red", \\\n'
                           % (stats_file_list[1], ver[1]))
            plotfile.write('     "%s" using 6 with lines axes '
                           'x1y1 title "%s" lt rgb "green" \n'
                           % (stats_file_list[0], ver[0]))
            return plot_file

    def run_gnuplot(self, plot_file):
        """ Run gnuplot
        :param str plot_file: Name of the plotfile
        :Return: None
        """
        pki_inst = PkiTools()
        gnuplot_cmd = 'gnuplot %s' % plot_file
        pki_inst.execute(shlex.split(gnuplot_cmd))
