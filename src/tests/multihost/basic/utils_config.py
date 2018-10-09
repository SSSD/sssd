""" Various utilities for manipulating SSSD configuration """
import configparser as ConfigParser


def set_param(multihost, section, key, value):
    multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                           '/tmp/sssd.conf')
    sssdconfig = ConfigParser.ConfigParser()
    sssdconfig.read('/tmp/sssd.conf')
    if section not in sssdconfig.sections():
        sssdconfig.add_section(section)

    sssdconfig.set(section, key, value)
    with open(str('/tmp/sssd.conf'), "w") as sssconf:
        sssdconfig.write(sssconf)

    multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                           '/etc/sssd/sssd.conf')


def remove_section(multihost, section):
    multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                           '/tmp/sssd.conf')
    sssdconfig = ConfigParser.ConfigParser()
    sssdconfig.read('/tmp/sssd.conf')
    sssdconfig.remove_section(section)

    with open(str('/tmp/sssd.conf'), "w") as sssconf:
        sssdconfig.write(sssconf)

    multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                           '/etc/sssd/sssd.conf')
