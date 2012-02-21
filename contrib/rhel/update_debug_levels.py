import os
import sys
import shutil
import traceback
from optparse import OptionParser
import SSSDConfig


# Older versions of SSSD (1.5 and earlier) would take a debug_level
# value set in the [sssd] section as authoritative for all other
# sections where not explicitly overridden. We changed this so that
# all sections need to set it if they want debug logs set.
# This script can be run to make the new version continue to produce
# the same logs as the old versions did, by explicitly adding
# debug_level to all domains and services that did not have it set
# already.

def parse_options():
    parser = OptionParser()
    parser.add_option("", "--no-backup", action="store_false",
                      dest="backup", default=True,
                      help="""Do not provide backup file after conversion.
The script copies the original file with the suffix .bak.<timestamp>
by default""")
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=False,
                      help="Be verbose")
    (options, args) = parser.parse_args()
    if len(args) > 0:
        print >>sys.stderr, "Stray arguments: %s" % ' '.join([a for a in args])
        return None

    return options

def verbose(msg, verbosity):
    if verbosity:
        print msg

def main():
    options = parse_options()
    if not options:
        print >> sys.stderr, "Cannot parse options"
        return 1

    # Import the current config file
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()

    except Exception, e:
        print "Error: %s" % e
        verbose(traceback.format_exc(), options.verbose)
        return 2

    # Check the [sssd] section for debug_level
    sssd_service = sssdconfig.get_service('sssd')

    if not 'debug_level' in sssd_service.options.keys():
        # Nothing to do, just return success
        verbose("No changes required, no backup necessary",
                options.verbose)
        return 0

    debug_level = sssd_service.options['debug_level']
    verbose("Setting all sections to debug_level = %d" % debug_level,
            options.verbose)

    # Loop through services
    for service in sssdconfig.list_services():
        svc = sssdconfig.get_service(service)
        if not 'debug_level' in svc.options.keys():
            # Not explicitly set, so add it
            svc.set_option('debug_level', debug_level)
            sssdconfig.save_service(svc)

    # Loop through domains (active AND inactive)
    for domain in sssdconfig.list_domains():
        dom = sssdconfig.get_domain(domain)
        if not 'debug_level' in dom.options.keys():
            # Not explicitly set, so add it
            dom.set_option('debug_level', debug_level)
            sssdconfig.save_domain(dom)

    # Save the original file
    if options.backup:
        import datetime
        currenttime = datetime.datetime.utcnow()
        newfile = "/etc/sssd/sssd.conf.bak.%s" % currenttime.isoformat()
        verbose("Backing up existing configuration to %s" % newfile,
                options.verbose)
        shutil.copy2("/etc/sssd/sssd.conf", newfile)

    # Save the changes
    sssdconfig.write()

if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
else:
    raise ImportError
