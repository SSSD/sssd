"""
Build configuration variables.
"""

PREFIX              = "prefix"
SYSCONFDIR          = "sysconfdir"
SSSDCONFDIR         = SYSCONFDIR + "/sssd"
CONF_PATH           = SSSDCONFDIR + "/sssd.conf"
DB_PATH             = "dbpath"
PID_PATH            = "pidpath"
PIDFILE_PATH        = PID_PATH + "/sssd.pid"
LOG_PATH            = "logpath"
MCACHE_PATH         = "mcpath"
