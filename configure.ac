AC_PREREQ(2.59)

m4_include([version.m4])
AC_INIT([sssd],
        VERSION_NUMBER,
        [sssd-devel@lists.fedorahosted.org])
AC_CONFIG_SRCDIR([BUILD.txt])
AC_CONFIG_AUX_DIR([build])

m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],
    [AC_USE_SYSTEM_EXTENSIONS],
    [AC_GNU_SOURCE])

CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE"


AM_INIT_AUTOMAKE([-Wall -Wno-portability foreign subdir-objects tar-pax
                  parallel-tests])
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_DISABLE_STATIC
AC_PROG_INSTALL
LT_INIT
m4_ifdef([AC_PROG_MKDIR_P],
         [AC_PROG_MKDIR_P],
         [AC_SUBST([MKDIR_P], "mkdir -p")])
LT_LIB_DLLOAD
AC_CONFIG_MACRO_DIR([m4])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.14.4])

AC_SUBST([PRERELEASE_VERSION],
         PRERELEASE_VERSION_NUMBER)

AC_DEFINE([PRERELEASE_VERSION], "PRERELEASE_VERSION_NUMBER",
          [Prerelease version number of package])

AM_CONDITIONAL([GIT_CHECKOUT], [git log -1 >/dev/null 2>&1])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

AC_CHECK_HEADERS(stdint.h dlfcn.h)
AC_CONFIG_HEADER(config.h)

AC_CHECK_TYPES([errno_t], [], [], [[#include <errno.h>]])

m4_include([src/build_macros.m4])
BUILD_WITH_SHARED_BUILD_DIR

AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <pthread.h>]],
        [[pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
          (void) m; /* unused */
        ]])],
    [AC_DEFINE([HAVE_PTHREAD], [1], [Pthread mutexes available.])
     HAVE_PTHREAD=1
    ],
    [AC_MSG_WARN([Pthread library not found! Clients will not be thread safe...])])


AM_CONDITIONAL([HAVE_PTHREAD], [test x"$HAVE_PTHREAD" != "x"])

# Check library for the timer_create function
SAVE_LIBS=$LIBS
LIBS=
LIBADD_TIMER=
AC_SEARCH_LIBS([timer_create], [rt posix4],
    [AC_DEFINE([HAVE_LIBRT], [1],
         [Define if you have the librt library or equivalent.])
     LIBADD_TIMER="$LIBS"],
    [AC_MSG_ERROR([unable to find library fot the timer_create() function])])

AC_SUBST([LIBADD_TIMER])
LIBS=$SAVE_LIBS

# Check library for the clock_gettime function
SAVE_LIBS=$LIBS
LIBS=
LIBCLOCK_GETTIME=
AC_SEARCH_LIBS([clock_gettime], [rt posix4],
    [AC_DEFINE([HAVE_LIBRT], [1],
         [Define if you have the librt library or equivalent.])
     LIBCLOCK_GETTIME="$LIBS"],
    [AC_MSG_ERROR([unable to find library for the clock_gettime() function])])

AC_SUBST([LIBCLOCK_GETTIME])
LIBS=$SAVE_LIBS

# Check for presence of modern functions for setting file timestamps
AC_CHECK_FUNCS([ utimensat \
                 futimens ])

#Check for endian headers
AC_CHECK_HEADERS([endian.h sys/endian.h byteswap.h])

AC_C_BIGENDIAN([AC_DEFINE(HAVE_BIG_ENDIAN, [1], [whether platform is big endian])],
               [AC_DEFINE(HAVE_LITTLE_ENDIAN, [1], [whether platform is little endian])])

#Set the NSS library install path
AC_ARG_ENABLE([nsslibdir], [AS_HELP_STRING([--enable-nsslibdir],
                                        [Where to install nss libraries ($libdir)])],
              [nsslibdir=$enableval],
              [nsslibdir=$libdir])
AC_SUBST(nsslibdir)

#Set the PAM module install path
AC_ARG_ENABLE([pammoddir], [AS_HELP_STRING([--enable-pammoddir],
                                        [Where to install pam modules ($libdir/security)])],
              [pammoddir=$enableval],
              [pammoddir=$libdir/security])
AC_SUBST(pammoddir)

#Set the NFSv4 idmapd library install path
AC_ARG_ENABLE([nfsidmaplibdir], [AS_HELP_STRING([--enable-nfsidmaplibdir],
                                        [Where to install libnfsidmap libraries ($libdir/libnfsidmap)])],
              [nfsidmaplibdir=$enableval],
              [nfsidmaplibdir=$libdir/libnfsidmap])
AC_SUBST(nfsidmaplibdir)

#Include here cause WITH_INIT_DIR requires $osname set in platform.m4
m4_include([src/external/platform.m4])

m4_include(src/conf_macros.m4)
WITH_DB_PATH
WITH_PLUGIN_PATH
WITH_PID_PATH
WITH_LOG_PATH
WITH_PUBCONF_PATH
WITH_PIPE_PATH
WITH_MCACHE_PATH
WITH_DEFAULT_CCACHE_DIR
WITH_DEFAULT_CCNAME_TEMPLATE
WITH_ENVIRONMENT_FILE
WITH_INIT_DIR
WITH_TEST_DIR
WITH_MANPAGES
WITH_XML_CATALOG
WITH_KRB5_PLUGIN_PATH
WITH_KRB5_RCACHE_DIR
WITH_KRB5AUTHDATA_PLUGIN_PATH
WITH_KRB5_CONF
WITH_PYTHON2_BINDINGS
WITH_PYTHON3_BINDINGS
WITH_CIFS_PLUGIN_PATH
WITH_WINBIND_PLUGIN_PATH
WITH_SELINUX
WITH_NSCD
WITH_IPA_GETKEYTAB
WITH_SEMANAGE
WITH_AD_GPO_DEFAULT
WITH_GPO_CACHE_PATH
WITH_NOLOGIN_SHELL
WITH_SESSION_RECORDING_SHELL
WITH_APP_LIBS
WITH_SUDO
WITH_SUDO_LIB_PATH
WITH_AUTOFS
WITH_SSH
WITH_IFP
WITH_CRYPTO
WITH_SYSLOG
WITH_SAMBA
WITH_NFS
WITH_NFS_LIB_PATH
WITH_LIBWBCLIENT
WITH_SSSD_USER
SSSD_RUNSTATEDIR
WITH_SECRETS
WITH_SECRETS_DB_PATH
WITH_KCM

m4_include([src/external/pkg.m4])
m4_include([src/external/libpopt.m4])
m4_include([src/external/libtalloc.m4])
m4_include([src/external/libtdb.m4])
m4_include([src/external/libtevent.m4])
m4_include([src/external/libldb.m4])
m4_include([src/external/libdhash.m4])
m4_include([src/external/libcollection.m4])
m4_include([src/external/libini_config.m4])
m4_include([src/external/pam.m4])
m4_include([src/external/ldap.m4])
m4_include([src/external/libpcre.m4])
m4_include([src/external/krb5.m4])
m4_include([src/external/libcares.m4])
m4_include([src/external/libcmocka.m4])
m4_include([src/external/docbook.m4])
m4_include([src/external/sizes.m4])
m4_include([src/external/python.m4])
m4_include([src/external/selinux.m4])
m4_include([src/external/crypto.m4])
m4_include([src/external/nscd.m4])
m4_include([src/external/nsupdate.m4])
m4_include([src/external/libkeyutils.m4])
m4_include([src/external/libnl.m4])
m4_include([src/external/systemd.m4])
m4_include([src/external/pac_responder.m4])
m4_include([src/external/cifsidmap.m4])
m4_include([src/external/signal.m4])
m4_include([src/external/inotify.m4])
m4_include([src/external/samba.m4])
m4_include([src/external/sasl.m4])
m4_include([src/external/libnfsidmap.m4])
m4_include([src/external/cwrap.m4])
m4_include([src/external/libresolv.m4])
m4_include([src/external/intgcheck.m4])
m4_include([src/external/systemtap.m4])
m4_include([src/external/service.m4])

if test x$with_secrets = xyes; then
    m4_include([src/external/libhttp_parser.m4])
fi

if test x$with_kcm = xyes; then
    m4_include([src/external/libuuid.m4])
fi

if test x$with_kcm = xyes -o x$with_secrets = xyes; then
    m4_include([src/external/libcurl.m4])
    m4_include([src/external/libjansson.m4])
fi

# This variable is defined by external/libcurl.m4, but conditionals
# must be always evaluated
AM_CONDITIONAL([BUILD_WITH_LIBCURL],
               [test x"$have_curlopt_unix_sockpath" = xyes])

WITH_UNICODE_LIB
if test x$unicode_lib = xlibunistring; then
    m4_include([src/external/libunistring.m4])
    AC_DEFINE_UNQUOTED(HAVE_LIBUNISTRING, 1, [Using libunistring for unicode])
    UNICODE_LIBS=$UNISTRING_LIBS
else
    m4_include([src/external/glib.m4])
    AC_DEFINE_UNQUOTED(HAVE_GLIB2, 1, [Using glib2 for unicode])
    UNICODE_LIBS=$GLIB2_LIBS
fi
AC_SUBST(UNICODE_LIBS)

WITH_LIBNL

if test x$HAVE_NSCD; then
    WITH_NSCD_CONF
fi

WITH_INITSCRIPT
if test x$initscript = xsystemd; then
    WITH_SYSTEMD_UNIT_DIR
    WITH_SYSTEMD_CONF_DIR
else
    CHECK_SERVICE_EXECUTABLE
fi

PKG_CHECK_MODULES([DBUS],[dbus-1])
dnl if test -n "`$PKG_CONFIG --modversion dbus-1 | grep '^0\.'`" ; then
if ! $PKG_CONFIG --atleast-version 1.0.0 dbus-1; then
    DBUS_CFLAGS="$DBUS_CFLAGS -DDBUS_API_SUBJECT_TO_CHANGE"
    AC_MSG_RESULT([setting -DDBUS_API_SUBJECT_TO_CHANGE])
fi

if test x$has_dbus != xno; then
    SAFE_LIBS="$LIBS"
    LIBS="$DBUS_LIBS"
    SAFE_CFLAGS=$CFLAGS
    CFLAGS="$CFLAGS $DBUS_CFLAGS"

    AC_CHECK_FUNC([dbus_watch_get_unix_fd],
                  AC_DEFINE([HAVE_DBUS_WATCH_GET_UNIX_FD], [1],
                            [Define if dbus_watch_get_unix_fd exists]))
    AC_CHECK_TYPES([DBusBasicValue],
                   [],
                   [],
                   [ #include <dbus/dbus.h> ])

    LIBS="$SAFE_LIBS"
    CFLAGS=$SAFE_CFLAGS
fi

# work around a bug in cov-build from Coverity
test -n "$XML_CATALOG_FILES" || unset XML_CATALOG_FILES

if test x$HAVE_MANPAGES != x; then
    CHECK_XML_TOOLS

    DOCBOOK_XSLT=http://docbook.sourceforge.net/release/xsl/current/manpages/profile-docbook.xsl
    CHECK_STYLESHEET([$SGML_CATALOG_FILES],
                     [$DOCBOOK_XSLT],
                     [Docbook XSL profiling templates],
                     [HAVE_PROFILE_CATALOGS=1],
                     [AC_MSG_WARN([Man pages might contain documentation for experimental features])])

    if test x$HAVE_PROFILE_CATALOGS = x; then
        DOCBOOK_XSLT=http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl
        CHECK_STYLESHEET([$SGML_CATALOG_FILES],
                         [$DOCBOOK_XSLT],
                         [Docbook XSL templates],
                         [],
                         [AC_MSG_ERROR([could not find the docbook xsl catalog])])
    fi

    AC_CHECK_PROG([PO4A],[po4a],[po4a],[no])
    AC_SUBST(DOCBOOK_XSLT)
fi
AM_CONDITIONAL([HAVE_PROFILE_CATALOGS], [test "x$HAVE_PROFILE_CATALOGS" != "x"])
AM_CONDITIONAL([HAVE_MANPAGES], [test "x$HAVE_MANPAGES" != "x"])
AM_CONDITIONAL([HAVE_PO4A], [test "x$PO4A" != "xno"])

AC_CHECK_PROG(HAVE_PYTHON2, python2, yes, no)
AS_IF([test x$HAVE_PYTHON2 = xyes],
      [AC_PATH_PROG(PYTHON2, python2)])

AC_CHECK_PROG(HAVE_PYTHON3, python3, yes, no)
AS_IF([test x$HAVE_PYTHON3 = xyes],
      [AC_PATH_PROG(PYTHON3, python3)])

if test x$HAVE_PYTHON2_BINDINGS = x1; then
    AS_IF([test x$HAVE_PYTHON2 != xyes],
          [AC_MSG_ERROR([
The program python2 was not found in search path.
Please ensure that it is installed and its directory is included in the search
path. It is required for building python2 bindings. If you do not want to build
them please use argument --without-python2-bindings when running configure.])])

    PYTHON=$PYTHON2
    AM_PATH_PYTHON([2.6])
    AM_PYTHON_CONFIG([python2])
    AM_CHECK_PYTHON_HEADERS([],
                            AC_MSG_ERROR([Could not find python2 headers]))
    AM_CHECK_PYTHON_COMPAT

    AC_SUBST([py2execdir], [$pyexecdir])
    AC_SUBST([python2dir], [$pythondir])
    AC_SUBST([PYTHON2_CFLAGS], [$PYTHON_CFLAGS])
    AC_SUBST([PYTHON2_LIBS], [$PYTHON_LIBS])
    AC_SUBST([PYTHON2_INCLUDES], [$PYTHON_INCLUDES])
    AC_SUBST([PYTHON2_VERSION], [$PYTHON_VERSION])
    AC_SUBST([PYTHON2_PREFIX], [$PYTHON_PREFIX])
    AC_SUBST([PYTHON2_EXEC_PREFIX], [$PYTHON_EXEC_PREFIX])

    SSS_CLEAN_PYTHON_VARIABLES
fi

if test x$HAVE_PYTHON3_BINDINGS = x1; then
    AS_IF([test x$HAVE_PYTHON3 != xyes],
          [AC_MSG_ERROR([
The program python3 was not found in search path.
Please ensure that it is installed and its directory is included in the search
path. It is required for building python3 bindings. If you do not want to build
them please use argument --without-python3-bindings when running configure.])])

    PYTHON=$PYTHON3
    AM_PATH_PYTHON([3.3])
    AM_PYTHON_CONFIG([python3])
    AM_CHECK_PYTHON_HEADERS([],
                            AC_MSG_ERROR([Could not find python3 headers]))
    AM_CHECK_PYTHON_COMPAT

    AC_SUBST([py3execdir], [$pyexecdir])
    AC_SUBST([python3dir], [$pythondir])
    AC_SUBST([PYTHON3_CFLAGS], [$PYTHON_CFLAGS])
    AC_SUBST([PYTHON3_LIBS], [$PYTHON_LIBS])
    AC_SUBST([PYTHON3_INCLUDES], [$PYTHON_INCLUDES])
    AC_SUBST([PYTHON3_VERSION], [$PYTHON_VERSION])
    AC_SUBST([PYTHON3_PREFIX], [$PYTHON_PREFIX])
    AC_SUBST([PYTHON3_EXEC_PREFIX], [$PYTHON_EXEC_PREFIX])

    SSS_CLEAN_PYTHON_VARIABLES
fi

AM_CONDITIONAL([BUILD_PYTHON_BINDINGS],
               [test x"$with_python2_bindings" = xyes \
                     -o x"$with_python3_bindings" = xyes])

AM_PYTHON2_MODULE([ldap])

if test x$HAVE_SELINUX != x; then
    AM_CHECK_SELINUX
fi

if test x$HAVE_SEMANAGE != x -a x$HAVE_SELINUX != x; then
    AM_CHECK_SEMANAGE
fi

dnl If journald was selected for logging, configure journald
if test x$syslog = xjournald; then
    AM_CHECK_JOURNALD
fi

if test x$cryptolib = xnss; then
    AM_CHECK_NSS
fi

if test x$cryptolib = xlibcrypto; then
    AM_CHECK_LIBCRYPTO
fi

AM_CHECK_INOTIFY

AC_CACHE_CHECK([whether compiler supports __attribute__((destructor))],
               sss_client_cv_attribute_destructor,
               [AC_COMPILE_IFELSE(
                    [AC_LANG_SOURCE([__attribute__((destructor)) static void cleanup(void) { }])],
                    sss_client_cv_attribute_destructor=yes)
               ])

if test x"$sss_client_cv_attribute_destructor" = xyes ; then
   AC_DEFINE(HAVE_FUNCTION_ATTRIBUTE_DESTRUCTOR, 1,
             [whether compiler supports __attribute__((destructor))])
fi

AC_CACHE_CHECK([whether compiler supports __attribute__((format))],
               sss_cv_attribute_format,
               [AC_COMPILE_IFELSE(
                    [AC_LANG_SOURCE(
                        [void debug_fn(const char *format, ...) __attribute__ ((format (printf, 1, 2)));]
                    )],
                    [sss_cv_attribute_format=yes],
                    [
                        AC_MSG_RESULT([no])
                        AC_MSG_WARN([compiler does NOT support __attribute__((format))])
                    ])
               ])

if test x"$sss_cv_attribute_format" = xyes ; then
   AC_DEFINE(HAVE_FUNCTION_ATTRIBUTE_FORMAT, 1,
             [whether compiler supports __attribute__((format))])
fi

AC_CACHE_CHECK([whether compiler supports __attribute__((warn_unused_result))],
               sss_cv_attribute_warn_unused_result,
               [AC_COMPILE_IFELSE(
                    [AC_LANG_SOURCE(
                        [ char _check_leaks(int bytes) __attribute__ ((warn_unused_result)); ]
                    )],
                    [sss_cv_attribute_warn_unused_result=yes],
                    [
                        AC_MSG_RESULT([no])
                        AC_MSG_WARN([compiler does NOT support __attribute__((warn_unused_result))])
                    ])
               ])
if test x"$sss_cv_attribute_warn_unused_result" = xyes ; then
   AC_DEFINE(HAVE_FUNCTION_ATTRIBUTE_WARN_UNUSED_RESULT, 1,
             [whether compiler supports __attribute__((warn_unused_result))])
fi

SAFE_CFLAGS=$CFLAGS
CFLAGS="-Werror"
AC_CACHE_CHECK(
    [whether compiler supports __attribute__((fallthrough))],
    [sss_cv_attribute_fallthrough],
    [AC_COMPILE_IFELSE(
         [AC_LANG_SOURCE(
             [ __attribute__ ((fallthrough)); ])
         ],[
             sss_cv_attribute_fallthrough=yes
             sss_cv_attribute_fallthrough_val="__attribute__ ((fallthrough))"
         ],[
             sss_cv_attribute_fallthrough=no
             sss_cv_attribute_fallthrough_val="((void)0)"
         ])
    ])
CFLAGS=$SAFE_CFLAGS

AC_DEFINE_UNQUOTED(
    [SSS_ATTRIBUTE_FALLTHROUGH],
    [$sss_cv_attribute_fallthrough_val],
    [__attribute__((fallthrough)) if supported])


PKG_CHECK_MODULES([CHECK], [check >= 0.9.5], [have_check=1], [have_check=])
if test x$have_check = x; then
    AC_MSG_WARN([Without the 'CHECK' libraries, you will be unable to run all tests in the 'make check' suite])
else
    AC_CHECK_HEADERS([check.h],,AC_MSG_ERROR([Could not find CHECK headers]))
fi

AC_PATH_PROG([DOXYGEN], [doxygen], [false])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x$DOXYGEN != xfalse ])

AM_CONDITIONAL([HAVE_CHECK], [test x$have_check != x])
AM_CHECK_CMOCKA
AM_CHECK_UID_WRAPPER
AM_CHECK_NSS_WRAPPER

# Check if the user wants SSSD to be compiled with systemtap probes
AM_CHECK_SYSTEMTAP

SSS_ENABLE_INTGCHECK_REQS

AM_CONDITIONAL([HAVE_DEVSHM], [test -d /dev/shm])

# Check if we should install polkit rules
ENABLE_POLKIT_RULES_PATH
AM_CONDITIONAL([HAVE_POLKIT_RULES_D], [test x$HAVE_POLKIT_RULES_D != x])

abs_build_dir=`pwd`
AC_DEFINE_UNQUOTED([ABS_BUILD_DIR], ["$abs_build_dir"], [Absolute path to the build directory])
AC_SUBST([abs_builddir], $abs_build_dir)

my_srcdir=`readlink -f $srcdir`
AC_DEFINE_UNQUOTED([ABS_SRC_DIR], ["$my_srcdir"], [Absolute path to the source directory])

AC_CONFIG_FILES([Makefile contrib/sssd.spec src/examples/rwtab src/doxy.config
                 contrib/sssd-pcsc.rules
                 src/sysv/sssd src/sysv/gentoo/sssd src/sysv/SUSE/sssd
                 po/Makefile.in src/man/Makefile src/tests/cwrap/Makefile
                 src/tests/intg/Makefile
                 src/lib/ipa_hbac/ipa_hbac.pc src/lib/ipa_hbac/ipa_hbac.doxy
                 src/lib/idmap/sss_idmap.pc src/lib/idmap/sss_idmap.doxy
                 src/lib/certmap/sss_certmap.pc src/lib/certmap/sss_certmap.doxy
                 src/sss_client/idmap/sss_nss_idmap.pc
                 src/sss_client/idmap/sss_nss_idmap.doxy
                 src/sss_client/libwbclient/wbclient_sssd.pc
                 src/lib/sifp/sss_simpleifp.pc
                 src/lib/sifp/sss_simpleifp.doxy
                 src/config/setup.py
                 src/systemtap/sssd.stp
                 src/config/SSSDConfig/__init__.py])
AC_OUTPUT
