AC_PREREQ(2.59)

m4_include([version.m4])
AC_INIT([sssd],
        VERSION_NUMBER,
        [sssd-devel@lists.fedorahosted.org])

m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],
    [AC_USE_SYSTEM_EXTENSIONS],
    [AC_GNU_SOURCE])

CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE"

AC_CONFIG_SRCDIR([BUILD.txt])
AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects tar-pax])
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_DISABLE_STATIC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
LT_LIB_DLLOAD
AC_CONFIG_MACRO_DIR([m4])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.14])

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
        [[pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;]])],
    [AC_DEFINE([HAVE_PTHREAD], [1], [Pthread mutexes available.])
     HAVE_PTHREAD=1
    ],
    [AC_MSG_WARN([Pthread library not found! Clients will not be thread safe...])])


AM_CONDITIONAL([HAVE_PTHREAD], [test x"$HAVE_PTHREAD" != "x"])

SAVE_LIBS=$LIBS
LIBS="$LIBS -lpthread"
AC_CHECK_FUNCS([ pthread_mutexattr_setrobust \
                 pthread_mutex_consistent \
                 pthread_mutexattr_setrobust_np \
                 pthread_mutex_consistent_np ])
LIBS=$SAVE_LIBS

# Check for presence of modern functions for setting file timestamps
AC_CHECK_FUNCS([ utimensat \
                 futimens ])

#Check for endian headers
AC_CHECK_HEADERS([endian.h sys/endian.h byteswap.h])

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
WITH_PYTHON_BINDINGS
WITH_CIFS_PLUGIN_PATH
WITH_SELINUX
WITH_NSCD
WITH_SEMANAGE
WITH_NOLOGIN_SHELL
WITH_APP_LIBS
WITH_SUDO
WITH_SUDO_LIB_PATH
WITH_AUTOFS
WITH_SSH
WITH_IFP
WITH_CRYPTO
WITH_SYSLOG
WITH_SAMBA

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
m4_include([src/external/configlib.m4])

if test x$build_config_lib = xyes; then
    m4_include([src/external/libaugeas.m4])
fi

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
    AC_CHECK_FUNC([dbus_watch_get_unix_fd],
                  AC_DEFINE([HAVE_DBUS_WATCH_GET_UNIX_FD], [1],
                            [Define if dbus_watch_get_unix_fd exists]))
    LIBS="$SAFE_LIBS"
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

    if test x$HAVE_PROFILE_CATALOGS == x; then
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

if test x$HAVE_PYTHON_BINDINGS != x; then
    PYTHON=python2
    AM_PATH_PYTHON([2.4])
    AM_CHECK_PYTHON_HEADERS([],
                            AC_MSG_ERROR([Could not find python headers]))
    AM_PYTHON_CONFIG
    AM_CHECK_PYTHON_COMPAT
fi

if test x$HAVE_SELINUX != x; then
    AM_CHECK_SELINUX
    AM_CHECK_SELINUX_LOGIN_DIR
fi

if test x$HAVE_SEMANAGE != x -a x$HAVE_SELINUX != x; then
    AM_CHECK_SEMANAGE
fi

if test x$HAVE_SYSTEMD_UNIT != x; then
    AM_CHECK_SYSTEMD
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

AM_CONDITIONAL([HAVE_DEVSHM], [test -d /dev/shm])

abs_build_dir=`pwd`
AC_DEFINE_UNQUOTED([ABS_BUILD_DIR], ["$abs_build_dir"], [Absolute path to the build directory])
AC_SUBST([abs_builddir], $abs_build_dir)

AC_CONFIG_FILES([Makefile contrib/sssd.spec src/examples/rwtab src/doxy.config
                 src/sysv/sssd src/sysv/gentoo/sssd src/sysv/SUSE/sssd
                 po/Makefile.in src/man/Makefile
                 src/providers/ipa/ipa_hbac.pc src/providers/ipa/ipa_hbac.doxy
                 src/lib/idmap/sss_idmap.pc src/lib/idmap/sss_idmap.doxy
                 src/sss_client/sudo/sss_sudo.doxy
                 src/sss_client/idmap/sss_nss_idmap.pc
                 src/sss_client/idmap/sss_nss_idmap.doxy
                 src/lib/sifp/sss_simpleifp.pc
                 src/lib/sifp/sss_simpleifp.doxy
                 src/config/setup.py
                 src/responder/ifp/org.freedesktop.sssd.infopipe.service
                 src/config/SSSDConfig/__init__.py])
AC_OUTPUT
