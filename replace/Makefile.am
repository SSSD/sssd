libreplace_sources = \
    dlfcn.c \
    getaddrinfo.c \
    getifaddrs.c \
    getpass.c \
    inet_aton.c \
    inet_ntoa.c \
    inet_ntop.c \
    inet_pton.c \
    repdir_getdents.c \
    repdir_getdirentries.c \
    replace.c \
    snprintf.c \
    socket.c \
    socketpair.c \
    strptime.c \
    timegm.c \
    getaddrinfo.h \
    replace.h \
    win32_replace.h \
    system/aio.h \
    system/capability.h \
    system/dir.h \
    system/filesys.h \
    system/glob.h \
    system/iconv.h \
    system/kerberos.h \
    system/locale.h \
    system/network.h \
    system/passwd.h \
    system/readline.h \
    system/select.h \
    system/shmem.h \
    system/syslog.h \
    system/terminal.h \
    system/time.h \
    system/wait.h

noinst_LIBRARIES = \
    libreplace.a

libreplace_a_SOURCES =
EXTRA_libreplace_a_SOURCES = \
    $(libreplace_sources)
libreplace_a_DEPENDENCIES = \
    @LIBREPLACEOBJ@

libreplace_a_LIBADD = \
    @LIBREPLACEOBJ@

tests: all
