dnl
dnl Enable all known GCC compiler warnings, except for those
dnl we can't yet cope with
dnl
AC_DEFUN([SSSD_COMPILE_WARNINGS],[
    dnl ******************************
    dnl More compiler warnings
    dnl ******************************

    AC_ARG_ENABLE([werror],
                  AS_HELP_STRING([--enable-werror], [Use -Werror (if supported)]),
                  [set_werror="$enableval"],
                  [if test -d $srcdir/.git; then
                     is_git_version=true
                     set_werror=yes
                   else
                     set_werror=no
                   fi])

    # List of warnings that are not relevant/wanted

    dontwarn=$1

    # In case these warnings are enabled we will break the build on every single
    # system used by our CI
    dontwarn="$dontwarn -Wcpp"
    dontwarn="$dontwarn -Winline"
    dontwarn="$dontwarn -Wsystem-headers"

    # We have no intention to fix these warnings

    # If we enable this warning, complitaion will break on RHEL6
    dontwarn="$dontwarn -Woverlength-strings"

    # Enable this again as soon as GCC is updated on RHEL6
    # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=34114
    dontwarn="$dontwarn -Wunsafe-loop-optimizations"

    # These are the warnings that, currently, we cannot cope with
    dontwarn="$dontwarn -Warray-bounds"
    dontwarn="$dontwarn -Wbad-function-cast"
    dontwarn="$dontwarn -Wformat-nonliteral"
    dontwarn="$dontwarn -Wformat-signedness"
    dontwarn="$dontwarn -Wformat-y2k"
    dontwarn="$dontwarn -Wlogical-op"
    dontwarn="$dontwarn -Wmissing-prototypes"
    dontwarn="$dontwarn -Wmissing-declarations"
    dontwarn="$dontwarn -Wpacked"
    dontwarn="$dontwarn -Wsign-compare"
    dontwarn="$dontwarn -Wstrict-overflow"
    dontwarn="$dontwarn -Wsuggest-attribute=pure"
    dontwarn="$dontwarn -Wsuggest-attribute=const"
    dontwarn="$dontwarn -Wsuggest-attribute=format"
    dontwarn="$dontwarn -Wsuggest-attribute=noreturn"
    dontwarn="$dontwarn -Wswitch-default"
    dontwarn="$dontwarn -Wunused-parameter"
    dontwarn="$dontwarn -Wunused-macros"
    dontwarn="$dontwarn -Wvla"

    # Get all possible GCC warnings
    gl_MANYWARN_ALL_GCC([maybewarn])

    # Remove the ones we don't want, blacklisted earlier
    gl_MANYWARN_COMPLEMENT([wantwarn], [$maybewarn], [$dontwarn])

    # Check for $CC support of each warning
    for w in $wantwarn; do
      gl_WARN_ADD([$w])
    done

    # GNULIB uses '-W' (aka -Wextra) which includes a bunch of stuff.
    # Unfortunately, this means you can't simply use '-Wsign-compare'
    # with gl_MANYWARN_COMPLEMENT
    # So we have -W enabled, and then have to explicitly turn off ...
    gl_WARN_ADD([-Wno-array-bounds])
    gl_WARN_ADD([-Wno-sign-compare])
    gl_WARN_ADD([-Wno-unused-parameter])

    # Use improved glibc headers
    AH_VERBATIM([FORTIFY_SOURCE],
    [/* Enable compile-time and run-time bounds-checking, and some warnings,
        without upsetting newer glibc. */
     #if !defined _FORTIFY_SOURCE && defined __OPTIMIZE__ && __OPTIMIZE__
     # define _FORTIFY_SOURCE 2
     #endif
    ])

    # Extra special flags
    gl_WARN_ADD([-fno-strict-aliasing])
    gl_WARN_ADD([-std=gnu99])
    gl_WARN_ADD([-Werror-implicit-declaration])

    if test "$set_werror" = "yes"
    then
      gl_WARN_ADD([-Werror])
    fi

    AC_SUBST([WARN_CFLAGS])
])
