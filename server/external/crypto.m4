AC_ARG_ENABLE(crypto,
    [  --enable-crypto         Use OpenSSL crypto instead of NSS],
    [CRYPTO="$enableval"],
    [CRYPTO="no"]
)

if test x$CRYPTO != xyes; then
    PKG_CHECK_MODULES([NSS],[nss],[have_nss=1],[have_nss=])
else
    PKG_CHECK_MODULES([CRYPTO],[libcrypto],[have_crypto=1],[have_crypto=])
fi
AM_CONDITIONAL([HAVE_NSS], [test x$have_nss != x])
AM_CONDITIONAL([HAVE_CRYPTO], [test x$have_crypto != x])
