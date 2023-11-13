# Primary version number
m4_define([VERSION_NUMBER], [2.9.3])

# If the PRERELEASE_VERSION_NUMBER is set, we'll append
# it to the release tag when creating an RPM or SRPM
# This is intended for build systems to create snapshot
# RPMs. The format should be something like:
# .20090915gitf1bcde7
# and would result in an SRPM looking like:
# sssd-0.5.0-0.20090915gitf1bcde7.fc11.src.rpm
m4_define([PRERELEASE_VERSION_NUMBER], [])

