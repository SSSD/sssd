#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPT_PATH=$(dirname "$SCRIPT")
exec python2 $SCRIPT_PATH/pysss_murmur-test.py
