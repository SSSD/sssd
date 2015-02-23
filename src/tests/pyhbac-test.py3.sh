#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPT_PATH=$(dirname "$SCRIPT")
exec python3 $SCRIPT_PATH/pyhbac-test.py
