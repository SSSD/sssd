#!/bin/bash

SRCDIR=$1
CODEGEN="$SRCDIR/src/sbus/codegen/sbus_CodeGen.py"

generate() {
    XML=$1
    DEST=$2
    PREFIX=$3
    HEADERS=`echo $DEST | sed -E 's|^$SRCDIR/src/||'`

    shift 3

    echo "Generating sbus code for: $XML"

    python $CODEGEN --sbus sbus --util util \
        --headers "$HEADERS" \
        --dest "$SRCDIR/src/$DEST" \
        --fileprefix "sbus_${PREFIX}_" \
        --symbolprefix "$PREFIX" $* \
        "$SRCDIR/src/$XML"
}

generate sbus/codegen/dbus.xml sbus/interface_dbus dbus
