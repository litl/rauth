#!/bin/bash

OUTPUT_PATH=$(pwd)/tests_output

function log() {
    echo "$@" | tee -a $OUTPUT_PATH/test.log
}

function nosetest_yanc_plugin() {
    nosetests --plugins | grep yanc >/dev/null
}

rm -rf $OUTPUT_PATH
mkdir -p $OUTPUT_PATH

NOSETEST_OPTIONS="-d"

if [ -n "$VERBOSE" ]; then
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS --verbose"
fi

if [ -z "$NOCOLOR" ] && nosetest_yanc_plugin; then
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS --with-yanc --yanc-color=on"
fi

if [ -n "$OPTIONS" ]; then
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS $OPTIONS"
fi

if [ -n "$TESTS" ]; then
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS $TESTS"
else
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS --with-coverage --cover-package=rauth"
fi

nosetest_yanc_plugin || [ -n "$NOCOLOR" ] || log "No yanc plugin for nosetests found. Color output unavailable."

log "Running tests..."
nosetests $NOSETEST_OPTIONS 2>&1 | tee -a $OUTPUT_PATH/test.log
ret=${PIPESTATUS[0]}

echo

case "$ret" in
    0) log -e "SUCCESS" ;;
    *) log -e "FAILURE" ;;
esac

exit $ret
