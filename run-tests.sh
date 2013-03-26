#!/bin/sh

OUTPUT_PATH=`pwd`/tests_output

log()
{
    echo "$@" | tee -a $OUTPUT_PATH/test.log
}

nosetest_yanc_plugin()
{
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

if [ $BASH ]; then
    nosetests $NOSETEST_OPTIONS 2>&1 | tee -a $OUTPUT_PATH/test.log
    R=${PIPESTATUS[0]}
else
    4>&1 R=$({ { nosetests $NOSETEST_OPTIONS 2>&1; echo $? >&3 ; } | { tee -a $OUTPUT_PATH/test.log >&4; } } 3>&1)
fi

echo

case "$R" in
    0) log "SUCCESS" ;;
    *) log "FAILURE" ;;
esac

exit $R
