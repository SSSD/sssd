#!/bin/bash

print-usage() {
    cat <<EOF
Run SSSD Continuous Integration Tests
Make sure to checkout and setup https://github.com/SSSD/sssd-test-suite

run.sh SSSD-SOURCE-DIR TEST-SUITE-DIR ARTIFACTS-DIR CONFIG-FILE
  SSSD-SOURCE-DIR Path to SSSD source directory.
  TEST-SUITE-DIR  Path to sssd-test-suite_dir directory.
  ARTIFACTS-DIR   Path to directory where artifacts should be stored.
  CONFIG-FILE     Path to sssd-test-suite_dir configuration file to use.
EOF
}

print-help-if-asked() {
    while test $# -gt 0
    do
        case "$1" in
            --help)
                print-usage ; exit 0
                ;;
            -h) print-usage ; exit 0
                ;;
            -?) print-usage ; exit 0
                ;;
        esac
        shift
    done
}

success-or-die() {
    if [ $1 -ne 0 ]; then
        echo $2
        exit 1
    fi
}

print-help-if-asked "$@"
if [[ $# -ne 4 ]]; then
    print-usage
    exit 1
fi

sssd_source=$1
suite_dir=$2
artifacts_dir=$3
config=$4

guest_source="/shared/sssd"
guest_artifacts="/shared/artifacts"

# Currently only client machine is needed.
guests="client"

run-vagrant() {
    VAGRANT_CWD="$suite_dir" \
    SSSD_TEST_SUITE_RSYNC="$sssd_source:$guest_source" \
    SSSD_TEST_SUITE_SSHFS="$artifacts_dir:$guest_artifacts" \
    SSSD_TEST_SUITE_CONFIG="$config" \
    vagrant "$@"
}

start-guest() {
    # This may fail if guest's box was not yet downloaded. We will ignore it.
    run-vagrant destroy $1 &> /dev/null

    run-vagrant box update client
    success-or-die $? "Unable to update guest: $1"

    run-vagrant up client
    success-or-die $? "Unable to start guest: $1"
}

stop-guest() {
    run-vagrant halt $1
    success-or-die $? "Unable to halt guest: $1"
}

echo "[1/5] Creating $artifacts_dir"
mkdir -p "$artifacts_dir"
success-or-die $? "Unable to create directory: $artifacts_dir"

echo "[2/5] Updating sssd-test-suite"
git -C "$suite_dir" pull --rebase
success-or-die $? "Unable to rebase sssd-test-suite at: $suite_dir"

echo "[3/5] Preparing vagrant machines"
for guest in $guests; do
    start-guest $guest
done

echo "[4/5] Running tests"
run-vagrant ssh client -- "$guest_source/contrib/test-suite/run-client.sh"
success-or-die $? "SSSD Test Suite Failed: $?"

echo "[5/5] Shutdown machines"
for guest in $guests; do
    stop-guest $guest
done
