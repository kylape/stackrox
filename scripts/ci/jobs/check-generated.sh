#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
# shellcheck source=../../../scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail
export SHELLOPTS

go mod tidy

FAIL_FLAG="/tmp/fail"

# This scripts consists of separate checks, each implemented in the form of a separate shell functions.
# After execution of each step we might need to handle errors.
#
# But unfortunately simply doing
#
#   set -e
#
#   function some_check() {
#       do_foo()
#       do_bar() # Only do this when do_foo() succeeded
#   }
#   some_check || handle_errors
#
# doesn't work as expected, because the `... || handle_errors` construct disables errexit (`set -e`), which means
# that `do_bar()` will be executed irregardless of whether `do_foo()` succeeded or failed, which is not the behavior
# we want at this point -- instead we want to terminate early and propagate a failure in a sequence of commands.
#
# Therefore we are using the following slightly more complex pattern here:
#
#   set -e
#   export SHELLOPTS # Propagate errexit to sub-shells.
#
#   function some_check() {
#       do_foo()
#       do_bar() # Only do this when do_foo() succeeded
#   }
#   export -f some_check
#   bash -c some_check || handle_errors
#
# This way we get both:
#
#   1. errexit behavior throughout the script.
#   2. a single point for handling errors after each check.

# shellcheck disable=SC2016
info 'Ensure that generated files are up to date. (If this fails, run `make proto-generated-srcs && make go-generated-srcs` and commit the result.)'
function generated_files-are-up-to-date() {
    git ls-files --others --exclude-standard >/tmp/untracked
    make proto-generated-srcs
    # Remove generated mocks, they should be regenerated and if source was deleted they should be deleted as well.
    git grep --files-with-matches "Package mocks is a generated GoMock package." -- '*.go' | xargs rm
    # Print the timestamp along with each new line of output, so we can track how long each command takes
    make go-generated-srcs 2>&1 | while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line"; done
    git diff --exit-code HEAD
    { git ls-files --others --exclude-standard ; cat /tmp/untracked ; } | sort | uniq -u >/tmp/untracked-new

    if [[ -s /tmp/untracked-new ]]; then
        # shellcheck disable=SC2016
        echo 'ERROR: Found new untracked files after running `make proto-generated-srcs` and `make go-generated-srcs`. Did you forget to `git add` generated mocks and protos?'
        cat /tmp/untracked-new

        if is_OPENSHIFT_CI; then
            cp /tmp/untracked-new "${ARTIFACT_DIR:-}/untracked-new"
        fi
        return 1
    fi
}
export -f generated_files-are-up-to-date
bash -c generated_files-are-up-to-date || {
    save_junit_failure "Check_Generated_Files" \
        "Found new untracked files after running \`make proto-generated-srcs\` and \`make go-generated-srcs\`" \
        "$(cat /tmp/untracked-new)"
    git reset --hard HEAD
    echo generated_files-are-up-to-date >> "$FAIL_FLAG"
}

# shellcheck disable=SC2016
info 'Check operator files are up to date (If this fails, run `make -C operator manifests generate bundle` and commit the result.)'
function check-operator-generated-files-up-to-date() {
    make -C operator/ generate
    make -C operator/ manifests
    echo 'Checking for diffs after making generate and manifests...'
    git diff --exit-code HEAD
    make -C operator/ bundle
    echo 'Checking for diffs after making bundle...'
    echo 'If this fails, check if the invocation of the normalize-metadata.py script in operator/Makefile'
    echo 'needs to change due to formatting changes in the generated files.'
    git diff --exit-code HEAD
}
export -f check-operator-generated-files-up-to-date
bash -c check-operator-generated-files-up-to-date || {
    save_junit_failure "Check_Operator_Generated_Files" \
        "Operator generated files are not up to date" \
        "$(git diff HEAD || true)"
    git reset --hard HEAD
    echo check-operator-generated-files-up-to-date >> "$FAIL_FLAG"
}

# shellcheck disable=SC2016
info 'Check config-controller files are up to date (If this fails, run `make config-controller-gen` and commit the result.)'
function check-config-controller-generated-files-up-to-date() {
    make config-controller-gen
    echo 'Checking for diffs after making config-controller-gen...'
    git diff --exit-code HEAD
}
export -f check-config-controller-generated-files-up-to-date
bash -c check-config-controller-generated-files-up-to-date || {
    save_junit_failure "Check_Config_Controller_Generated_Files" \
        "Config controller generated files are not up to date" \
        "$(git diff HEAD || true)"
    git reset --hard HEAD
    echo check-config-controller-generated-files-up-to-date >> "$FAIL_FLAG"
}

info 'Check .containerignore file is in sync with .dockerignore (If this fails, follow instructions in .containerignore to update it.)'
function check-containerignore-is-in-sync() {
    diff \
        --unified \
        --ignore-blank-lines \
        <(grep -v -e '^#' .containerignore) \
        <(grep -vF -e '/.git/' -e '/image/' -e '/qa-tests-backend/' .dockerignore) \
    > diff.txt
}
export -f check-containerignore-is-in-sync
bash -c check-containerignore-is-in-sync || {
    save_junit_failure "Check_Containerignore_File" \
        ".containerignore file is not in sync with .dockerignore" \
        "$(cat diff.txt)"
    git reset --hard HEAD
    echo check-containerignore-is-in-sync >> "$FAIL_FLAG"
}

# shellcheck disable=SC2016
echo 'Check if a script that was on the failed shellcheck list is now fixed. (If this fails, run `make update-shellcheck-skip` and commit the result.)'
function check-shellcheck-failing-list() {
    make update-shellcheck-skip
    echo 'Checking for diffs after updating shellcheck failing list...'
    if ! git diff --exit-code HEAD; then
        echo 'Failure only if files can be removed from the skip file.'
        test "$(git diff --numstat scripts/style/shellcheck_skip.txt | cut -f2)" -lt 1 \
            && git reset --hard HEAD
    fi
}
export -f check-shellcheck-failing-list
bash -c check-shellcheck-failing-list || {
    save_junit_failure "Check_Shellcheck_Skip_List" \
        "Check if a script that is listed in scripts/style/shellcheck_skip.txt is now free from shellcheck errors" \
        "$(git diff HEAD || true)"
    git reset --hard HEAD
    echo check-shellcheck-failing-list >> "$FAIL_FLAG"
}

if [[ -e "$FAIL_FLAG" ]]; then
    echo "ERROR: Some generated file checks failed:"
    cat "$FAIL_FLAG"
    exit 1
fi
