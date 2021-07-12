#!/bin/bash
# The script does automatic checking on a Go package and its sub-packages, including:
# 1. gofmt         (http://golang.org/cmd/gofmt/)
# 2. golint        (https://github.com/golang/lint)
# 3. go vet        (http://golang.org/cmd/vet)
# 4. gosimple      (https://github.com/dominikh/go-simple)
# 5. unconvert     (https://github.com/mdempsky/unconvert)
# 6. race detector (http://blog.golang.org/race-detector)
# 7. test coverage (http://blog.golang.org/cover)
#
# gometalinter (github.com/alecthomas/gometalinter) is used to run each static
# checker.

declare GREEN='\033[0;32m'
declare NC='\033[0m'
print () {
    echo -e "${GREEN}$1${NC}"
}

# test_with_profile run test coverage on each subdirectories and merge the
# coverage profile. Be aware that we are skipping the integration tests, as the
# tool won't gather any useful coverage information from them.
test_with_coverage_profile() {
    print "* Running tests with creating coverage profile"

    echo "mode: count" > profile.cov

    # Standard go tooling behavior is to ignore dirs with leading underscores.
    for dir in $(find . -maxdepth 10 \
    -not -path './.git*' \
    -not -path '*/_*' \
    -not -path './cmd*' \
    -not -path './release*' \
    -not -path './vendor*' \
    -type d)
    do
    if ls $dir/*.go &> /dev/null; then
      go test -v -covermode=count -coverprofile=$dir/profile.tmp $dir

      if [ -f $dir/profile.tmp ]; then
        cat $dir/profile.tmp | tail -n +2 >> profile.cov
        rm $dir/profile.tmp
      fi
    fi
    done

    if [ "$TRAVIS" == "true" ] ; then
        print "* Send test coverage to travis server"
        # Make sure goveralls is installed and $GOPATH/bin is in your path.
        if [ ! -x "$(type -p goveralls)" ]; then
            print "** Install goveralls:"
            go get github.com/mattn/goveralls
        fi

        print "** Submit the test coverage result to coveralls.io"
        goveralls -coverprofile=profile.cov -service=travis-ci
    fi
}

# test_race_conditions run standard go test without creating coverage
# profile but with race condition checks.
test_race_conditions() {
    print "* Running tests with the race condition detector"

    test_targets=$(go list ./... | grep -v '/vendor/')
    env GORACE="history_size=7 halt_on_error=1" go test -v -p 1 -race $test_targets
}

# lint_check runs static checks.
lint_check() {
    print "* Run static checks"

    # Make sure gometalinter is installed and $GOPATH/bin is in your path.
    if [ ! -x "$(type -p gometalinter.v2)" ]; then
        print "** Install gometalinter"
        GO111MODULE=off go get -u gopkg.in/alecthomas/gometalinter.v2
        GO111MODULE=off gometalinter.v2 --install
    fi

    # Update metalinter if needed.
    GO111MODULE=off gometalinter.v2 --install 1>/dev/null

    # Automatic checks
    linter_targets=$(go list ./... | grep -v 'lnrpc')
    test -z "$(gometalinter.v2 --disable-all \
    --enable=gofmt \
    --enable=vet \
    --enable=golint \
    --line-length=72 \
    --deadline=4m $linter_targets 2>&1 | grep -v 'ALL_CAPS\|OP_' 2>&1 | tee /dev/stderr)"
}

set -e

print "====+ Start +===="

# Read input flags and initialize variables
NEED_LINT="false"
NEED_COVERAGE="false"
NEED_RACE="false"
NEED_INSTALL="false"

while getopts "lrcio" flag; do
        case "${flag}" in
            l) NEED_LINT="true" ;;
            r) NEED_RACE="true" ;;
            c) NEED_COVERAGE="true" ;;
            i) NEED_INSTALL="true" ;;
            *)
                printf '\nUsage: %s [-l] [-r] [-c] [-i] [-o], where:\n' $0
                printf ' -l: include code lint check\n'
                printf ' -r: run tests with race condition check\n'
                printf ' -c: run tests with test coverage\n'
                printf ' -i: reinstall project dependencies\n'
                exit 1 ;;
        esac
    done

# remove the options from the positional parameters
shift $(( OPTIND - 1 ))

# Lint check is first because we shouldn't run tests on garbage code.
if [ "$NEED_LINT" == "true" ] || [ "$RACE" == "false" ]; then
    lint_check
fi

# Race condition second because we shouldn't check coverage on buggy code.
if [ "$NEED_RACE" == "true" ] || [ "$RACE" == "true" ]; then
    test_race_conditions
fi

# Test coverage is third because in this case code should work properly and
# we may calmly send coverage profile (if script is run on travis)
if [ "$NEED_COVERAGE" == "true" ] || [ "$RACE" == "false" ]; then
    test_with_coverage_profile
fi

print "=====+ End +====="
