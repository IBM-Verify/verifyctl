#!/bin/bash

package=github.com/ibm-verify/verifyctl/cmd/verifyctl
bin_name=verifyctl

# use go env if noset
GOOS=${GOOS:-$(go env GOOS)}
GOARCH=${GOARCH:-$(go env GOARCH)}
output_name=$bin_name'-'$GOOS'-'$GOARCH
if [ $GOOS = "windows" ]; then
	output_name+='.exe'
fi

env GOOS=$GOOS GOARCH=$GOARCH GO_BUILD_FLAGS="${GO_BUILD_FLAGS}" go build -o ./bin/$output_name $package
if [ $? -ne 0 ]; then
	echo 'Build failed!'
	exit 1
fi

# copy to arch-less binary if requested
archless=${1:-no}
if [ "$archless" == "yes" ] || [ "$archless" == "true" ]; then
	cp -f ./bin/$output_name ./bin/verifyctl
fi