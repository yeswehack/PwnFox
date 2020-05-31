#!/bin/bash

cd "$(dirname "$0")"

function build_ff(){
    pushd firefox
    web-ext build --overwrite-dest
    version=$(cat manifest.json | grep '"version"' | cut -d '"' -f 4)
    success=$?
    cp web-ext-artifacts/pwnfox-${version}.zip web-ext-artifacts/pwnfox-latest.zip
    popd
    return $success
}

function build_burp(){
    pushd burp
    gradle build
    success=$?
    popd
    return $success
}

mkdir -p bin
(build_ff && build_burp) || exit
cp "firefox/web-ext-artifacts/pwnfox-latest.zip" ./bin/
cp "burp/build/libs/PwnFox.jar" ./bin/

echo "BUILD COMPLETE"                         
