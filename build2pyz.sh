#!/bin/bash
# date 2020-06-07 07:08:55
# author calllivecn <c-all@qq.com>

CWD=$(pwd -P)
TMP=$(mktemp -d -p "$CWD")

NAME="tar"
EXT=".pyz"

pip3 install --no-compile -r src/requirements.txt --target "${TMP}" 

clean(){
	echo "clean... ${TMP}"
	rm -rf "${TMP}"
	echo "done"
}

trap clean SIGINT SIGTERM EXIT ERR

cp -rv src/*.py "$TMP"

shiv --site-packages "$TMP" --compressed -p '/usr/bin/python3 -sE' -o "${NAME}.pyz" -e tar:main
