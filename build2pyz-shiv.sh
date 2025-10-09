#!/bin/bash
# date 2020-06-07 07:08:55
# author calllivecn <calllivecn@outlook.com>

CWD=$(pwd -P)
TMP=$(mktemp -d -p "$CWD")

NAME="tarpy"
EXT=".pyz"

pip install --no-compile -r requirements.txt --target "${TMP}" 

clean(){
	echo "clean... ${TMP}"
	rm -rf "${TMP}"
	echo "done"
}

trap clean SIGINT SIGTERM EXIT ERR

cp -rv src/*.py "$TMP"

shiv --site-packages "$TMP" --compressed -p '/usr/bin/python -sE' -o "${NAME}.pyz" -e tar:main
