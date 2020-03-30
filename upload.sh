#!/bin/sh
# upload.sh - file uploader for Bitbucket Cloud
# Copyright (C) 2018-2019 Kaz Nishimura
#
# Copying and distribution of this file, with or without modification, are
# permitted in any medium without royalty provided the copyright notice and
# this notice are preserved.  This file is offered as-is, without any warranty.

repository="$BITBUCKET_REPO_FULL_NAME"
user="$USERNAME${PASSWORD+:$PASSWORD}"

while getopts 'r:u:' opt; do
    case "$opt" in
    r) repository="$OPTARG" ;;
    u) user="$OPTARG" ;;
    '?') exit 64 ;;
    esac
done
set -- _ "$@"
shift "$OPTIND"

if test -z "$repository"; then
    echo "$0: repository not specified" >&2
    exit 1
fi

args=
for file in "$@"; do
    args="$args --fail --form files=@\"$file\""
done

exec curl ${user:+--user "$user"} --request POST $args \
    "https://api.bitbucket.org/2.0/repositories/$repository/downloads"
