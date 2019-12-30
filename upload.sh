#!/bin/sh
# upload.sh - file uploader for Bitbucket Cloud
# Copyright (C) 2018-2019 Kaz Nishimura
#
# Copying and distribution of this file, with or without modification, are
# permitted in any medium without royalty provided the copyright notice and
# this notice are preserved.  This file is offered as-is, without any warranty.

repository="$BITBUCKET_REPO_FULL_NAME"

test -n "$USERNAME" || exit 0

if test -z "$repository"; then
    echo "Repository not specified" >&2
    exit 1
fi

for file in "$@"; do
    files="$files --form files=@\"$file\""
done
test -n "$files" || exit 1

exec curl --silent --show-error --user "$USERNAME${PASSWORD+:$PASSWORD}" \
    --request POST $files \
    https://api.bitbucket.org/2.0/repositories/$repository/downloads
