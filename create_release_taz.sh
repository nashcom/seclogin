#!/bin/bash
set -e

log()
{
  echo
  echo "$@"
  echo
}

TAR_FILE="seclogin-$(cat version.txt)-linux64.tar.gz"

if [ -e "$TAR_FILE" ]; then
  log "Removing existing release file: $TAR_FILE"
  rm -f "$TAR_FILE"
fi

tar -czf "$TAR_FILE" seclogin

log "Release file created: $TAR_FILE"
