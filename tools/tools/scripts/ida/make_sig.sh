#!/bin/sh

# This script produces an IDA FLIRT signature from the given collection
# of object files. Copy this file to the sig folder of your IDA installation.

FLAIR_ROOT="/opt/ida-6.6-sdk/flair66/bin/linux"

if [ ! -d "$FLAIR_ROOT" ]; then
  echo $FLAIR_ROOT does not exist
  exit 1
fi

if [ $# -ne 2 ]; then
  echo "Usage: $0 directory sigfile.sig"
  exit 1
fi

DIR="$1"
SIG="$2"

for f in $(find $DIR/ -name *.elf); do
  "$FLAIR_ROOT/pelf" "$f" "${f}.pat"
done

"$FLAIR_ROOT/sigmake" $(find $DIR/ -name *.pat) "$SIG"
