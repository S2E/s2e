#!/bin/bash

# Copyright (C) 2016, Dependable Systems Laboratory, EPFL
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.


#
# Print human readable fork profile info.
#
# Usage: ./forkprofile.sh
#
# Output format:
#   --- BY ADDRESS ---
#   COUNT ADDRESS FUNCTION SRC_LINE
#   --- BY LINE ---
#   COUNT FUNCTION SRC_LINE
#   --- BY FUNCTION ---
#   COUNT FUNCTION
#

set -eu

# Adjust paths if needed
BOOTSTRAP='./bootstrap.sh'
BINARIES_DIR='./binaries/'
OUT='./out/s2e-last'
FORKPROFILER='./forkprofiler'
CGC_ADDR2LINE='./i386-linux-cgc-addr2line'
VMLINUX='../linux/vmlinux'

# Get binary name from bootstrap.sh (search for line CB="XXX")
BINARY=$(sed -nr 's/^CB="(.*)"/\1/p' ${BOOTSTRAP} | tail -n1)
if [ -z "${BINARY}" ]; then
  echo 'No binary!'
  exit
fi
echo "Binary: ${BINARY}"

# Check linux image exists
[ ! -f ${VMLINUX} ] && { echo "${VMLINUX} not found, will not addr2line kernel PCs"; VMLINUX=''; }

# Collect execution traces
if [ -f "${OUT}/ExecutionTracer.dat" ]; then
  traces="-trace=${OUT}/ExecutionTracer.dat"
else
  num=0
  EXPDIR=$(pwd)/${OUT}
  traces=""

  while [ true ]; do
    if [ ! -d "$EXPDIR/$num" ]; then
      break
    fi

    if [ -f "$EXPDIR/$num/ExecutionTracer.dat" ]; then
      traces="$traces -trace=$EXPDIR/$num/ExecutionTracer.dat"
    fi

    num=$(expr $num + 1)
  done
fi

# Build fork profile
${FORKPROFILER} -outputdir=${OUT}/ $traces >/dev/null

# Parse fork profile
IFS=$'\n'
FORKSTAT=( $(cat ${OUT}/forkprofile.txt | tail -n +2 | awk '{print $1, $2, $3}') )
unset IFS

if [ ${#FORKSTAT[@]} -eq 0 ]; then
  echo 'Empty fork profile!'
  exit -1
fi

# Output data

echo '--- BY ADDRESS ---'

declare -A LINESTAT
declare -A FUNCSTAT

for line in "${FORKSTAT[@]}"; do
  arr=( $line )
  addr=${arr[0]}
  mod=${arr[1]}
  cnt=${arr[2]}

  place="${addr} ?? ??:0"
  if [[ ${addr} -lt 0xc0000000 ]]; then
    [ "${mod}" == "${BINARY}" ] && place=$(${CGC_ADDR2LINE} -f -e ${BINARIES_DIR}${BINARY} -a ${addr})
  else
    [ -n "${VMLINUX}" ] && place=$(addr2line -f -e ${VMLINUX} -a ${addr})
  fi

  arr=( $place )
  func=${arr[1]}
  line=${arr[2]}

  funcline="${func} ${line}"
  set +u; [ ${LINESTAT[${funcline}]+_} ] || LINESTAT[${funcline}]=0; set -u
  LINESTAT[${funcline}]=$(( ${LINESTAT[${funcline}]} + ${cnt} ))

  set +u; [ ${FUNCSTAT[${func}]+_} ] || FUNCSTAT[${func}]=0; set -u
  FUNCSTAT[${func}]=$(( ${FUNCSTAT[${func}]} + ${cnt} ))

  echo $cnt $place
done

echo '--- BY LINE ---'

for f in "${!LINESTAT[@]}"; do
  echo ${LINESTAT[$f]} $f
done | sort -rh

echo '--- BY FUNCTION ---'

for f in "${!FUNCSTAT[@]}"; do
  echo ${FUNCSTAT[$f]} $f
done | sort -rh

