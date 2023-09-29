#!/usr/bin/env bash

set -e

function join_by { local IFS="$1"; shift; echo "$*"; }

pids=()

pushd agg-only-demo

cluster_lock_path="./node0/cluster-lock.json"

raw_validators=$(jq -r .distributed_validators[].distributed_public_key $cluster_lock_path)

comma_validators=$(join_by " " $raw_validators)

export VALIDATORS_PUBKEYS=$comma_validators

echo "starting lido-dv-exit mockservers"
../lido-dv-exit mockservers --validators $(join_by "," $raw_validators) --lockfile-path $cluster_lock_path  > /dev/null 2>&1 &
pids+=($!)

for i in {0..3}; do
  rm -rf ejector_node$i
  mkdir ejector_node$i
  ../lido-dv-exit run \
    --beacon-node-url http://localhost:9999 \
    --charon-runtime-dir node$i \
    --ejector-exit-path ejector_node$i \
    --obol-api-url http://localhost:9998 \
    &
done

function clean_up {
  for item in ${pids[@]}; do
      kill -9 $item
  done

  popd
  exit
}

trap clean_up SIGHUP SIGINT SIGTERM

echo "press enter when done"
read

clean_up
