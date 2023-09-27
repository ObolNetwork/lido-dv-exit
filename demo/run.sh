#!/usr/bin/env bash

set -e

function join_by { local IFS="$1"; shift; echo "$*"; }

rm -rf charoncluster

charon create cluster \
  --fee-recipient-addresses 0x00000000219ab540356cBB839Cbe05303d7705Fa \
  --withdrawal-addresses 0x00000000219ab540356cBB839Cbe05303d7705Fa \
  --name "simpledvt" \
  --num-validators 10 --nodes 4 \
  --network goerli \
  --cluster-dir charoncluster

cluster_lock_path="charoncluster/node0/cluster-lock.json"

raw_validators=$(jq -r .distributed_validators[].distributed_public_key $cluster_lock_path)

comma_validators=$(join_by " " $raw_validators)

export VALIDATORS_PUBKEYS=$comma_validators

echo $VALIDATORS_PUBKEYS

pids=()

function clean_up {
    for i in {0..3} ; do
      docker stop ejector_node$i
        rm -rf ejector_node$i
    done

    for item in ${pids[@]}; do
        kill $item
    done

    exit
}

trap clean_up SIGHUP SIGINT SIGTERM

echo "starting lido-dv-exit mockservers"
../lido-dv-exit mockservers --validators $(join_by "," $raw_validators) --lockfile-path $cluster_lock_path &
pids+=($!)


echo "starting anvil"
anvil --fork-url https://mainnet.infura.io/v3/2c9aded0297647a3b0d408e0f4749aaf > /dev/null 2>&1 &
pids+=($!)

echo "starting ejector instances for each operator"

for i in {0..3} ; do
  rm -rf ejector_node$i
  mkdir ejector_node$i
  docker run --rm -it --quiet -d \
    --name ejector_node$i \
    -e EXECUTION_NODE=http://host.docker.internal:8545 \
    -e CONSENSUS_NODE=http://host.docker.internal:9999 \
    -e LOCATOR_ADDRESS=0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb \
    -e STAKING_MODULE_ID=1 \
    -e OPERATOR_ID=0 \
    -e ORACLE_ADDRESSES_ALLOWLIST='["0x852deD011285fe67063a08005c71a85690503Cee"]' \
    -e MESSAGES_LOCATION=/exitmessages \
    -e DRY_RUN=true \
    -v $PWD/ejector_node$i:/exitmessages \
    lidofinance/validator-ejector:local
done

echo "press enter to start lido-dv-exit signature aggregation process"
read

for i in {0..3} ; do
  ../lido-dv-exit run --beacon-node-url http://localhost:9999 --charon-runtime-dir charoncluster/node$i --ejector-exit-path ejector_node$i --obol-api-url http://localhost:9998 &
  pids+=($!)
done

read

clean_up

popd
