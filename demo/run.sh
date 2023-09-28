#!/usr/bin/env bash

set -e

function join_by { local IFS="$1"; shift; echo "$*"; }

rm -rf charoncluster
rm -f env

charon create cluster \
  --fee-recipient-addresses 0x00000000219ab540356cBB839Cbe05303d7705Fa \
  --withdrawal-addresses 0x00000000219ab540356cBB839Cbe05303d7705Fa \
  --name "simpledvt" \
  --num-validators 1 --nodes 4 \
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
../lido-dv-exit mockservers --validators $(join_by "," $raw_validators) --lockfile-path $cluster_lock_path > /dev/null 2>&1 &
pids+=($!)


echo "starting anvil"
anvil --fork-url https://mainnet.infura.io/v3/2c9aded0297647a3b0d408e0f4749aaf -b 1 > /dev/null 2>&1 &
pids+=($!)

sleep 2

echo "setting up lido mock EL contracts"

bash lido-1-setup-validators.sh

source ./env

echo "starting ejector instances for each operator"

for i in {0..3} ; do
  rm -rf ejector_node$i
  mkdir ejector_node$i
done

echo "starting lido-dv-exit signature aggregation process"

for i in {0..3} ; do
  ../lido-dv-exit run --beacon-node-url http://localhost:9999 --charon-runtime-dir charoncluster/node$i --ejector-exit-path ejector_node$i --obol-api-url http://localhost:9998 &
  pids+=($!)
done

sleep 15

echo "sleeping 15s before starting ejector containers"

for i in {0..3} ; do
    docker run --rm -it --quiet -d \
      --name ejector_node$i \
      -e EXECUTION_NODE=http://host.docker.internal:8545 \
      -e CONSENSUS_NODE=http://host.docker.internal:9999 \
      -e LOCATOR_ADDRESS=$locator_address \
      -e STAKING_MODULE_ID=$simple_dvt_module_id \
      -e OPERATOR_ID=$operator_id \
      -e ORACLE_ADDRESSES_ALLOWLIST="[\"$exit_bus_oracle_address\"]" \
      -e MESSAGES_LOCATION=/exitmessages \
      -e DRY_RUN=true \
      -e LOGGER_LEVEL=debug \
      -e JOB_INTERVAL=10000 \
      -e RUN_METRICS=true \
      -e BLOCKS_LOOP=1000 \
      -e DISABLE_SECURITY_DONT_USE_IN_PRODUCTION=true \
      -p 4000$i:8989 \
      -v $PWD/ejector_node$i:/exitmessages \
      lidofinance/validator-ejector:local
done

echo "press enter to request validators to exit through lido ejector"

read

bash lido-2-exit-validators.sh

echo "done! press enter to exit and cleanup"

read

clean_up

popd
