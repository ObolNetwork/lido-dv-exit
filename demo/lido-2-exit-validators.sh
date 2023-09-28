#!/bin/bash

# Run anvil in separate terminal
# anvil --fork-url https://mainnet.infura.io/v3/$INFURA_KEY

set -e
set -x

source ./env

#################################

# Variables
curated_module_address=0x55032650b14df07b85bF18A3a3eC8E0Af2e028d5
kernel_address=0xb8FFC3Cd6e7Cf5a098A1c92F48009765B24088Dc
ens_address=0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e
apm_address=0x0cb113890b04B49455DfE06554e2D784598A29C9
voting_address=0x2e59A20f205bB85a89C53f1936454680651E618e
agent_address=0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c

locator_address=0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb
staking_router_address=$(cast call $locator_address "stakingRouter()(address)")
lido_address=$(cast call $locator_address "lido()(address)")
dsm_address=$(cast call $locator_address "depositSecurityModule()(address)")
withdrawal_queue_address=$(cast call $locator_address "withdrawalQueue()(address)")
exit_bus_oracle_address=$(cast call $locator_address "validatorsExitBusOracle()(address)")

arr=($VALIDATORS_PUBKEYS)

echo "validators that will be requested to exit: $arr"

count=1
for pubkey in ${arr[@]}; do
  echo "exiting $pubkey"
  # 6. Request validators to exit

  # 6.1 Rewind time to the next frame of the oracle report to make sure the report has not passed yet
  current_oracle_state=$(cast call $exit_bus_oracle_address "getProcessingState()((uint256,uint256,bytes32,bool,uint256,uint256,uint256))")
  current_oracle_state_parsed=(${current_oracle_state//,/ })
  current_frame_deadline=${current_oracle_state_parsed[1]}
  next_block_time=$(($current_frame_deadline + 120)) # end of the frame + some time
  cast rpc evm_setNextBlockTimestamp $next_block_time > /dev/null
  cast rpc evm_mine > /dev/null
  current_slot_time=$current_frame_deadline
  echo "rewound time to the beginning of a new oracle frame"

  # 6.2 Get fast lane oracle members
  exit_bus_oracle_consensus_address=$(cast call $exit_bus_oracle_address "getConsensusContract()(address)")
  fast_lane_response=$(cast call $exit_bus_oracle_consensus_address "getFastLaneMembers()(address[],uint256[])")
  fast_lane_response_array=(${fast_lane_response//\n/ })
  fast_lane_members_array=${fast_lane_response_array[0]:1:${#fast_lane_response_array[0]}-2}
  fast_lane_members=(${fast_lane_members_array//,/ })
  echo "fetched fast lane members"

  # 6.3 Build a report
  genesis_time=$(cast call $exit_bus_oracle_address "GENESIS_TIME()(uint256)")
  slot_per_seconds=$(cast call $exit_bus_oracle_address "SECONDS_PER_SLOT()(uint256)")

  report_slot=$((($current_slot_time-$genesis_time) / $slot_per_seconds))
  consensus_version=$(cast call $exit_bus_oracle_address "getConsensusVersion()(uint256)")
  requests_count=1
  data_format=1
  validator_index=$count # some validator index

  numberToBytes() {
      local num="$1"
      local size_in_bytes="$2"
      local hex_num=$(printf '%x' "$num")
      local padding_length=$((2 * $size_in_bytes))
      local bytes_padded=$(printf "%0${padding_length}s" $hex_num | tr ' ' '0')
      echo 0x$bytes_padded
  }

  consensus_version_bytes=$(numberToBytes $consensus_version 32)
  report_slot_bytes=$(numberToBytes $report_slot 32)
  requests_count_bytes=$(numberToBytes $requests_count 32)
  data_format_bytes=$(numberToBytes $data_format 32)

  module_id_bytes=$(numberToBytes $simple_dvt_module_id 3)
  operator_id_bytes=$(numberToBytes $operator_id 5)
  validator_index_bytes=$(numberToBytes $validator_index 8)
  data_bytes=$(cast concat-hex $module_id_bytes $operator_id_bytes $validator_index_bytes $pubkey)

  report="($consensus_version,$report_slot,$requests_count,$data_format,$data_bytes)"
  report_encoded=$(cast abi-encode "submitReportData((uint256,uint256,uint256,uint256,bytes))" $report)
  report_hash=$(cast keccak $report_encoded)

  # 6.4 Submit report hashes from fast lane members
  for fast_lane_member_address in "${fast_lane_members[@]}"
  do
      cast rpc anvil_setBalance $fast_lane_member_address 0x100000000000000000 > /dev/null
      cast send --unlocked --from $fast_lane_member_address $exit_bus_oracle_consensus_address "submitReport(uint256,bytes32,uint256)" $report_slot $report_hash $consensus_version > /dev/null
      echo "report hash submitted from $fast_lane_member_address"
  done

  # 6.5 Submit report data
  first_member_address=${fast_lane_members[0]}
  contract_version=$(cast call $exit_bus_oracle_address "getContractVersion()(uint256)")

  cast send --unlocked --from $first_member_address $exit_bus_oracle_address "submitReportData((uint256,uint256,uint256,uint256,bytes),uint256)" $report $contract_version > /dev/null
  echo "report data sent"

  (( count++ ))
done
