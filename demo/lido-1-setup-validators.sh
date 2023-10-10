#!/bin/bash

# Run anvil in separate terminal
# anvil --fork-url https://mainnet.infura.io/v3/$INFURA_KEY

# this script exports in "env":
#  - simple_dvt_module_id
#  - operator_id
#  - exit_bus_oracle_address

set -e

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

echo "export exit_bus_oracle_address='$exit_bus_oracle_address'" >> env
echo "export locator_address='$locator_address'" >> env

deployer_address=0x00000000219ab540356cBB839Cbe05303d7705Fa

simple_dvt_app_name=simple-dvt

simple_dvt_app_id=0xe1635b63b5f7b5e545f2a637558a4029dea7905361a2f0fc28c66e9136cf86a4 # namehash('simple-dvt.lidopm.eth')
curated_module_app_id=0x7071f283424072341f856ac9e947e7ec0eb68719f757a7e785979b6b8717579d # namehash('node-operators-registry.lidopm.eth')


#################################


# 0. Enable auto impersonating
cast rpc anvil_autoImpersonateAccount true > /dev/null


#################################


# 1. Deploy app proxy for simple dvt module

new_app_proxy_call="--from $deployer_address $kernel_address newAppProxy(address,bytes32)(address) $kernel_address $simple_dvt_app_id"
simple_dvt_module_address=$(cast call $new_app_proxy_call)

cast send --unlocked $new_app_proxy_call > /dev/null
echo "simple dvt module proxy app deployed: simple_dvt_module_address"


#################################


# 2. Clone curated module

# 2.1 Get the curated module app info from the repo
resolver_address=$(cast call $ens_address 'resolver(bytes32)(address)' $curated_module_app_id)
repo_address=$(cast call $resolver_address 'addr(bytes32)(address)' $curated_module_app_id)
curated_module_version=$(cast call $repo_address 'getLatest()(uint16[3],address,bytes)')
curated_module_version_parsed=(${curated_module_version//\n/ })
curated_module_app_implementation_address=${curated_module_version_parsed[1]}
curated_module_app_content_uri=${curated_module_version_parsed[2]}

# 2.2 Top up voting and agent contracts to send transactions from them
cast rpc anvil_setBalance $voting_address 0x100000000000000000 > /dev/null
cast rpc anvil_setBalance $agent_address 0x100000000000000000 > /dev/null

# 2.3 Create app repo
simple_dvt_app_version='[1,0,0]'
simple_dvt_app_implementation_address=$curated_module_app_implementation_address
simple_dvt_module_app_content_uri=$curated_module_app_content_uri
cast send --unlocked --from $voting_address $apm_address 'newRepoWithVersion(string,address,uint16[3],address,bytes)(address)' $simple_dvt_app_name $voting_address $simple_dvt_app_version $simple_dvt_app_implementation_address $simple_dvt_module_app_content_uri > /dev/null
echo 'app repo created'

# 2.4 link app id with the implementation
kernel_app_bases_namespace=$(cast call $kernel_address 'APP_BASES_NAMESPACE()(bytes32)')
cast send --unlocked --from $voting_address $kernel_address 'setApp(bytes32,bytes32,address)' $kernel_app_bases_namespace $simple_dvt_app_id $simple_dvt_app_implementation_address > /dev/null
echo 'app id linked to the implementation'

# 2.5 Initialize module
curated_module_type=$(cast call $curated_module_address 'getType()(bytes32)')
curated_module_penalty_delay=$(cast call $curated_module_address 'getStuckPenaltyDelay()(uint256)')
simple_dvt_module_type=$curated_module_type
simple_dvt_penalty_delay=$curated_module_penalty_delay
cast send --unlocked --from $voting_address $simple_dvt_module_address 'initialize(address,bytes32,uint256)' $locator_address $simple_dvt_module_type $simple_dvt_penalty_delay > /dev/null
echo 'simple dvt module initialized'

# 2.6 Set permissions to voting contract
acl_address=$(cast call $kernel_address "acl()(address)")
manage_signing_keys_role=$(cast call $simple_dvt_module_address "MANAGE_SIGNING_KEYS()(bytes32)")
manage_node_operator_role=$(cast call $simple_dvt_module_address "MANAGE_NODE_OPERATOR_ROLE()(bytes32)")
set_node_operator_limit_role=$(cast call $simple_dvt_module_address "SET_NODE_OPERATOR_LIMIT_ROLE()(bytes32)")
cast send --unlocked --from $voting_address $acl_address "createPermission(address,address,bytes32,address)" $voting_address $simple_dvt_module_address $manage_signing_keys_role $voting_address > /dev/null
cast send --unlocked --from $voting_address $acl_address "createPermission(address,address,bytes32,address)" $voting_address $simple_dvt_module_address $manage_node_operator_role $voting_address > /dev/null
cast send --unlocked --from $voting_address $acl_address "createPermission(address,address,bytes32,address)" $voting_address $simple_dvt_module_address $set_node_operator_limit_role $voting_address > /dev/null
echo 'roles granted to the voting contract'

# 2.7 Set permissions to staking router contract
staking_router_role=$(cast call $simple_dvt_module_address "STAKING_ROUTER_ROLE()(bytes32)")
staking_module_manage_role=$(cast call $staking_router_address "STAKING_MODULE_MANAGE_ROLE()(bytes32)")

cast send --unlocked --from $agent_address $staking_router_address "grantRole(bytes32,address)" $staking_module_manage_role $voting_address > /dev/null
cast send --unlocked --from $voting_address $acl_address "createPermission(address,address,bytes32,address)" $staking_router_address $simple_dvt_module_address $staking_router_role $voting_address > /dev/null
echo 'roles granted to the staking router contract'

# 2.8 Connect new module to the staking router
simple_dvt_target_share=1000
simple_dvt_module_fee=500
simple_dvt_treasure_fee=500
cast send --unlocked --from $voting_address $staking_router_address "addStakingModule(string,address,uint256,uint256,uint256)" $simple_dvt_app_name $simple_dvt_module_address $simple_dvt_target_share $simple_dvt_module_fee $simple_dvt_treasure_fee > /dev/null
simple_dvt_module_index=$(($(cast call $staking_router_address "getStakingModulesCount()(uint256)")-1))
export simple_dvt_module_id=$(($simple_dvt_module_index+1))
echo "export simple_dvt_module_id='$simple_dvt_module_id'" >> env
echo "module connected to the staking router with index $simple_dvt_module_index"

#################################


# 3. Add new cluster (aka node operator)
operator_name='test_operator'
operator_reward_address=$deployer_address
operator_id=$(cast call --from $voting_address $simple_dvt_module_address "addNodeOperator(string,address)(uint256)" $operator_name $operator_reward_address)
cast send --unlocked --from $voting_address $simple_dvt_module_address "addNodeOperator(string,address)(uint256)" $operator_name $operator_reward_address > /dev/null
echo "added new operator with id $operator_id"
echo "export operator_id='$operator_id'" >> env

#################################

echo "submitting validator keys as specified in the VALIDATORS_PUBKEYS env var"

arr=($VALIDATORS_PUBKEYS)

keys_count=${#arr[@]}

for validator_pubkey in ${arr[@]}; do
  echo "submitting $validator_pubkey"
  # 4. Submit validator key
  pubkey=$validator_pubkey
  signature=0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002
  operator_id=0
  cast send --unlocked --from $operator_reward_address $simple_dvt_module_address "addSigningKeys(uint256,uint256,bytes,bytes)(uint256)" $operator_id $keys_count $pubkey $signature > /dev/null
  echo 'signing key submitted'

  cast send --unlocked --from $voting_address $simple_dvt_module_address "setNodeOperatorStakingLimit(uint256,uint64)" $operator_id $keys_count > /dev/null
  echo 'submitted key is vetted'
done





#################################


# 5. Deposit

# 5.1 Top up dsm contract to send transactions from it
cast rpc anvil_setBalance $dsm_address 0x100000000000000000 > /dev/null

# 5.2 Transfer some eth to the lido buffer
demand_in_withdrawal_queue=$(cast call $withdrawal_queue_address "unfinalizedStETH()(uint256)")
cast send --unlocked --from $deployer_address $lido_address --value $demand_in_withdrawal_queue > /dev/null
cast send --unlocked --from $deployer_address $lido_address --value 32ether > /dev/null

# 5.3 Perform deposit
deposits_count=1
cast send --unlocked --from $dsm_address $lido_address "deposit(uint256,uint256,bytes)" $deposits_count $simple_dvt_module_id 0x > /dev/null
echo "deposited"
