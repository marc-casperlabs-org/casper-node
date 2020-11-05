#!/usr/bin/env bash
#
# Invokes auction.withdraw-bid entry point.
# Globals:
#   NCTL - path to nctl home directory.
# Arguments:
#   Network ordinal identifier (int).
#   Node ordinal identifier (int).
#   User ordinal identifier (int).
#   Withdrawal amount (motes).

# Import utils.
source $NCTL/sh/utils/misc.sh

#######################################
# Destructure input args.
#######################################

# Unset to avoid parameter collisions.
unset amount
unset gas
unset payment
unset net
unset node
unset user

# Destructure.
for ARGUMENT in "$@"
do
    KEY=$(echo $ARGUMENT | cut -f1 -d=)
    VALUE=$(echo $ARGUMENT | cut -f2 -d=)
    case "$KEY" in
        amount) amount=${VALUE} ;;
        gas) gas_price=${VALUE} ;;
        net) net=${VALUE} ;;
        node) node=${VALUE} ;;
        payment) gas_payment=${VALUE} ;;
        user) user=${VALUE} ;;
        *)
    esac
done

# Set defaults.
amount=${amount:-1000000}
gas_payment=${gas_payment:-200000}
gas_price=${gas_price:-10}
net=${net:-1}
node=${node:-1}
user=${user:-1}

#######################################
# Main
#######################################

# Set vars.
user_public_key=$(cat $path_net/users/user-$user/public_key_hex)
user_purse_uref="TODO"
user_secret_key=$path_net/users/user-$user/secret_key.pem
contract_name="withdraw_bid.wasm"
node_address=$(get_node_address $net $node)
path_net=$NCTL_DATA/assets/net-$net
path_client=$path_net/bin/casper-client
path_contract=$path_net/bin/$contract_name

# Inform.
log "dispatching deploy -> "$contract_name
log "... network = $net"
log "... node = $node"
log "... node address = $node_address"
log "... contract = $path_contract"
log "... user id = $user"
log "... user public key = $user_public_key"
log "... user secret key = $user_secret_key"
log "... user purse uref = $user_purse_uref"
log "... withdrawal amount = $amount"

# Dispatch deploy.
deploy_hash=$(
    $path_client put-deploy \
        --chain-name casper-net-$net \
        --gas-price $gas_price \
        --node-address $node_address \
        --payment-amount $gas_payment \
        --secret-key $user_secret_key \
        --session-arg="public_key:public_key='$user_public_key'" \
        --session-arg "amount:u512='$amount'" \
        --session-arg "unbond_purse:uref-='$user_purse_uref'" \
        --session-path $path_contract \
        --ttl "1day" \
        | jq '.result.deploy_hash' \
        | sed -e 's/^"//' -e 's/"$//'
    )

# Display deploy hash.
log "deploy dispatched:"
log "... deploy hash = $deploy_hash"
