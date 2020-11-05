#!/usr/bin/env bash
#
# Dispatches wasmless transfers to a test net.
# Globals:
#   NCTL - path to nctl home directory.
# Arguments:
#   Network ordinal identifier.
#   Node ordinal identifier.
#   User ordinal identifier.
#   Transfer dispatch count.
#   Transfer dispatch interval.

# Import utils.
source $NCTL/sh/utils/misc.sh

#######################################
# Destructure input args.
#######################################

# Unset to avoid parameter collisions.
unset amount
unset gas
unset interval
unset net
unset node
unset payment
unset transfers
unset user

for ARGUMENT in "$@"
do
    KEY=$(echo $ARGUMENT | cut -f1 -d=)
    VALUE=$(echo $ARGUMENT | cut -f2 -d=)
    case "$KEY" in
        amount) amount=${VALUE} ;;
        gas) gas_price=${VALUE} ;;
        interval) transfer_interval=${VALUE} ;;
        net) net=${VALUE} ;;
        node) node=${VALUE} ;;
        payment) gas_payment=${VALUE} ;;
        transfers) transfers=${VALUE} ;;
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
transfers=${transfers:-100}
transfer_interval=${transfer_interval:-0.01}
user=${user:-1}

#######################################
# Main
#######################################

# Deploy dispatcher.
function _dispatch_deploy() {
    echo $(
        $path_net/bin/casper-client transfer \
            --chain-name casper-net-$net \
            --gas-price $gas_price \
            --node-address $node_address \
            --payment-amount $gas_payment \
            --secret-key $cp1_secret_key \
            --ttl "1day" \
            --amount $amount \
            --target-account $cp2_public_key \
            | jq '.result.deploy_hash' \
            | sed -e 's/^"//' -e 's/"$//'
        )
}

# Set paths.
path_net=$NCTL_DATA/assets/net-$net

# Set counter-parties.
cp1_secret_key=$path_net/faucet/secret_key.pem
cp1_public_key=`cat $path_net/faucet/public_key_hex`
cp1_account_hash=$(get_account_hash $cp1_public_key)
cp2_public_key=`cat $path_net/users/user-$user/public_key_hex`
cp2_account_hash=$(get_account_hash $cp2_public_key)

log "dispatching $transfers wasmless transfers"
log "... network=$net"
log "... node=$node"
log "... transfer amount=$amount"
log "... transfer interval=$transfer_interval (s)"
log "... counter-party 1 public key=$cp1_public_key"
log "... counter-party 2 public key=$cp2_public_key"
log "... counter-party 1 account hash=$cp1_account_hash"
log "... counter-party 2 account hash=$cp2_account_hash"
if [ $transfers -le 10 ]; then
    log "... dispatched deploys:"
fi

# Dispatch transfers to each node in round-robin fashion.
if [ $node = "all" ]; then
    transferred=0
    while [ $transferred -lt $transfers ];
    do
        source $NCTL/assets/net-$net/vars
        for node_idx in $(seq 1 $NCTL_NET_NODE_COUNT)
        do
            node_address=$(get_node_address $net $node_idx)
            deploy_hash=$(_dispatch_deploy)
            if [ $transfers -le 10 ]; then
                log "... ... "$deploy_hash
            fi
            transferred=$((transferred + 1))
            if [[ $transferred -eq $transfers ]]; then
                break
            fi
            sleep $transfer_interval
        done
    done

# Dispatch transfers to user specified node.
else
    node_address=$(get_node_address $net $node)
    for transfer_id in $(seq 1 $transfers)
    do
        deploy_hash=$(_dispatch_deploy)
        if [ $transfers -le 10 ]; then
            log "... ... "$deploy_hash
        fi
        sleep $transfer_interval
    done
fi

log "dispatch complete"
