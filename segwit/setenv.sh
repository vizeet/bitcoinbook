#!/usr/bin/env bash
export BITCOIN_HOME=~/snap/bitcoin-core/common/.bitcoin
export BLOCKS_PATH=$BITCOIN_HOME/blocks/
export CHAINSTATE_DB=$BITCOIN_HOME/chainstate
export BLOCK_INDEX_DB=$BITCOIN_HOME/blocks/index
export TX_INDEX_DB=$BITCOIN_HOME/indexes/txindex

export BITCOIN_REGTEST_HOME=~/snap/bitcoin-core/common/.bitcoin/regtest
export REGTEST_BLOCKS_PATH=$BITCOIN_REGTEST_HOME/blocks/
export REGTEST_CHAINSTATE_DB=$BITCOIN_REGTEST_HOME/chainstate
export REGTESTBLOCK_INDEX_DB=$BITCOIN_REGTEST_HOME/blocks/index
export REGTEST_TX_INDEX_DB=$BITCOIN_REGTEST_HOME/indexes/txindex

export BITCOIN_TESTNET_HOME=~/snap/bitcoin-core/common/.bitcoin/testnet3
export TESTNET_BLOCKS_PATH=$BITCOIN_TESTNET_HOME/blocks/
export TESTNET_CHAINSTATE_DB=$BITCOIN_TESTNET_HOME/chainstate
export TESTNET_BLOCK_INDEX_DB=$BITCOIN_TESTNET_HOME/blocks/index
export TESTNET_TX_INDEX_DB=$BITCOIN_TESTNET_HOME/indexes/txindex
