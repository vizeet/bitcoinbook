def getBlockReward(block_height):
    halving_count = block_height // 210000
    print(halving_count)
    block_reward = 50/(2**halving_count)
    return block_reward

block_reward = getBlockReward(645675)
print(block_reward)
