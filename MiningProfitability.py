import plyvel
import os

block_db_g = plyvel.DB(os.getenv('BLOCK_INDEX_DB'), compression=None)

blocks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16

def b128_varint_decode(b: bytes, pos = 0):
    n = 0
    while True:
        data = b[pos]
        pos += 1
        n = (n << 7) | (data & 0x7f)
        if data & 0x80 == 0:
            return (n, pos)
        n += 1

SATOSHIS_IN_BTC = 10**8

def getBlockReward(block_height):
    halving_count = block_height // 210000
    block_reward = 50/(2**halving_count)
    return block_reward

def getBlockIndex(block_hash: bytes, block_db):
    key = b'b' + block_hash
    value = block_db.get(key)
    jsonobj = {}
    jsonobj['version'], pos = b128_varint_decode(value)
    jsonobj['height'], pos = b128_varint_decode(value, pos)
    jsonobj['status'], pos = b128_varint_decode(value, pos)
    jsonobj['tx_count'], pos = b128_varint_decode(value, pos)
    if jsonobj['status'] & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO):
            jsonobj['n_file'], pos = b128_varint_decode(value, pos)
    if jsonobj['status'] & BLOCK_HAVE_DATA:
            jsonobj['data_pos'], pos = b128_varint_decode(value, pos)
    if jsonobj['status'] & BLOCK_HAVE_UNDO:
            jsonobj['undo_pos'], pos = b128_varint_decode(value, pos)
    return jsonobj

def getTargetThreshold(bits: bytes):
    shift = bits[3]
    value = int.from_bytes(bits[0:3], byteorder='little')
    target_threshold = value * 2 ** (8 * (shift - 3))
    print('%x' % target_threshold)
    return target_threshold

def getNetworkHashRate(target_threshold: int):
    network_hashrate = (1<<256)/(600*target_threshold)
    return network_hashrate

def convertToRupeeFormat(num: float):
    numstr = "%.2f" % (num)

    commaloc = 6
    while commaloc < len(numstr):
            numstr = numstr[:-commaloc] + ',' + numstr[-commaloc:]
            commaloc += 3
    rupees = "\u20B9%s" % (numstr)
    return rupees

electricity_rates = {"rate_slabs": [{"min": 1, "max": 30, "unit_price": 3.25}, {"min": 31, "max": 100, "unit_price": 4.7}, {"min": 101, "max": 200, "unit_price": 6.25}, {"min": 201, "unit_price": 7.3}]}

def getPriceFromUnit(unit: float):
    rate_slabs = electricity_rates['rate_slabs']
    price = 0
    for slab in rate_slabs:
        if slab['min'] > unit:
                countinue
        elif ('max' in slab and slab['max']) > unit or 'max' not in slab:
                price += (unit - slab['min']) * slab['unit_price']
        else:
                price += (slab['max'] - slab['min']) * slab['unit_price']
    return price

def getUnitFromPower(power: float):
    unit = power * 24 * 30 / 1000
    return unit

def getBlockMiningRatePer10Min(hashrate: int, target_threshold: int):
    network_hashrate = getNetworkHashRate(target_threshold)
    block_mining_rate = hashrate/network_hashrate
    return block_mining_rate

def getBlockHeader(blkhdr: bytes):
    block = {}
    block['version'] = blkhdr[0:4][::-1].hex()
    blkhdr = blkhdr[4:]
    block['prev_blockhash'] = blkhdr[0:32][::-1].hex()
    blkhdr = blkhdr[32:]
    block['merkle_root'] = blkhdr[0:32][::-1].hex()
    blkhdr = blkhdr[32:]
    block['time'] =int.from_bytes(blkhdr[0:4], byteorder='little')
    blkhdr = blkhdr[4:]
    block['bits'] = blkhdr[0:4][::-1].hex()
    blkhdr = blkhdr[4:]
    block['nonce'] = blkhdr[0:4][::-1].hex()
    return block

def getBitcoinMiningRate(hashrate: int, bits: bytes, blk_reward: int):
    tgt_threshold = getTargetThreshold(bits)
    block_mining_rate = getBlockMiningRatePer10Min(hashrate, tgt_threshold)
    bitcoin_mining_rate = block_mining_rate * blk_reward
    return bitcoin_mining_rate

def getMiningPowerExpense(power: float):
    unit = getUnitFromPower(power)
    expense = getPriceFromUnit(unit)
    return expense

def getBitcoinMinedPerMonth(hashrate: int, bits: bytes, blk_reward: int):
    btc_mined_per_month = getBitcoinMiningRate(hashrate, bits, blk_reward) * 6 * 24 * 30
    return btc_mined_per_month

def getCurrentSellPrice():
    return 800000

def miningReturn(power: float, hashrate: int, bits: bytes, blk_reward: int):
    expense = getMiningPowerExpense(power)
    btc_mined_per_month = getBitcoinMinedPerMonth(hashrate, bits, blk_reward)
    revenue = btc_mined_per_month * getCurrentSellPrice()
    profit = revenue - expense
    return profit

def costOfMiningBitcoin(power: float, hashrate: int, bits: bytes, blk_reward: int):
    unit = getUnitFromPower(power)
    price_per_month = getPriceFromUnit(unit)
    bitcoin_mined_per_month = getBitcoinMiningRate(hashrate, bits, blk_reward) * 6 * 24 * 30
    cost_of_mining_bitcoin = price_per_month/bitcoin_mined_per_month
    return cost_of_mining_bitcoin

def getBlockHeaderBytes(blk_hash: bytes):
    global block_db_g, blocks_path_g
    jsonobj = getBlockIndex(blk_hash, block_db_g)
    if 'data_pos' in jsonobj:
        block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
        start = jsonobj['data_pos']
    elif 'undo_pos' in jsonobj:
        block_filepath = os.path.join(blocks_path_g, 'rev%05d.dat' % jsonobj['n_file'])
        start = jsonobj['undo_pos']

    # load file to memory
    with open(block_filepath, 'rb') as blk_f:
        blk_f.seek(start)
        return blk_f.read(80)

def getMinerHashRate():
    return 110 * 10**12

def getMinerPowerWatt():
    return 3250

if __name__ == '__main__':
    blk_hash = bytes.fromhex('000000000000000000081537d1ad0a35968c4e0b9dd76c647ffc174058e75d3c')[::-1]
    blk_index = getBlockIndex(blk_hash, block_db_g)
    blk_hdr_b = getBlockHeaderBytes(blk_hash)
    jsonobj = getBlockHeader(blk_hdr_b)
    print(jsonobj)

    blk_reward = getBlockReward(blk_index['height'])

    miner_hashrate = getMinerHashRate()
    print("Miner hashrate = %d" % (miner_hashrate))

    miner_power = getMinerPowerWatt()
    print ("Miner Power in Watt = %f" % (miner_power))

    expense = getMiningPowerExpense(miner_power)
    print ("Miner Power Expense Per Month = %.2f" % (expense))

    bits_b = bytes.fromhex(jsonobj['bits'])[::-1]
    bitcoin_mined_per_month = getBitcoinMinedPerMonth(miner_hashrate, bits_b, blk_reward)
    print("Bitcoin Mined Per Month = %.8f from Miner with hashrate = %d" % (bitcoin_mined_per_month, miner_hashrate))

    mining_return = miningReturn(miner_power, miner_hashrate, bits_b, blk_reward)
    print("Mining Return Per Month = %s" % (mining_return))

    cost_of_mining_bitcoin = costOfMiningBitcoin(miner_power, miner_hashrate, bits_b, blk_reward)
    print("Cost of Mining Bitcoin = %.2f" % (cost_of_mining_bitcoin))
