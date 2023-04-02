import os
import hashlib
import concurrent.futures
from ecdsa import SigningKey, SECP256k1
from base58 import b58encode_check
from pybloom_live import BloomFilter
import time



def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    return hashlib.new("ripemd160", data).digest()

def generate_private_key():
    return os.urandom(32)

def get_public_key(private_key, compressed=True):
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    vk = sk.verifying_key
    x, y = vk.pubkey.point.x(), vk.pubkey.point.y()
    if compressed:
        return (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')
    else:
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def generate_bitcoin_address(public_key):
    extended_key = b'\x00' + ripemd160(sha256(public_key))
    return b58encode_check(extended_key)

def check_and_save_match(address, private_key, addresses):
    if address in addresses:
        with open("Found.txt", "a") as f:
            f.write(f"Address: {address}, Private key: {private_key.hex()}\n")
        print(f"Found matching address: {address}")



def load_btc_addresses(file_path):
    with open(file_path, 'r') as f:
        addresses = [line.strip() for line in f.readlines()]
    bloom = BloomFilter(len(addresses))
    for address in addresses:
        bloom.add(address)
    print(f"Loaded {len(addresses)} addresses into the bloom filter.")
    return bloom, addresses

address_count = 0

def process_key_pair(btc_bloom_filter, btc_addresses):
    global address_count
    private_key = generate_private_key()
    public_key_compressed = get_public_key(private_key, compressed=True)
    public_key_uncompressed = get_public_key(private_key, compressed=False)
    address_compressed = generate_bitcoin_address(public_key_compressed).decode('utf-8')
    address_uncompressed = generate_bitcoin_address(public_key_uncompressed).decode('utf-8')

    #print(f"Compressed Address: {address_compressed}, Private key: {private_key.hex()}")
    #print(f"Uncompressed Address: {address_uncompressed}, Private key: {private_key.hex()}")

    if address_compressed in btc_bloom_filter:
        check_and_save_match(address_compressed, private_key, btc_addresses)
    if address_uncompressed in btc_bloom_filter:
        check_and_save_match(address_uncompressed, private_key, btc_addresses)

    address_count += 2
    if address_count % 1000 == 0:
        print(f"Generated {address_count} addresses.")


def main():
    btc_bloom_filter, btc_addresses = load_btc_addresses("btcaddress.txt")

    while True:
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            while time.time() - start_time < 10 * 60 * 60:  # Run for 10 hours
                futures = [executor.submit(process_key_pair, btc_bloom_filter, btc_addresses) for _ in range(10)]
                concurrent.futures.wait(futures)
        print("Resting for 2 hours.")
        time.sleep(2 * 60 * 60)  # Rest for 2 hours

if __name__ == "__main__":
    main()
