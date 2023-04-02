import os
import hashlib
from ecdsa import SigningKey, SECP256k1
from base58 import b58encode_check

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

def load_btc_addresses(file_path):
    with open(file_path, 'r') as f:
        return set(line.strip() for line in f.readlines())

def check_and_save_match(address, private_key, addresses):
    if address in addresses:
        with open("Found.txt", "a") as f:
            f.write(f"Address: {address}, Private key: {private_key.hex()}\n")

def main():
    btc_addresses = load_btc_addresses("btcaddress.txt")

    while True:
        private_key = generate_private_key()
        public_key_compressed = get_public_key(private_key, compressed=True)
        public_key_uncompressed = get_public_key(private_key, compressed=False)
        address_compressed = generate_bitcoin_address(public_key_compressed).decode('utf-8')
        address_uncompressed = generate_bitcoin_address(public_key_uncompressed).decode('utf-8')

        check_and_save_match(address_compressed, private_key, btc_addresses)
        check_and_save_match(address_uncompressed, private_key, btc_addresses)

        print(f"Checked: Compressed address: {address_compressed}")
        print(f"Checked: Uncompressed address: {address_uncompressed}")
        print(f"Private key: {private_key.hex()}")
        print()

if __name__ == "__main__":
    main()
