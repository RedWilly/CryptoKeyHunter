# CryptoKeyHunter
CryptoKeyHunter is a Python script that generates an unlimited number of Bitcoin addresses and keys, checks them against a list of target addresses, and saves the matched addresses along with their private keys.

## Requirements

- Python 3.6 or higher
- ecdsa (`pip install ecdsa`)
- base58 (`pip install base58`)
- Bloom filters (`pip install pybloom_live`) - HuntBL

## Usage

1. Prepare a text file named `btcaddress.txt` containing the target Bitcoin addresses, with one address per line.
2. Run the script using `python Hunt.py`.

The script will generate an unlimited number of Bitcoin addresses and keys, both compressed and uncompressed, and check if they match any of the addresses in `btcaddress.txt`. If a match is found, the script will save the matched address and its corresponding private key in a file named `Found.txt`.

## Disclaimer

This script is provided for educational purposes only. The use of this script for malicious purposes or activities that violate ethical guidelines is strictly prohibited. The user is solely responsible for any consequences resulting from the use of this script.


