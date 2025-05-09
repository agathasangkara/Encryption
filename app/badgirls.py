import json
import time
import hashlib
import binascii
from Crypto.Cipher import AES

class AESUtility:
    def __init__(self, passphrase: str = "appWorldKey"):
        self.key = self._derive_key(passphrase)

    def _derive_key(self, passphrase: str) -> bytes:
        return hashlib.md5(passphrase.encode()).digest()

    def _pad(self, data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - len(data) % block_size
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt(self, plaintext) -> str:
        if isinstance(plaintext, dict):
            plaintext = json.dumps(plaintext, separators=(',', ':'))
        elif not isinstance(plaintext, str):
            raise TypeError("Input must be a str or dict")

        cipher = AES.new(self.key, AES.MODE_ECB)
        padded = self._pad(plaintext.encode())
        encrypted = cipher.encrypt(padded)
        return binascii.hexlify(encrypted).decode()

    def decrypt(self, cipher_hex: str) -> str:
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = binascii.unhexlify(cipher_hex)
        decrypted = cipher.decrypt(encrypted)
        return self._unpad(decrypted).decode(errors='ignore')

    @staticmethod
    def generate_timestamp() -> int:
        return int(time.time() * 1000)


LINK APP : https://app-earnings-link.com/badGirls/gezuy57ho1bpnov5t
BUILD WITH YOUR OWN !!!
