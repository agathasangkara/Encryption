import json
import hashlib
from uuid import uuid4
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Utility:
    AES_KEY = bytes.fromhex("e7743aeb495e7918f9af6ffd515e9xx") # guess the last 3 numbers

    @staticmethod
    def aes_encrypt(data: dict) -> str:
        plaintext = json.dumps(data, separators=(",", ":")).encode()
        cipher = AES.new((Utility()).AES_KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(plaintext, 16))
        return encrypted.hex()

    @staticmethod
    def aes_decrypt(cipher_hex: str) -> dict:
        cipher = AES.new((Utility()).AES_KEY, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(bytes.fromhex(cipher_hex)), 16)
        return json.loads(decrypted.decode())

    @staticmethod
    def generate_device_id() -> str:
        raw = str(uuid4()).encode()
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def generate_adid() -> str:
        raw = str(uuid4()).replace("-", "")[:16].encode()
        return hashlib.md5(raw).hexdigest()

# LINK : https://play.google.com/store/apps/details?id=com.bom.temanlive
# BUILD WITH YOUR OWN
# SS : https://github.com/user-attachments/assets/c0236886-2775-4ec6-a44f-bcb29e0e2843

# EXAMPLE
if __name__ == "__main__":
    crypto = Utility()

    device_id = crypto.generate_device_id()
    ad_id = crypto.generate_adid()

    payload = {"example": "data", "device": device_id, "adid": ad_id}
    encrypted = crypto.aes_encrypt(payload)
    decrypted = crypto.aes_decrypt(encrypted)

    print(f"Device ID: {device_id}")
    print(f"Ad ID: {ad_id}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
