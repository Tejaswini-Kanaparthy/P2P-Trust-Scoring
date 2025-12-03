from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import config
import random

class CryptoChannel:
    def __init__(self, peer_a, peer_b):
        self.peer_a = peer_a
        self.peer_b = peer_b
        self.key = get_random_bytes(32)
        self.hmac_key = get_random_bytes(32)
        self.rounds_since_rotation = 0

    def pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len]) * pad_len

    def unpad(self, data):
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Bad padding")
        return data[:-pad_len]

    def maybe_fail(self):
        return random.random() < config.CRYPTO_FAIL_PROB

    def rotate_keys(self):
        self.key = get_random_bytes(32)
        self.hmac_key = get_random_bytes(32)
        self.rounds_since_rotation = 0

    def encrypt(self, plaintext, sender_id, receiver_id):
        if self.maybe_fail():
            return None, None, None
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        padded = self.pad(plaintext)
        ciphertext = cipher.encrypt(padded)
        h = HMAC.new(self.hmac_key, ciphertext, digestmod=SHA256)
        tag = h.digest()
        return iv, ciphertext, tag

    def decrypt(self, iv, ciphertext, tag, receiver_id):
        if iv is None or ciphertext is None or tag is None:
            raise ValueError("crypto-failure")
        h = HMAC.new(self.hmac_key, ciphertext, digestmod=SHA256)
        try:
            h.verify(tag)
        except:
            raise ValueError("bad-hmac")
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        try:
            padded = cipher.decrypt(ciphertext)
        except:
            raise ValueError("decrypt-error")
        try:
            plaintext = self.unpad(padded)
        except:
            raise ValueError("bad-padding")
        return plaintext

class CryptoManager:
    def __init__(self):
        self.channels = {}

    def get_channel(self, a, b):
        key = tuple(sorted((a, b)))
        if key not in self.channels:
            self.channels[key] = CryptoChannel(a, b)
        return self.channels[key]

    def encrypt_for(self, sender, receiver, plaintext):
        ch = self.get_channel(sender, receiver)
        ch.rounds_since_rotation += 1
        if ch.rounds_since_rotation >= config.CRYPTO_KEY_ROTATION_INTERVAL:
            ch.rotate_keys()
        return ch.encrypt(plaintext, sender, receiver)

    def decrypt_from(self, sender, receiver, iv, ciphertext, tag):
        ch = self.get_channel(sender, receiver)
        return ch.decrypt(iv, ciphertext, tag, receiver)
