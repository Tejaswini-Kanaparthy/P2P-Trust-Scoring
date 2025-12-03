import random
import config

class Peer:
    def __init__(self, pid, ptype, trust_ref, crypto_ref):
        self.id = pid
        self.type = ptype
        self.trust = trust_ref
        self.crypto = crypto_ref
        self.neighbors = set()
        self.cache = {}
        self.quarantined = False

    def is_honest(self):
        return self.type == "honest"

    def is_malicious(self):
        return self.type == "malicious"

    def is_snooper(self):
        return self.type == "snooper"

    def is_uncooperative(self):
        return self.type == "uncoop"

    def isolated(self):
        return self.trust.isolated_state(self.id)

    def refuse(self):
        if self.is_uncooperative() and random.random() < config.REFUSE_PROB:
            self.trust.uncoop(self.id)
            return True
        return False

    def snoop_cipher(self, ciphertext):
        if not self.is_snooper():
            return False
        if random.random() < config.SNOOP_PROB:
            self.trust.snoop(self.id)
            return True
        return False

    def corrupt_cipher(self, ciphertext):
        if not self.is_malicious():
            return ciphertext
        if random.random() < config.CORRUPTION_PROB:
            self.trust.corrupt(self.id)
            if len(ciphertext) > 0:
                idx = random.randint(0, len(ciphertext)-1)
                b = ciphertext[idx] ^ 0xFF
                return ciphertext[:idx] + bytes([b]) + ciphertext[idx+1:]
        return ciphertext

    def accidental_corruption(self, ciphertext):
        if random.random() < config.ACCIDENT_PROB:
            self.trust.accident(self.id)
            if len(ciphertext) > 0:
                idx = random.randint(0, len(ciphertext)-1)
                b = ciphertext[idx] ^ 0x0F
                return ciphertext[:idx] + bytes([b]) + ciphertext[idx+1:]
        return ciphertext

    def encrypt_piece(self, receiver_id, plaintext):
        iv, ciphertext, tag = self.crypto.encrypt_for(self.id, receiver_id, plaintext)
        if iv is None or ciphertext is None or tag is None:
            self.trust.crypto_fail(self.id)
            return None, None, None
        ciphertext = self.corrupt_cipher(ciphertext)
        ciphertext = self.accidental_corruption(ciphertext)
        return iv, ciphertext, tag

    def decrypt_piece(self, sender_id, iv, ciphertext, tag):
        if self.snoop_cipher(ciphertext):
            pass
        try:
            plaintext = self.crypto.decrypt_from(sender_id, self.id, iv, ciphertext, tag)
            self.trust.reward(self.id)
            return plaintext, True
        except ValueError as e:
            msg = str(e)
            if "bad-hmac" in msg:
                self.trust.bad_hmac(self.id)
            elif "bad-padding" in msg:
                self.trust.bad_padding(self.id)
            else:
                self.trust.crypto_fail(self.id)
            return None, False

    def add_neighbor(self, pid):
        if pid != self.id:
            self.neighbors.add(pid)

    def drop_neighbor(self, pid):
        if pid in self.neighbors:
            self.neighbors.remove(pid)

    def can_send(self):
        if self.isolated():
            return False
        if self.quarantined:
            return False
        if self.is_uncooperative() and random.random() < config.REFUSE_PROB:
            self.trust.uncoop(self.id)
            return False
        return True

    def send_piece(self, receiver, piece_id, plaintext):
        if not self.can_send():
            return None
        iv, ciphertext, tag = self.encrypt_piece(receiver.id, plaintext)
        if iv is None:
            return None
        return (iv, ciphertext, tag)

    def receive_piece(self, sender, data, piece_id):
        if data is None:
            return False
        iv, ciphertext, tag = data
        plaintext, ok = self.decrypt_piece(sender.id, iv, ciphertext, tag)
        if ok:
            self.cache[piece_id] = plaintext
        return ok

    def has_piece(self, piece_id):
        return piece_id in self.cache

    def request_piece(self, sender, piece_id):
        if piece_id not in sender.cache:
            return False
        if not sender.can_send():
            return False
        data = sender.send_piece(self, piece_id, sender.cache[piece_id])
        return self.receive_piece(sender, data, piece_id)

    def cycle_behavior(self):
        if self.isolated():
            self.quarantined = True
        else:
            self.quarantined = False

    def __repr__(self):
        return f"Peer({self.id}, {self.type}, trust={self.trust.get(self.id):.2f})"
