import os
import random

class ContentManager:
    def __init__(self):
        self.all_pieces = {}
        self.checksums = {}

    def make_pieces(self, num):
        for i in range(num):
            data = os.urandom(64)
            self.all_pieces[i] = data
            self.checksums[i] = sum(data) % 256

    def poison_piece(self, pid):
        if pid not in self.all_pieces:
            return
        data = bytearray(self.all_pieces[pid])
        if len(data) > 0:
            idx = random.randint(0, len(data)-1)
            data[idx] ^= 0xAA
        self.all_pieces[pid] = bytes(data)
        self.checksums[pid] = sum(data) % 256

    def verify(self, pid, data):
        if pid not in self.checksums:
            return False
        return (sum(data) % 256) == self.checksums[pid]

    def get_piece(self, pid):
        return self.all_pieces[pid]

    def get_all_ids(self):
        return list(self.all_pieces.keys())
