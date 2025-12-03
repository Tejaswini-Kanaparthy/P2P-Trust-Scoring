import random
import config
from trust import TrustSystem
from peer import Peer
from crypto_channel import CryptoManager
from network import Network
from content import ContentManager
from attack_models import AttackModels
from logger import SimulationLogger
from metrics import Metrics

class Simulation:
    def __init__(self):
        self.ids = list(range(config.NUM_PEERS))
        self.types = self.assign_types()
        self.trust = TrustSystem(self.ids, self.types)
        self.crypto = CryptoManager()
        self.logger = SimulationLogger()
        self.peers = {pid: Peer(pid, self.types[pid], self.trust, self.crypto) for pid in self.ids}
        self.network = Network(self.peers, self.trust)
        self.content = ContentManager()
        self.attacks = AttackModels(self.peers, self.trust, self.content)
        self.network.initialize_random_neighbors()
        self.content.make_pieces(config.CONTENT_PIECES)
        for pid in self.ids[:5]:
            self.peers[pid].cache = {i: self.content.get_piece(i) for i in range(5)}
        self.round_counter = 0

    def assign_types(self):
        t = {}
        total = len(self.ids)
        m = int(total * config.PERCENT_MALICIOUS)
        s = int(total * config.PERCENT_SNOOPER)
        u = int(total * config.PERCENT_UNCOOP)
        arr = ["malicious"] * m + ["snooper"] * s + ["uncoop"] * u
        while len(arr) < total:
            arr.append("honest")
        random.shuffle(arr)
        for i, pid in enumerate(self.ids):
            t[pid] = arr[i]
        return t

    def run_round(self):
        for pid in self.ids:
            p = self.peers[pid]
            if p.isolated():
                p.quarantined = True
                continue
            piece_id = random.choice(self.content.get_all_ids())
            nbr = self.network.pick_neighbor(pid)
            if nbr is None:
                continue
            sender = self.peers[nbr]
            receiver = p
            if not sender.has_piece(piece_id):
                continue
            if sender.refuse():
                self.logger.log_uncoop(f"round {self.round_counter}: peer {sender.id} refused upload for piece {piece_id}")
                continue
            data = sender.send_piece(receiver, piece_id, sender.cache[piece_id])
            ok = receiver.receive_piece(sender, data, piece_id)
            if config.LOG_CONTENT:
                self.logger.log_content(f"round {self.round_counter}: {sender.id}->{receiver.id} piece {piece_id} success={ok}")

        self.inject_adversarial_events()

        for pid in self.ids:
            self.peers[pid].cycle_behavior()

        self.network.loop_cycle()

        if config.LOG_TRUST:
            self.logger.log_trust_snapshot(self.round_counter, self.trust.snapshot())

    def inject_adversarial_events(self):
        if random.random() < 0.08:
            m = self.select_behavior("malicious")
            if m is not None:
                self.attacks.ddos_burst(m)
                self.logger.log_corruption(f"round {self.round_counter}: malicious peer {m} DDoS burst")
        if random.random() < 0.05:
            m = self.select_behavior("malicious")
            if m is not None:
                self.attacks.targeted_poison(m)
                self.logger.log_corruption(f"round {self.round_counter}: malicious peer {m} poisoned a piece")
        if random.random() < 0.07:
            s = self.select_behavior("snooper")
            if s is not None:
                self.attacks.metadata_snoop(s)
                self.logger.log_snoop(f"round {self.round_counter}: snooper peer {s} metadata snooping")
        for pid in self.ids:
            self.attacks.adaptive_probe(pid)

    def select_behavior(self, behavior_type):
        cands = [pid for pid in self.ids if self.types[pid] == behavior_type]
        if not cands:
            return None
        return random.choice(cands)

    def run(self):
        for r in range(config.NUM_ROUNDS):
            self.round_counter = r
            self.run_round()
        self.finalize()

    def finalize(self):
        m = Metrics(self.peers, self.trust, self.logger, self.content)
        m.generate_summary()
        self.logger.export_all("logs")
        for k, v in self.logger.summary.items():
            print(f"{k}: {v}")

if __name__ == "__main__":
    sim = Simulation()
    sim.run()
