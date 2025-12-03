import random
import config

class AttackModels:
    def __init__(self, peers, trust, content):
        self.peers = peers
        self.trust = trust
        self.content = content

    def ddos_burst(self, malicious_id):
        p = self.peers[malicious_id]
        if not p.is_malicious():
            return
        targets = list(p.neighbors)
        random.shuffle(targets)
        for t in targets[:3]:
            self.trust.corrupt(malicious_id)

    def targeted_poison(self, malicious_id):
        p = self.peers[malicious_id]
        if not p.is_malicious():
            return
        pid = random.choice(self.content.get_all_ids())
        self.content.poison_piece(pid)
        self.trust.corrupt(malicious_id)

    def metadata_snoop(self, snooper_id):
        p = self.peers[snooper_id]
        if not p.is_snooper():
            return
        if random.random() < 0.6:
            self.trust.snoop(snooper_id)

    def adaptive_probe(self, pid):
        if random.random() < 0.15:
            self.trust.accident(pid)
