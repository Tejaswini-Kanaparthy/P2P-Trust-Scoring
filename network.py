import random
import config

class Network:
    def __init__(self, peers, trust):
        self.peers = peers
        self.trust = trust

    def initialize_random_neighbors(self):
        ids = list(self.peers.keys())
        for pid, p in self.peers.items():
            other = [x for x in ids if x != pid]
            random.shuffle(other)
            k = random.randint(config.MIN_NEIGHBORS, config.MAX_NEIGHBORS)
            p.neighbors = set(other[:k])

    def pick_neighbor(self, pid):
        p = self.peers[pid]
        if not p.neighbors:
            return None
        valid = [n for n in p.neighbors if not self.trust.isolated_state(n)]
        if not valid:
            return None
        random.shuffle(valid)
        return valid[0]

    def rewire_isolated(self):
        for pid, p in self.peers.items():
            if self.trust.isolated_state(pid):
                p.neighbors.clear()
                continue
            bad = [x for x in p.neighbors if self.trust.isolated_state(x)]
            for x in bad:
                p.drop_neighbor(x)
            if len(p.neighbors) < config.MIN_NEIGHBORS:
                self.reconnect(pid)

    def reconnect(self, pid):
        p = self.peers[pid]
        if self.trust.isolated_state(pid):
            return
        ids = list(self.peers.keys())
        random.shuffle(ids)
        for cand in ids:
            if cand != pid and cand not in p.neighbors:
                if not self.trust.isolated_state(cand):
                    p.add_neighbor(cand)
                if len(p.neighbors) >= config.MIN_NEIGHBORS:
                    break

    def dynamic_churn(self):
        for pid, p in self.peers.items():
            if random.random() < 0.05:
                if p.neighbors:
                    lst = list(p.neighbors)
                    random.shuffle(lst)
                    p.drop_neighbor(lst[0])
            if len(p.neighbors) < config.MIN_NEIGHBORS:
                self.reconnect(pid)

    def loop_cycle(self):
        self.rewire_isolated()
        self.dynamic_churn()

    def __repr__(self):
        return f"Network(peers={len(self.peers)})"
