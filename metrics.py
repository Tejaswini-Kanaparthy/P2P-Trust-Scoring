class Metrics:
    def __init__(self, peers, trust, logger, content):
        self.peers = peers
        self.trust = trust
        self.logger = logger
        self.content = content

    def final_trust_distribution(self):
        dist = {}
        for pid, score in self.trust.scores.items():
            dist[pid] = score
        return dist

    def count_isolated(self):
        return sum(1 for x in self.trust.isolated.values() if x)

    def avg_trust(self):
        vals = list(self.trust.scores.values())
        return sum(vals) / len(vals)

    def count_by_type(self):
        out = {"honest": 0, "malicious": 0, "snooper": 0, "uncoop": 0}
        for p in self.peers.values():
            if p.type in out:
                out[p.type] += 1
        return out

    def count_corruptions(self):
        return len(self.logger.corruption_log)

    def count_crypto_fails(self):
        return len(self.logger.crypto_log)

    def count_bad_hmac(self):
        return len(self.logger.hmac_fail_log)

    def count_bad_padding(self):
        return len(self.logger.padding_fail_log)

    def count_snoop_events(self):
        return len(self.logger.snoop_log)

    def count_uncoop_events(self):
        return len(self.logger.uncoop_log)

    def generate_summary(self):
        self.logger.add_summary("avg_trust", round(self.avg_trust(), 3))
        self.logger.add_summary("isolated_peers", self.count_isolated())
        self.logger.add_summary("corruption_events", self.count_corruptions())
        self.logger.add_summary("crypto_fail_events", self.count_crypto_fails())
        self.logger.add_summary("bad_hmac_events", self.count_bad_hmac())
        self.logger.add_summary("bad_padding_events", self.count_bad_padding())
        self.logger.add_summary("snoop_events", self.count_snoop_events())
        self.logger.add_summary("uncoop_events", self.count_uncoop_events())
        t = self.count_by_type()
        for k, v in t.items():
            self.logger.add_summary(f"type_{k}", v)
