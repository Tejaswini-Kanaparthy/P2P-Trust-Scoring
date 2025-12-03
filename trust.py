import config

class TrustSystem:
    def __init__(self, peer_ids, types):
        self.scores = {pid: config.TRUST_INITIAL for pid in peer_ids}
        self.types = types
        self.isolated = {pid: False for pid in peer_ids}

    def clamp(self, v):
        if v < config.TRUST_MIN:
            return config.TRUST_MIN
        if v > config.TRUST_MAX:
            return config.TRUST_MAX
        return v

    def reward(self, pid):
        if self.isolated[pid]:
            return
        v = self.scores[pid] + config.TRUST_REWARD
        self.scores[pid] = self.clamp(v)
        self.check_isolation(pid)

    def penalize(self, pid, amt):
        if self.isolated[pid]:
            return
        v = self.scores[pid] - amt
        self.scores[pid] = self.clamp(v)
        self.check_isolation(pid)

    def bad_hmac(self, pid):
        if self.isolated[pid]:
            return
        self.penalize(pid, config.TRUST_PENALTY_BAD_HMAC)

    def bad_padding(self, pid):
        if self.isolated[pid]:
            return
        self.penalize(pid, config.TRUST_PENALTY_BAD_PADDING)

    def crypto_fail(self, pid):
        if self.isolated[pid]:
            return
        self.penalize(pid, config.TRUST_PENALTY_CRYPTO_FAIL)

    def corrupt(self, pid):
        if self.isolated[pid]:
            return
        self.penalize(pid, config.TRUST_PENALTY_CORRUPT)

    def snoop(self, pid):
        if self.isolated[pid]:
            return
        self.penalize(pid, config.TRUST_PENALTY_SNOOP)

    def uncoop(self, pid):
        if self.isolated[pid]:
            return
        self.penalize(pid, config.TRUST_PENALTY_UNCOOP)

    def accident(self, pid):
        if self.isolated[pid]:
            return
        self.penalize(pid, config.TRUST_PENALTY_ACCIDENT)

    def check_isolation(self, pid):
        if self.scores[pid] <= config.ISOLATION_THRESHOLD:
            self.isolated[pid] = True
        else:
            self.isolated[pid] = False

    def get(self, pid):
        return self.scores[pid]

    def isolated_state(self, pid):
        return self.isolated[pid]

    def snapshot(self):
        return dict(self.scores)
