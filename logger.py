import csv
import os
import datetime

class SimulationLogger:
    def __init__(self):
        self.trust_log = []
        self.crypto_log = []
        self.event_log = []
        self.content_log = []
        self.neighbor_log = []
        self.corruption_log = []
        self.hmac_fail_log = []
        self.padding_fail_log = []
        self.accident_log = []
        self.uncoop_log = []
        self.snoop_log = []
        self.summary = {}

    def log_trust_snapshot(self, round_idx, trust_map):
        row = {"round": round_idx}
        for p, v in trust_map.items():
            row[f"peer_{p}"] = v
        self.trust_log.append(row)

    def log_event(self, msg):
        self.event_log.append(msg)

    def log_crypto(self, msg):
        self.crypto_log.append(msg)

    def log_corruption(self, msg):
        self.corruption_log.append(msg)

    def log_hmac_fail(self, msg):
        self.hmac_fail_log.append(msg)

    def log_padding_fail(self, msg):
        self.padding_fail_log.append(msg)

    def log_accident(self, msg):
        self.accident_log.append(msg)

    def log_uncoop(self, msg):
        self.uncoop_log.append(msg)

    def log_snoop(self, msg):
        self.snoop_log.append(msg)

    def log_neighbor(self, msg):
        self.neighbor_log.append(msg)

    def log_content(self, msg):
        self.content_log.append(msg)

    def write_csv(self, path, rows):
        if not rows:
            return
        keys = rows[0].keys()
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def export_all(self, out_dir="logs"):
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        self.write_csv(os.path.join(out_dir, "trust_evolution.csv"), self.trust_log)
        self.write_list(os.path.join(out_dir, "crypto_log.txt"), self.crypto_log)
        self.write_list(os.path.join(out_dir, "event_log.txt"), self.event_log)
        self.write_list(os.path.join(out_dir, "neighbor_log.txt"), self.neighbor_log)
        self.write_list(os.path.join(out_dir, "content_log.txt"), self.content_log)
        self.write_list(os.path.join(out_dir, "corruption_log.txt"), self.corruption_log)
        self.write_list(os.path.join(out_dir, "hmac_fail_log.txt"), self.hmac_fail_log)
        self.write_list(os.path.join(out_dir, "padding_fail_log.txt"), self.padding_fail_log)
        self.write_list(os.path.join(out_dir, "accident_log.txt"), self.accident_log)
        self.write_list(os.path.join(out_dir, "uncoop_log.txt"), self.uncoop_log)
        self.write_list(os.path.join(out_dir, "snoop_log.txt"), self.snoop_log)

        self.write_summary(os.path.join(out_dir, "summary.txt"))

    def write_list(self, filename, data):
        with open(filename, "w") as f:
            for item in data:
                f.write(str(item) + "\n")

    def add_summary(self, key, value):
        self.summary[key] = value

    def write_summary(self, filename):
        with open(filename, "w") as f:
            ts = datetime.datetime.now().isoformat()
            f.write(f"Simulation Summary ({ts})\n\n")
            for k, v in self.summary.items():
                f.write(f"{k}: {v}\n")
