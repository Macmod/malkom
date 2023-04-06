from metrics.metric import Metric
import tlsh


class TLSH(Metric):
    def similarity(self, other):
        diff_score = tlsh.diff(self.value, other.value)
        if diff_score > 1000:
            diff_score = 1000

        return (1000 - diff_score) / 1000

    def _extract(self, path):
        with open(path, 'rb') as f:
            tlsh_hash = tlsh.hash(f.read())
            if len(tlsh_hash) != 72:
                return None
            return tlsh_hash
