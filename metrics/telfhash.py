from metrics.metric import Metric
from telfhash import telfhash
import tlsh


class Telfhash(Metric):
    def similarity(self, other):
        diff_score = tlsh.diff(self.value, other.value)
        if diff_score > 1000:
            diff_score = 1000

        return (1000 - diff_score) / 1000

    def _extract(self, path):
        telfhash_list = telfhash(path)
        if len(telfhash_list) < 1:
            return None

        telfhash_hash = telfhash_list[0]['telfhash'].upper()

        if len(telfhash_hash) != 72:
            return None

        return telfhash_hash
