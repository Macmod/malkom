from metrics.metric import Metric
from utils.utils import contenthash, get_overlay_offset


class Overhash(Metric):
    def similarity(self, other):
        return 1 if self.value == other.value else 0

    def _extract(self, path):
        offset = get_overlay_offset(path)
        if offset is None:
            return None

        with open(path, 'rb') as f:
            r = f.read()
            return contenthash(r[offset:])
