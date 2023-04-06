from metrics.metric import Metric
import ssdeep


class SSDeep(Metric):
    def similarity(self, other):
        return ssdeep.compare(self.value, other.value) / 100.0

    def _extract(self, path):
        ssdeep_hash = ssdeep.hash_from_file(path)
        return ssdeep_hash 
