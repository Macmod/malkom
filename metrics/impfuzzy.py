from metrics.metric import Metric
import pyimpfuzzy


class Impfuzzy(Metric):
    def similarity(self, other):
        return pyimpfuzzy.hash_compare(self.value, other.value)

    def _extract(self, path):
        with open(path, 'rb') as f:
            pyimpfuzzy_hash = pyimpfuzzy.get_impfuzzy_data(f.read())
            return pyimpfuzzy_hash
