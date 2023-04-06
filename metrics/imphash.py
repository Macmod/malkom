from .metric import Metric
import pefile


class Imphash(Metric):
    def similarity(self, other):
        return 1 if self.value == other.value else 0

    def _extract(self, path):
        pe = pefile.PE(path)
        imphash = pe.get_imphash()
        return imphash
