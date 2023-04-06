from metrics.metric import Metric
from utils.utils import pe_get_imports, pe_get_exports, jaccard
from pefile import PE


class PEImports(Metric):
    def __init__(self, path=None, value=None):
        if path is None and value is not None and type(value) == list:
            value = list(map(tuple, value))
            super().__init__(path=path, value=value)

    def similarity(self, other):
        sim_metric = jaccard(self.value, other.value)
        if sim_metric is None:
            return 0
        return sim_metric

    def _extract(self, path):
        imports = pe_get_imports(PE(path))
        imports_set = [
            (lib, symbol) for lib, symbols in imports for symbol in symbols
        ]

        return imports_set


class PEExports(Metric):
    def similarity(self, other):
        sim_metric = jaccard(self.value, other.value)
        if sim_metric is None:
            return 0
        return sim_metric

    def _extract(self, path):
        exports_set = pe_get_exports(PE(path))
        return exports_set
