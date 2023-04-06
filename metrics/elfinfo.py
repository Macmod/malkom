from metrics.metric import Metric
from elftools.elf.elffile import ELFFile
from utils.utils import elf_get_symbols, jaccard


class ELFSymbols(Metric):
    def similarity(self, other):
        sim_metric = jaccard(self.value, other.value)
        if sim_metric is None:
            return 0
        return sim_metric

    def _extract(self, path):
        symbols = []

        with open(path, 'rb') as f:
            elf_obj = ELFFile(f)
            symbols_iter = elf_get_symbols(elf_obj)

            for sym in symbols_iter:
                sym_type = sym.entry.st_info.type
                sym_name = sym.name.lower()
                if sym_type in ('STT_FILE', 'STT_FUNC', 'STT_OBJECT'):
                    symbols.append(sym_name)

            return symbols
