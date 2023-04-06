class Metric():
    def __init__(self, path=None, value=None):
        if path is not None:
            self.value = self._extract(path)
        elif value is not None:
            self.value = value
        else:
            # Throw exception?
            pass

    def similarity(self, a, b):
        return 0

    def _extract(self, path):
        return None
