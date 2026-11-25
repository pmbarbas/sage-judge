class AdjudicationError(ValueError):
    """Explicit failed computation; never reinterpret as UNKNOWN evidence."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
