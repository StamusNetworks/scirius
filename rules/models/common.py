class DuplicateSidException(Exception):
    def __init__(self, msg: str, same_source: bool = False) -> None:
        super().__init__(msg)
        self.same_source = same_source
