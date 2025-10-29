import dataclasses


@dataclasses.dataclass(slots=True, kw_only=True)
class StateDTO:
    next_url: str
    csrf_token: str
