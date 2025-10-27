import dataclasses


@dataclasses.dataclass(slots=True, kw_only=True)
class TokenRefreshResult:
    should_remove_response_cookies: bool


@dataclasses.dataclass(slots=True, kw_only=True)
class StateDTO:
    next_url: str
