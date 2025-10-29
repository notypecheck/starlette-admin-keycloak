import dataclasses


@dataclasses.dataclass(slots=True, kw_only=True)
class RouteInfo:
    path: str
    name: str


class Routes:
    oauth_callback = RouteInfo(
        path="/auth/oauth-callback",
        name="starlette-admin-keycloak:callback",
    )
