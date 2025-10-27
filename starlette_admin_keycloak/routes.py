import dataclasses


@dataclasses.dataclass(slots=True, kw_only=True)
class RouteInfo:
    path: str
    name: str


class Routes:
    openid_callback = RouteInfo(
        path="/auth/openid-callback",
        name="starlette-admin-keycloak:callback",
    )
