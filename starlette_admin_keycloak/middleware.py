from __future__ import annotations

import base64
import dataclasses
import json
from http import HTTPStatus
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import RedirectResponse, Response
from starlette.routing import Match, Mount, Route, WebSocketRoute

from starlette_admin_keycloak._dto import StateDTO
from starlette_admin_keycloak.cookies import CookieNames
from starlette_admin_keycloak.routes import Routes

if TYPE_CHECKING:
    from keycloak import KeycloakOpenID
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.types import ASGIApp

    from starlette_admin_keycloak.providers import KeycloakAuthProvider


class KeycloakAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        provider: KeycloakAuthProvider,
        keycloak_openid: KeycloakOpenID,
    ) -> None:
        super().__init__(app=app)
        self._app = app
        self._provider = provider
        self._keycloak_openid = keycloak_openid
        self.allow_paths = ()
        self.allow_routes = ()

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        _admin_app: Starlette = request.scope["app"]
        current_route: Route | Mount | WebSocketRoute | None = None

        for route in _admin_app.routes:
            match, _ = route.matches(request.scope)
            if match == Match.FULL:
                assert isinstance(route, (Route, Mount, WebSocketRoute))  # noqa: S101
                current_route = route
                break

        token_refresh_result = await self._provider.maybe_refresh_tokens(request)

        if (
            (current_route is not None and current_route.path in self.allow_paths)
            or (current_route is not None and current_route.name in self.allow_routes)
            or (
                current_route is not None
                and hasattr(current_route, "endpoint")
                and getattr(current_route.endpoint, "_login_not_required", False)
            )
            or await self._provider.is_authenticated(request)
        ):
            request.state.access_token = await self._provider.get_access_token(request)
            response = await call_next(request)
            if token_refresh_result.should_remove_response_cookies:
                response.delete_cookie(CookieNames.access)
                response.delete_cookie(CookieNames.refresh)
            return response

        redirect_url = request.url_for(f"admin:{Routes.oauth_callback.name}")
        state = StateDTO(next_url=str(request.url))
        auth_url = self._keycloak_openid.auth_url(
            redirect_uri=str(redirect_url),
            state=base64.b64encode(
                json.dumps(dataclasses.asdict(state)).encode()
            ).decode(),
        )
        return RedirectResponse(
            auth_url,
            status_code=HTTPStatus.SEE_OTHER,
        )
