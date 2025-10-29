import base64
import hmac
import json
from collections.abc import Sequence
from http import HTTPStatus
from typing import Any

from jwcrypto.common import JWException
from jwcrypto.jwt import JWTExpired
from keycloak import KeycloakOpenID
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route
from starlette_admin import BaseAdmin
from starlette_admin.auth import AdminUser, AuthProvider, login_not_required

from starlette_admin_keycloak._dto import StateDTO
from starlette_admin_keycloak.cookies import CookieNames
from starlette_admin_keycloak.middleware import KeycloakAuthMiddleware
from starlette_admin_keycloak.routes import Routes


class KeycloakAuthProvider(AuthProvider):
    def __init__(
        self,
        *,
        login_path: str = "/login",
        logout_path: str = "/logout",
        allow_routes: Sequence[str] | None = None,
        keycloak_openid: KeycloakOpenID,
    ) -> None:
        super().__init__(
            login_path=login_path, logout_path=logout_path, allow_routes=allow_routes
        )
        self._keycloak_openid = keycloak_openid

    def setup_admin(self, admin: BaseAdmin) -> None:
        super().setup_admin(admin)
        admin.routes.extend(
            [
                Route(
                    path=Routes.oauth_callback.path,
                    name=Routes.oauth_callback.name,
                    methods=["GET"],
                    endpoint=self._route_auth_callback,
                )
            ]
        )

    @login_not_required
    async def _route_auth_callback(self, request: Request) -> Response:
        code = request.query_params.get("code")
        state_raw = request.query_params.get("state", None)
        csrf_token = request.cookies.pop(CookieNames.csrf, None)
        if code is None or state_raw is None or csrf_token is None:
            response = Response(status_code=HTTPStatus.BAD_REQUEST)
            response.delete_cookie(CookieNames.csrf)
            return response

        state = StateDTO(**json.loads(base64.b64decode(state_raw)))
        if not hmac.compare_digest(state.csrf_token, csrf_token):
            response = Response(status_code=HTTPStatus.BAD_REQUEST)
            response.delete_cookie(CookieNames.csrf)
            return response

        tokens = await self._keycloak_openid.a_token(
            code=code,
            grant_type="authorization_code",
            redirect_uri=str(request.url_for(f"admin:{Routes.oauth_callback.name}")),
        )
        access = tokens["access_token"]
        refresh = tokens["refresh_token"]
        response = RedirectResponse(state.next_url)
        response.set_cookie(
            key=CookieNames.access, value=access, httponly=True, secure=True
        )
        response.set_cookie(
            key=CookieNames.refresh, value=refresh, httponly=True, secure=True
        )
        response.delete_cookie(CookieNames.csrf)
        return response

    def get_middleware(self, admin: "BaseAdmin") -> Middleware:  # noqa: ARG002
        return Middleware(
            KeycloakAuthMiddleware, provider=self, keycloak_openid=self._keycloak_openid
        )

    async def maybe_refresh_tokens(self, request: Request) -> None:
        access_token = request.cookies.get(CookieNames.access)
        if not access_token:
            return

        try:
            await self._keycloak_openid.a_decode_token(token=access_token)
        except JWTExpired:
            refresh_token = request.cookies[CookieNames.refresh]
            try:
                await self._keycloak_openid.a_decode_token(refresh_token)
            except JWException:
                request.cookies.pop(CookieNames.access, None)
                request.cookies.pop(CookieNames.refresh, None)
                return

            response = await self._keycloak_openid.a_refresh_token(
                refresh_token=request.cookies[CookieNames.refresh]
            )
            request.cookies[CookieNames.access] = response["access_token"]
            request.cookies[CookieNames.refresh] = response["refresh_token"]
        except JWException:
            request.cookies.pop(CookieNames.access, None)
            request.cookies.pop(CookieNames.refresh, None)

    async def is_authenticated(self, request: Request) -> bool:
        try:
            token = await self._token_from_request(request)
            if token is None:
                return False
        except (ValueError, JWException):
            return False
        return True

    def get_admin_user(self, request: Request) -> AdminUser | None:
        token = request.state.access_token
        if token is None:
            return None
        return AdminUser(username=token.get("preferred_username", "Administrator"))

    async def logout(self, request: Request, response: Response) -> Response:  # noqa: ARG002
        response.delete_cookie(key=CookieNames.access)
        response.delete_cookie(key=CookieNames.refresh)
        return response

    async def get_access_token(self, request: Request) -> dict[str, Any] | None:
        try:
            return await self._token_from_request(request)
        except (ValueError, JWException):
            return None

    async def _token_from_request(self, request: Request) -> dict[str, Any] | None:
        access_token = request.cookies.get(CookieNames.access)
        if not access_token:
            return None
        return await self._keycloak_openid.a_decode_token(token=access_token)
