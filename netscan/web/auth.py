from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

DASHBOARD_PATHS = {"/", "/provision", "/scans", "/settings"}
DASHBOARD_PREFIX = "/subnets/"


class DashboardAuthMiddleware(BaseHTTPMiddleware):
    """Redirect unauthenticated users to /login for all dashboard pages."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        is_dashboard_page = (
            path in DASHBOARD_PATHS
            or path.startswith(DASHBOARD_PREFIX)
            or path == "/web/ips/available"
        )

        if is_dashboard_page and not request.session.get("api_key"):
            return RedirectResponse(url="/login", status_code=303)

        response = await call_next(request)
        return response
