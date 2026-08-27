import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlmodel import Session, select
from netscan.api.auth import hash_key
from netscan.config import settings
from netscan.db import get_session
from netscan.models import ApiKey, IPAddress, IPHistory, IPStatus, ScanJob, Subnet, Webhook
from netscan.scanner.cidr import expand_cidr_hosts, get_subnet_metadata

templates_path = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))

web_router = APIRouter(include_in_schema=False)


def _get_api_key(request: Request) -> str:
    """Extract the API key from the dashboard session."""
    return request.session.get("api_key", "")


def _generate_csrf_token(request: Request) -> str:
    """Generate a signed CSRF token bound to the current session."""
    secret = settings.SECRET_KEY or "test-csrf-fallback"
    salt = f"csrf-login-{request.session.get('_sid', '')}"
    return URLSafeTimedSerializer(secret).dumps("csrf", salt=salt)


def _validate_csrf_token(request: Request, token: str) -> bool:
    """Validate a CSRF token. Returns False if missing, expired, or invalid."""
    if not token:
        return False
    secret = settings.SECRET_KEY or "test-csrf-fallback"
    salt = f"csrf-login-{request.session.get('_sid', '')}"
    try:
        URLSafeTimedSerializer(secret).loads(token, salt=salt, max_age=1800)
        return True
    except (BadSignature, SignatureExpired):
        return False


# ---------------------------------------------------------------------------
# Authentication routes (no session required)
# ---------------------------------------------------------------------------

@web_router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("api_key"):
        return RedirectResponse(url="/", status_code=303)
    csrf_token = _generate_csrf_token(request)
    return templates.TemplateResponse(request=request, name="login.html", context={"csrf_token": csrf_token})


@web_router.post("/login")
def login_submit(
    request: Request,
    password: str = Form(""),
    api_key: str = Form(""),
    csrf_token: str = Form(""),
    session: Session = Depends(get_session),
):
    if not _validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid or expired form token. Please try again.", "csrf_token": _generate_csrf_token(request)},
        )

    if password != settings.DASHBOARD_PASSWORD:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid password.", "csrf_token": _generate_csrf_token(request)},
        )

    hashed = hash_key(api_key)
    key_rec = session.exec(
        select(ApiKey).where(ApiKey.key_hash == hashed, ApiKey.is_active == True)
    ).first()
    if not key_rec:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid or revoked API key.", "csrf_token": _generate_csrf_token(request)},
        )

    request.session["api_key"] = api_key
    return RedirectResponse(url="/", status_code=303)


@web_router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


# ---------------------------------------------------------------------------
# Protected dashboard routes (middleware handles auth redirect)
# ---------------------------------------------------------------------------

@web_router.get("/", response_class=HTMLResponse)
def index_view(request: Request, session: Session = Depends(get_session)):
    api_key = _get_api_key(request)
    subnets = session.exec(select(Subnet)).all()
    subnet_cards = []

    total_active = 0
    total_uncertain = 0
    total_available = 0

    for s in subnets:
        total_ips = len(expand_cidr_hosts(s.cidr))
        active_count = len(session.exec(select(IPAddress).where(IPAddress.subnet_id == s.id, IPAddress.status == IPStatus.ACTIVE_DETECTED)).all())
        uncertain_count = len(session.exec(select(IPAddress).where(IPAddress.subnet_id == s.id, IPAddress.status == IPStatus.UNCERTAIN_FIREWALLED)).all())
        reserved_count = len(session.exec(select(IPAddress).where(IPAddress.subnet_id == s.id, IPAddress.status == IPStatus.ASSIGNED_RESERVED)).all())
        available_count = max(0, total_ips - (active_count + uncertain_count + reserved_count))

        total_active += active_count
        total_uncertain += uncertain_count
        total_available += available_count

        meta = get_subnet_metadata(s.cidr)
        subnet_cards.append({
            "id": s.id,
            "cidr": s.cidr,
            "name": s.name,
            "description": s.description,
            "scan_interval_minutes": s.scan_interval_minutes,
            "miss_threshold": s.miss_threshold,
            "quarantine_hours": s.quarantine_hours,
            "metadata": meta,
            "stats": {
                "total": total_ips,
                "active": active_count,
                "uncertain": uncertain_count,
                "reserved": reserved_count,
                "available": available_count,
            }
        })

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "active_page": "subnets",
            "subnets": subnet_cards,
            "total_subnets": len(subnets),
            "total_active_ips": total_active,
            "total_uncertain_ips": total_uncertain,
            "total_available_ips": total_available,
            "api_key": api_key,
        },
    )


@web_router.get("/subnets/{subnet_id}/matrix", response_class=HTMLResponse)
def matrix_view(subnet_id: uuid.UUID, request: Request, session: Session = Depends(get_session)):
    api_key = _get_api_key(request)
    subnet = session.get(Subnet, subnet_id)
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    all_hosts = expand_cidr_hosts(subnet.cidr)
    existing_ips = session.exec(select(IPAddress).where(IPAddress.subnet_id == subnet.id)).all()
    ip_map = {ip_rec.ip: ip_rec for ip_rec in existing_ips}

    matrix = []
    for host_ip in all_hosts:
        rec = ip_map.get(host_ip)
        if rec:
            matrix.append({
                "ip": host_ip,
                "status": rec.status.value,
                "hostname": rec.hostname,
            })
        else:
            matrix.append({
                "ip": host_ip,
                "status": IPStatus.AVAILABLE_CANDIDATE.value,
                "hostname": None,
            })

    return templates.TemplateResponse(
        request=request,
        name="matrix.html",
        context={
            "active_page": "subnets",
            "subnet": subnet,
            "total_hosts": len(all_hosts),
            "matrix": matrix,
            "api_key": api_key,
        },
    )


@web_router.get("/web/ips/{ip_address}/drawer", response_class=HTMLResponse)
def ip_drawer_partial(ip_address: str, request: Request, session: Session = Depends(get_session)):
    api_key = _get_api_key(request)
    rec = session.exec(select(IPAddress).where(IPAddress.ip == ip_address.strip())).first()
    if not rec:
        raise HTTPException(status_code=404, detail=f"IP '{ip_address}' not tracked yet.")

    history = session.exec(
        select(IPHistory)
        .where(IPHistory.ip_address_id == rec.id)
        .order_by(IPHistory.timestamp.desc())
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="drawer.html",
        context={
            "ip": rec,
            "history": history,
            "api_key": api_key,
        },
    )


@web_router.get("/provision", response_class=HTMLResponse)
def provision_view(request: Request, session: Session = Depends(get_session)):
    api_key = _get_api_key(request)
    subnets = session.exec(select(Subnet)).all()
    subnet_cards = []
    for s in subnets:
        total_ips = len(expand_cidr_hosts(s.cidr))
        unavailable = len(session.exec(select(IPAddress).where(IPAddress.subnet_id == s.id, IPAddress.status.in_([IPStatus.ACTIVE_DETECTED, IPStatus.ASSIGNED_RESERVED, IPStatus.UNCERTAIN_FIREWALLED]))).all())
        subnet_cards.append({
            "id": s.id,
            "cidr": s.cidr,
            "name": s.name,
            "stats": {"available": max(0, total_ips - unavailable)},
        })

    return templates.TemplateResponse(
        request=request,
        name="provision.html",
        context={
            "active_page": "provision",
            "subnets": subnet_cards,
            "api_key": api_key,
        },
    )


@web_router.get("/web/ips/available", response_class=JSONResponse)
def web_available_ips(
    subnet_id: str,
    count: int = 1,
    session: Session = Depends(get_session),
):
    try:
        sid = uuid.UUID(subnet_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet_id")
    subnet = session.get(Subnet, sid)
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found")

    all_hosts = expand_cidr_hosts(subnet.cidr)
    unavailable_query = select(IPAddress).where(
        IPAddress.subnet_id == subnet.id,
        IPAddress.status.in_([IPStatus.ACTIVE_DETECTED, IPStatus.ASSIGNED_RESERVED, IPStatus.UNCERTAIN_FIREWALLED]),
    )
    unavailable_ips = {rec.ip for rec in session.exec(unavailable_query).all()}

    available = [h for h in all_hosts if h not in unavailable_ips][:count]
    return {
        "subnet_id": str(subnet.id),
        "cidr": subnet.cidr,
        "requested_count": count,
        "available_ips": available,
        "count_returned": len(available),
    }


@web_router.get("/scans", response_class=HTMLResponse)
def scans_view(request: Request, session: Session = Depends(get_session)):
    api_key = _get_api_key(request)
    scans = session.exec(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(100)).all()
    return templates.TemplateResponse(
        request=request,
        name="scans.html",
        context={
            "active_page": "scans",
            "scans": scans,
            "str": str,
            "api_key": api_key,
        },
    )


@web_router.get("/settings", response_class=HTMLResponse)
def settings_view(request: Request, session: Session = Depends(get_session)):
    api_key = _get_api_key(request)
    keys = session.exec(select(ApiKey)).all()
    webhooks = session.exec(select(Webhook)).all()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "active_page": "settings",
            "keys": keys,
            "webhooks": webhooks,
            "api_key": api_key,
        },
    )
