import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, Request, status
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import Settings, get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    settings: Optional[Settings] = None,
) -> str:
    settings = settings or get_settings()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded


def decode_access_token(token: str, settings: Optional[Settings] = None) -> Optional[str]:
    settings = settings or get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        sub: Optional[str] = payload.get("sub")
        if sub is None:
            return None
        return sub
    except JWTError:
        return None


URL_REGEX = re.compile(
    r"^(https?)://"  # scheme
    r"([\w.-]+)"  # domain
    r"(:\d+)?"  # optional port
    r"(/.*)?$",  # optional path
    re.IGNORECASE,
)


def validate_target_url(url: str, settings: Optional[Settings] = None) -> str:
    settings = settings or get_settings()

    url = url.strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty",
        )

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    if not URL_REGEX.match(url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL format",
        )

    parsed = urlparse(url)

    if parsed.scheme not in settings.ALLOWED_SCHEMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scheme '{parsed.scheme}' not allowed",
        )

    hostname = parsed.hostname or ""

    try:
        ip_addr = ipaddress.ip_address(hostname)
        for blocked in settings.BLOCKED_IP_RANGES:
            if ip_addr in ipaddress.ip_network(blocked, strict=False):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Private/internal IP addresses are not allowed",
                )
    except ValueError:
        pass

    blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if hostname.lower() in blocked_hosts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Localhost addresses are not allowed",
        )

    return url


async def resolve_and_check_ip(url: str, settings: Optional[Settings] = None) -> None:
    settings = settings or get_settings()
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    try:
        import socket

        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                for blocked in settings.BLOCKED_IP_RANGES:
                    if ip_addr in ipaddress.ip_network(blocked, strict=False):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="URL resolves to a private IP address",
                        )
            except ValueError:
                continue
    except socket.gaierror:
        pass


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
