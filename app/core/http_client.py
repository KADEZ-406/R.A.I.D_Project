"""
HTTP Client wrapper for R.A.I.D core.

Provides a stable API for plugins and engine, wrapping the existing
`app.utils.http_client.HTTPClient` while offering a ResponseWrapper with
sanitization helpers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.utils.http_client import HTTPClient as _LegacyHTTPClient
from app.utils.http_client import Response as _LegacyResponse


_DEFAULT_NORMALIZERS = [
    # Timestamps
    (re.compile(r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}"), "TIMESTAMP"),
    # Session IDs
    (re.compile(r"sessionid=[A-Za-z0-9]+", re.I), "sessionid=SESSIONID"),
    (re.compile(r"PHPSESSID=[A-Za-z0-9]+", re.I), "PHPSESSID=SESSIONID"),
    # CSRF tokens
    (re.compile(r"csrf[_-]?token=[A-Za-z0-9]+", re.I), "csrf_token=CSRFTOKEN"),
    (re.compile(r"_token=[A-Za-z0-9]+", re.I), "_token=CSRFTOKEN"),
    # UUID
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "UUID"),
]


@dataclass
class ResponseWrapper:
    """Normalized response object returned by the core HTTPClient.

    Times are expressed in milliseconds to simplify timing comparisons.
    """

    status_code: int
    headers: Dict[str, str]
    text: str
    content: bytes
    url: str
    elapsed_ms: float

    def sanitized_text(self, extra_normalizers: Optional[list[tuple[re.Pattern, str]]] = None) -> str:
        """Return response text with volatile tokens removed."""
        normalized = self.text or ""
        for pattern, repl in _DEFAULT_NORMALIZERS + (extra_normalizers or []):
            normalized = pattern.sub(repl, normalized)
        return normalized

    @property
    def elapsed(self) -> float:
        """Compatibility accessor returning seconds."""
        return (self.elapsed_ms or 0.0) / 1000.0


class HTTPClient:
    """Core HTTP client facade.

    Wraps utils HTTP client and exposes a compact, stable API.
    """

    def __init__(
        self,
        timeout: int = 10,
        proxies: Optional[str] = None,
        user_agent: Optional[str] = None,
        max_redirects: int = 5,
        trust_env: bool = False,
        force: bool = False,
    ) -> None:
        self._legacy = _LegacyHTTPClient(
            timeout=timeout,
            user_agent=user_agent or "R.A.I.D-Scanner/1.0",
            proxy=proxies,
            verify_ssl=True,
            max_retries=2,
        )
        self._force = force

    async def __aenter__(self) -> "HTTPClient":
        await self._legacy._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    async def request(self, method: str, url: str, **kwargs: Any) -> ResponseWrapper:
        method_upper = method.upper()
        respect_robots = not self._force
        if method_upper == "GET":
            legacy_resp = await self._legacy.get(
                url,
                headers=kwargs.get("headers"),
                params=kwargs.get("params"),
                follow_redirects=kwargs.get("follow_redirects", True),
                respect_robots=respect_robots,
            )
        elif method_upper == "POST":
            legacy_resp = await self._legacy.post(
                url,
                data=kwargs.get("data"),
                headers=kwargs.get("headers"),
                follow_redirects=kwargs.get("follow_redirects", False),
                respect_robots=respect_robots,
            )
        else:
            # Fallback to underlying request
            legacy_resp = await self._legacy._make_request(
                method=method_upper,
                url=url,
                headers=kwargs.get("headers"),
                data=kwargs.get("data"),
                params=kwargs.get("params"),
                follow_redirects=kwargs.get("follow_redirects", False),
            )
        return self._wrap(legacy_resp)

    async def get(self, url: str, params: dict | None = None, **kwargs: Any) -> ResponseWrapper:
        legacy_resp = await self._legacy.get(
            url,
            params=params,
            headers=kwargs.get("headers"),
            follow_redirects=kwargs.get("follow_redirects", True),
            respect_robots=not self._force,
        )
        return self._wrap(legacy_resp)

    async def post(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> ResponseWrapper:
        # Prefer data; if json provided, pass it via data for legacy client simplicity
        payload = data if data is not None else json
        legacy_resp = await self._legacy.post(
            url,
            data=payload,
            headers=kwargs.get("headers"),
            follow_redirects=kwargs.get("follow_redirects", False),
            respect_robots=not self._force,
        )
        return self._wrap(legacy_resp)

    async def close(self) -> None:
        await self._legacy.close()

    @staticmethod
    def _wrap(resp: _LegacyResponse) -> ResponseWrapper:
        return ResponseWrapper(
            status_code=resp.status_code,
            headers=resp.headers,
            text=resp.text,
            content=resp.content,
            url=resp.url,
            elapsed_ms=float(resp.elapsed) * 1000.0,
        )

    async def get_underlying_httpx(self):
        """Expose the underlying httpx.AsyncClient for discovery components.
        Only for internal integration use.
        """
        return await self._legacy._ensure_session()


