"""
Shared GitHub HTTP helpers: rate limit handling, exponential backoff, and polite delays.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Default minimal delay between API calls to avoid bursting
_DEFAULT_DELAY_SEC = float(os.getenv("GITHUB_REQ_DELAY", "0.35"))
# Max attempts when backing off for 429/5xx
_DEFAULT_MAX_ATTEMPTS = int(os.getenv("GITHUB_REQ_MAX_ATTEMPTS", "6"))
# Backoff multiplier
_DEFAULT_BACKOFF_BASE = float(os.getenv("GITHUB_REQ_BACKOFF_BASE", "1.7"))


def make_rate_limited_session(token: Optional[str], user_agent: str = "auditgh") -> requests.Session:
    """Create a requests Session with retry for idempotent requests and auth headers.

    Retries cover transient 5xx and 429, but we still implement explicit rate-limit backoff.
    """
    s = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    headers: Dict[str, str] = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"{user_agent}" if user_agent else "auditgh",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    s.headers.update(headers)
    return s


def _compute_rate_limit_sleep(resp: requests.Response) -> Optional[float]:
    try:
        remaining = int(resp.headers.get("X-RateLimit-Remaining", "0"))
        if resp.status_code == 403 and remaining == 0:
            reset = int(resp.headers.get("X-RateLimit-Reset", "0"))
            now = time.time()
            return max(0.0, reset - now + 2.0)  # small buffer
    except Exception:
        pass
    return None


def request_with_rate_limit(
    session: requests.Session,
    method: str,
    url: str,
    *,
    logger: Optional[logging.Logger] = None,
    min_delay_sec: float = _DEFAULT_DELAY_SEC,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    backoff_base: float = _DEFAULT_BACKOFF_BASE,
    **kwargs: Any,
) -> requests.Response:
    """Perform a GitHub API request with:
    - pre-request delay (politeness)
    - explicit 403(remaining=0) sleep-until-reset handling
    - exponential backoff for 429/5xx
    - improved logging
    """
    log = logger or logging.getLogger("auditgh.github.rate_limit")
    attempt = 0
    # Polite pacing to reduce bursts
    if min_delay_sec > 0:
        time.sleep(min_delay_sec)

    while True:
        attempt += 1
        try:
            resp = session.request(method, url, **kwargs)
        except requests.RequestException as e:
            if attempt >= max_attempts:
                raise
            sleep_s = (backoff_base ** (attempt - 1))
            log.warning("Request error on %s %s (attempt %d/%d): %s; sleeping %.1fs",
                        method, url, attempt, max_attempts, e, sleep_s)
            time.sleep(sleep_s)
            continue

        # Handle hard rate-limit
        sleep_reset = _compute_rate_limit_sleep(resp)
        if sleep_reset is not None:
            log.warning("GitHub rate limit exhausted. Sleeping for %.1fs until reset (X-RateLimit-Reset=%s)",
                        sleep_reset, resp.headers.get("X-RateLimit-Reset"))
            time.sleep(sleep_reset)
            # After reset, retry immediately without counting as failure
            continue

        # Retry on 429/5xx with exponential backoff
        if resp.status_code in (429, 500, 502, 503, 504):
            if attempt >= max_attempts:
                return resp  # let caller raise_for_status()
            sleep_s = (backoff_base ** (attempt - 1))
            log.warning("Transient HTTP %s on %s %s (attempt %d/%d). Sleeping %.1fs",
                        resp.status_code, method, url, attempt, max_attempts, sleep_s)
            time.sleep(sleep_s)
            continue

        return resp
