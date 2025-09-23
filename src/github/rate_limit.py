"""
Shared GitHub HTTP helpers: rate limit handling, exponential backoff, and polite delays.
"""
from __future__ import annotations

import logging
import os
import time
import threading
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

# Adaptive throttling settings
_ADAPTIVE_ENABLED = os.getenv("GITHUB_ADAPTIVE_THROTTLE", "1") not in ("0", "false", "False")
_TARGET_UTIL = float(os.getenv("GITHUB_TARGET_UTILIZATION", "0.6"))  # use ~60% of budget
_SMOOTHING = float(os.getenv("GITHUB_ADAPTIVE_SMOOTHING", "0.3"))     # EMA factor for interval updates
_MIN_INTERVAL = float(os.getenv("GITHUB_MIN_INTERVAL", "0.15"))        # floor between requests
_MAX_INTERVAL = float(os.getenv("GITHUB_MAX_INTERVAL", "5.0"))         # ceiling between requests


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
        # Prefer Bearer; GitHub also accepts legacy 'token ' prefix
        headers["Authorization"] = f"Bearer {token}"
    s.headers.update(headers)
    # Attach adaptive limiter for this session
    if _ADAPTIVE_ENABLED:
        s._auditgh_rate_limiter = _AdaptiveRateLimiter(
            initial_interval=_DEFAULT_DELAY_SEC,
            min_interval=_MIN_INTERVAL,
            max_interval=_MAX_INTERVAL,
            target_util=_TARGET_UTIL,
            smoothing=_SMOOTHING,
        )
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


class _AdaptiveRateLimiter:
    """Cross-thread adaptive rate limiter based on GitHub headers.

    Ensures requests across threads are spaced by a shared interval and adjusts
    that interval using remaining/reset headers to avoid hard rate-limit sleeps.
    """

    def __init__(
        self,
        *,
        initial_interval: float,
        min_interval: float,
        max_interval: float,
        target_util: float,
        smoothing: float,
    ) -> None:
        self.interval = max(min(initial_interval, max_interval), min_interval)
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.target_util = max(0.05, min(0.95, target_util))
        self.smoothing = max(0.05, min(0.9, smoothing))
        self._lock = threading.Lock()
        self._next_ts = time.monotonic()

    def wait_turn(self) -> None:
        with self._lock:
            now = time.monotonic()
            sleep_for = max(0.0, self._next_ts - now)
            # Reserve the next slot based on current interval
            base = now if now > self._next_ts else self._next_ts
            self._next_ts = base + self.interval
        if sleep_for > 0:
            time.sleep(sleep_for)

    def adjust_from_response(self, resp: requests.Response, log: logging.Logger) -> None:
        try:
            # Secondary rate-limit honoring via Retry-After
            if resp.status_code in (403, 429):
                ra = resp.headers.get("Retry-After")
                if ra:
                    try:
                        ra_s = float(ra)
                    except Exception:
                        ra_s = None
                    if ra_s and ra_s > 0:
                        log.warning("Secondary rate limit signaled. Sleeping %.1fs (Retry-After)", ra_s)
                        # Push next window and slow down
                        with self._lock:
                            self._next_ts = time.monotonic() + ra_s
                            self.interval = min(self.max_interval, self.interval * 1.5)
                        time.sleep(ra_s)
                        return

            limit = int(resp.headers.get("X-RateLimit-Limit", "0") or 0)
            remaining = int(resp.headers.get("X-RateLimit-Remaining", "-1") or -1)
            reset = int(resp.headers.get("X-RateLimit-Reset", "0") or 0)
            now = time.time()
            reset_in = max(1.0, reset - now) if reset else 60.0

            if remaining >= 0 and limit > 0:
                # Compute budgeted RPS and corresponding interval with headroom
                allowed_rps = max(0.01, (remaining / reset_in) * self.target_util)
                target_interval = min(self.max_interval, max(self.min_interval, 1.0 / allowed_rps))
                with self._lock:
                    old = self.interval
                    # Exponential moving average for smoother changes
                    self.interval = old * (1.0 - self.smoothing) + target_interval * self.smoothing
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(
                        "Adaptive throttle: remain=%s limit=%s reset_in=%.0fs interval: %.2fs -> %.2fs (rps≈%.2f)",
                        remaining, limit, reset_in, old, self.interval, 1.0 / max(self.interval, 1e-6)
                    )
        except Exception:
            # Never let throttling errors break calls
            return

    def bump_after_hard_reset(self) -> None:
        with self._lock:
            self.interval = min(self.max_interval, max(self.min_interval, self.interval * 2.0))


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
    # Cross-thread pacing using shared limiter if available
    limiter: Optional[_AdaptiveRateLimiter] = getattr(session, "_auditgh_rate_limiter", None)

    while True:
        attempt += 1
        try:
            # Pre-request pacing
            if limiter:
                limiter.wait_turn()
            else:
                if min_delay_sec > 0:
                    time.sleep(min_delay_sec)
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
            if limiter:
                limiter.bump_after_hard_reset()
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

        # Adjust pacing from response headers (adaptive throttle)
        if limiter:
            limiter.adjust_from_response(resp, log)
        return resp
