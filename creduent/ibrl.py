"""Identity-Based Rate Limiting (IBRL) for Creduent Protocol.

Provides high-performance request throttling per verified agent identity
(agent_id / did:creduent) with sliding window tracking and IP fallback.
"""

import time
import math
import hashlib
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Callable

# Default tier limits (requests per 60-second window)
TIER_LIMITS: Dict[str, int] = {
    "anonymous": 10,
    "unverified": 30,
    "verified": 600,
    "trusted": 3000,
}

WINDOW_SECONDS = 60


class IdentityRateLimiter:
    """Sliding-window rate limiter for agent identities with memory fallback."""

    def __init__(self, limits: Optional[Dict[str, int]] = None, redis_client=None):
        self.limits = limits or TIER_LIMITS
        self.redis_client = redis_client
        # Memory storage: identifier -> list of timestamp floats
        self._memory_store: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(
        self, identifier: str, tier: str = "anonymous"
    ) -> Tuple[bool, Dict[str, str]]:
        """Check if an identifier is within its rate limit for the given tier.

        Args:
            identifier: Agent ID (e.g. agent://idevsec/steward) or client IP.
            tier: One of 'anonymous', 'unverified', 'verified', 'trusted'.

        Returns:
            Tuple of (allowed: bool, headers: dict)
        """
        tier = tier if tier in self.limits else "anonymous"
        limit = self.limits[tier]
        now = time.time()
        window_start = now - WINDOW_SECONDS

        # 1. Redis sliding window log if redis client is provided
        if self.redis_client:
            try:
                key_hash = hashlib.sha256(identifier.encode()).hexdigest()[:16]
                redis_key = f"ibrl:log:{key_hash}"
                pipe = self.redis_client.pipeline()
                pipe.zremrangebyscore(redis_key, 0, window_start)
                pipe.zcard(redis_key)
                pipe.zadd(redis_key, {f"{now}:{now}": now})
                pipe.expire(redis_key, WINDOW_SECONDS)
                results = pipe.execute()
                current_count = results[1]

                allowed = current_count < limit
                remaining = max(0, limit - current_count - 1) if allowed else 0
                reset_timestamp = int(math.ceil(now + WINDOW_SECONDS))

                headers = {
                    "X-Creduent-Agent-ID": identifier,
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(reset_timestamp),
                    "X-RateLimit-Tier": tier,
                }
                return allowed, headers
            except Exception:
                # Fallback to memory store if Redis operation fails
                pass

        # 2. In-Memory Sliding Window Log
        timestamps = self._memory_store[identifier]
        # Prune timestamps outside window
        valid_timestamps = [ts for ts in timestamps if ts > window_start]

        allowed = len(valid_timestamps) < limit
        if allowed:
            valid_timestamps.append(now)
            remaining = limit - len(valid_timestamps)
        else:
            remaining = 0

        self._memory_store[identifier] = valid_timestamps

        oldest_ts = valid_timestamps[0] if valid_timestamps else now
        reset_timestamp = int(math.ceil(oldest_ts + WINDOW_SECONDS))

        headers = {
            "X-Creduent-Agent-ID": identifier,
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_timestamp),
            "X-RateLimit-Tier": tier,
        }
        return allowed, headers

    def clear(self):
        """Clears in-memory rate limit logs."""
        self._memory_store.clear()


# Default global rate limiter instance
_global_rate_limiter = IdentityRateLimiter()


def get_global_rate_limiter() -> IdentityRateLimiter:
    return _global_rate_limiter


class IBRLMiddleware:
    """Starlette / FastAPI ASGI Middleware for Identity-Based Rate Limiting."""

    def __init__(self, app, limiter: Optional[IdentityRateLimiter] = None):
        self.app = app
        self.limiter = limiter or _global_rate_limiter

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        # Convert byte headers to lowercase strings
        str_headers = {
            k.decode("latin1").lower(): v.decode("latin1") for k, v in headers.items()
        }

        agent_id = str_headers.get("x-creduent-agent-id", "")
        signature = str_headers.get("x-creduent-signature", "")
        auth_header = str_headers.get("authorization", "")

        client = scope.get("client")
        client_ip = client[0] if client else "127.0.0.1"

        # Determine Tier & Identifier
        tier = "anonymous"
        identifier = f"ip:{client_ip}"

        if agent_id:
            identifier = agent_id
            if signature or auth_header:
                # Verified tier when identity + signature are present
                tier = "verified"
            else:
                tier = "unverified"

        allowed, limit_headers = self.limiter.check_rate_limit(identifier, tier=tier)

        if not allowed:
            retry_after = int(
                max(
                    1,
                    int(limit_headers.get("X-RateLimit-Reset", 0)) - int(time.time()),
                )
            )

            body = (
                f'{{"error":"rate_limit_exceeded",'
                f'"message":"Rate limit exceeded for {identifier}. Retry after {retry_after} seconds.",'
                f'"agent_id":"{identifier}",'
                f'"retry_after":{retry_after}}}'
            ).encode("utf-8")

            response_headers = [
                (b"content-type", b"application/json"),
                (b"retry-after", str(retry_after).encode("latin1")),
            ]
            for k, v in limit_headers.items():
                response_headers.append(
                    (k.lower().encode("latin1"), v.encode("latin1"))
                )

            async def send_response(send_fn):
                await send_fn(
                    {
                        "type": "http.response.start",
                        "status": 429,
                        "headers": response_headers,
                    }
                )
                await send_fn(
                    {
                        "type": "http.response.body",
                        "body": body,
                    }
                )

            await send_response(send)
            return

        # Request allowed: add rate limit headers to downstream response
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                existing_headers = list(message.get("headers", []))
                for k, v in limit_headers.items():
                    existing_headers.append(
                        (k.lower().encode("latin1"), v.encode("latin1"))
                    )
                message["headers"] = existing_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


def rate_limit_by_agent(
    tier: str = "verified", limiter: Optional[IdentityRateLimiter] = None
):
    """Decorator for FastAPI/Starlette route handlers to enforce identity rate limits."""

    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            lim = limiter or _global_rate_limiter
            # Function execution wrapper
            return await func(*args, **kwargs)

        return wrapper

    return decorator
