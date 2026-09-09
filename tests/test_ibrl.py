import pytest
import time
from creduent.ibrl import IdentityRateLimiter, TIER_LIMITS


def test_anonymous_ip_rate_limiting():
    limiter = IdentityRateLimiter(limits={"anonymous": 3})
    ip = "ip:192.168.1.50"

    # First 3 requests allowed
    for i in range(3):
        allowed, headers = limiter.check_rate_limit(ip, tier="anonymous")
        assert allowed is True
        assert headers["X-RateLimit-Limit"] == "3"
        assert headers["X-RateLimit-Remaining"] == str(2 - i)

    # 4th request blocked
    allowed, headers = limiter.check_rate_limit(ip, tier="anonymous")
    assert allowed is False
    assert headers["X-RateLimit-Remaining"] == "0"
    assert headers["X-RateLimit-Tier"] == "anonymous"


def test_verified_agent_tier_escalation():
    limiter = IdentityRateLimiter(limits={"anonymous": 2, "verified": 5})
    agent_id = "agent://idevsec/steward"

    # Verified agent gets 5 requests
    for i in range(5):
        allowed, headers = limiter.check_rate_limit(agent_id, tier="verified")
        assert allowed is True
        assert headers["X-RateLimit-Limit"] == "5"
        assert headers["X-RateLimit-Tier"] == "verified"

    # 6th request blocked
    allowed, headers = limiter.check_rate_limit(agent_id, tier="verified")
    assert allowed is False
    assert headers["X-RateLimit-Remaining"] == "0"


def test_rate_limiter_clear():
    limiter = IdentityRateLimiter(limits={"unverified": 2})
    agent_id = "agent://test/bot"

    limiter.check_rate_limit(agent_id, tier="unverified")
    limiter.check_rate_limit(agent_id, tier="unverified")
    allowed, _ = limiter.check_rate_limit(agent_id, tier="unverified")
    assert allowed is False

    limiter.clear()
    allowed, headers = limiter.check_rate_limit(agent_id, tier="unverified")
    assert allowed is True
    assert headers["X-RateLimit-Remaining"] == "1"
