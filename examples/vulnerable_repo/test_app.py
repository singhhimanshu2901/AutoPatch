import pytest
from database import query_user_profile

def test_legitimate_user_lookup():
    """Verify standard legitimate query functions correctly."""
    results = query_user_profile("alice")
    assert len(results) == 1
    assert results[0][1] == "alice"
    assert results[0][2] == "member"

def test_nonexistent_user():
    """Verify non-existent user returns empty list."""
    results = query_user_profile("unknown_user")
    assert len(results) == 0

def test_sql_injection_defense():
    """
    Simulate SQL injection payload.
    With proper parameterized queries, this should return 0 rows (no user named "alice' OR '1'='1").
    """
    results = query_user_profile("alice' OR '1'='1")
    assert len(results) == 0
