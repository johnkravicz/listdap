"""
Windows timestamp conversion utilities.
"""

from datetime import datetime, timezone, timedelta

# Windows FILETIME epoch: January 1, 1601
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FILETIME_TICK  = 1e7  # 100-nanosecond intervals per second


def filetime_to_dt(filetime: int) -> datetime:
    """Convert a Windows FILETIME integer to a UTC datetime."""
    return _FILETIME_EPOCH + timedelta(seconds=filetime / _FILETIME_TICK)


def filetime_to_str(filetime) -> str:
    """Convert a Windows FILETIME to a human-readable string.
    Returns 'never' for 0 or None, 'unknown' for invalid values.
    """
    try:
        value = int(filetime)
    except (TypeError, ValueError):
        return "unknown"

    if value == 0 or value == 0x7FFFFFFFFFFFFFFF:
        return "never"

    try:
        dt = filetime_to_dt(value)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return "unknown"


def generalized_time_to_str(value) -> str:
    """Parse a generalized time string (e.g., '20240115120000.0Z') to readable format."""
    if not value:
        return "never"
    s = str(value).strip()
    # ldap3 may return datetime objects directly
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    try:
        s = s.rstrip("Z").split(".")[0]
        dt = datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(value)


def days_since_filetime(filetime) -> int:
    """Return the number of days since a FILETIME timestamp. -1 if never/invalid."""
    try:
        value = int(filetime)
    except (TypeError, ValueError):
        return -1
    if value == 0 or value == 0x7FFFFFFFFFFFFFFF:
        return -1
    try:
        dt = filetime_to_dt(value)
        delta = datetime.now(timezone.utc) - dt
        return delta.days
    except Exception:
        return -1
