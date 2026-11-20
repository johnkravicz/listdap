"""SID privilege classification helpers (utils/sids.py).

Guards the foreign-privileged-SID detection used by the sidhistory module.
"""
import tests.sd_helpers  # noqa: F401  (puts repo root on sys.path)
from utils.sids import is_privileged_sid, privileged_rid_of

DSID = "S-1-5-21-1111111111-2222222222-3333333333"
OTHER = "S-1-5-21-9999999999-8888888888-7777777777"


# --- is_privileged_sid: current domain only -----------------------------------

def test_local_domain_admins_is_privileged():
    assert is_privileged_sid(f"{DSID}-512", DSID) is True

def test_local_normal_user_not_privileged():
    assert is_privileged_sid(f"{DSID}-1105", DSID) is False

def test_builtin_administrators_is_privileged():
    assert is_privileged_sid("S-1-5-32-544", DSID) is True

def test_foreign_domain_admins_not_seen_by_domain_scoped_check():
    # The whole point: the domain-scoped check does NOT flag a foreign -512.
    assert is_privileged_sid(f"{OTHER}-512", DSID) is False


# --- privileged_rid_of: domain-agnostic ---------------------------------------

def test_foreign_domain_admins_has_privileged_rid():
    assert privileged_rid_of(f"{OTHER}-512") is True

def test_foreign_enterprise_admins_has_privileged_rid():
    assert privileged_rid_of(f"{OTHER}-519") is True

def test_foreign_normal_user_not_privileged_rid():
    assert privileged_rid_of(f"{OTHER}-1105") is False

def test_builtin_sid_is_not_a_domain_account_rid():
    # S-1-5-32-544 is not an S-1-5-21 domain account SID.
    assert privileged_rid_of("S-1-5-32-544") is False

def test_local_privileged_rid_also_matches():
    assert privileged_rid_of(f"{DSID}-519") is True
