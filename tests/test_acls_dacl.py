"""DACL parser + effective-access engine (modules/acls.py).

Covers the correctness fixes: DENY ACEs (v2.23.0), INHERIT_ONLY ACEs and
conditional/callback ACEs (v2.25.0). Pure byte-level fixtures, no DC.
"""
from tests.sd_helpers import ace, sd, SID_LOWPRIV, COND_BLOB

from modules.acls import (
    _parse_dacl, _effective_access, _effective_danger, _control_from_effective,
    GENERIC_ALL, WRITE_DACL, RIGHT_DS_CONTROL_ACCESS, RIGHT_DS_WRITE_PROP,
    INHERIT_ONLY_ACE,
    ACE_ACCESS_ALLOWED, ACE_ACCESS_DENIED,
    ACE_ACCESS_ALLOWED_OBJECT, ACE_ACCESS_DENIED_OBJECT,
    ACE_ACCESS_ALLOWED_CALLBACK, ACE_ACCESS_DENIED_CALLBACK,
    ACE_ACCESS_ALLOWED_CALLBACK_OBJECT,
    GUID_DS_REPL_GET_CHANGES, GUID_DS_REPL_GET_CHANGES_ALL,
    GUID_KEY_CREDENTIAL_LINK, GUID_MEMBER,
)

S = SID_LOWPRIV


def _eff(raw):
    return _effective_access(_parse_dacl(raw, include_deny=True), {S})


# --- the ALLOW-only default contract (protects gpo/adidns/adcs/gmsa) ----------

def test_default_parse_is_allow_only():
    raw = sd([ace(ACE_ACCESS_DENIED, GENERIC_ALL, S),
              ace(ACE_ACCESS_ALLOWED, WRITE_DACL, S)])
    assert len(_parse_dacl(raw)) == 1                 # DENY excluded by default
    assert len(_parse_dacl(raw, include_deny=True)) == 2


# --- DENY handling (v2.23.0) --------------------------------------------------

def test_deny_suppresses_same_trustee_genericall():
    raw = sd([ace(ACE_ACCESS_DENIED, GENERIC_ALL, S),
              ace(ACE_ACCESS_ALLOWED, GENERIC_ALL, S)])
    assert _effective_danger(_eff(raw))[0] is False

def test_allow_only_is_still_a_finding():
    raw = sd([ace(ACE_ACCESS_ALLOWED, GENERIC_ALL, S)])
    assert _effective_danger(_eff(raw)) == (True, "GenericAll")

def test_deny_on_repl_guid_suppresses_dcsync():
    raw = sd([ace(ACE_ACCESS_DENIED_OBJECT, RIGHT_DS_CONTROL_ACCESS, S, guid=GUID_DS_REPL_GET_CHANGES_ALL),
              ace(ACE_ACCESS_ALLOWED_OBJECT, RIGHT_DS_CONTROL_ACCESS, S, guid=GUID_DS_REPL_GET_CHANGES_ALL),
              ace(ACE_ACCESS_ALLOWED_OBJECT, RIGHT_DS_CONTROL_ACCESS, S, guid=GUID_DS_REPL_GET_CHANGES)])
    eff = _eff(raw)
    assert GUID_DS_REPL_GET_CHANGES_ALL not in eff.access_guids
    assert GUID_DS_REPL_GET_CHANGES in eff.access_guids

def test_blanket_deny_genericall_wipes_repl_guid():
    raw = sd([ace(ACE_ACCESS_DENIED, GENERIC_ALL, S),
              ace(ACE_ACCESS_ALLOWED_OBJECT, RIGHT_DS_CONTROL_ACCESS, S, guid=GUID_DS_REPL_GET_CHANGES_ALL)])
    assert GUID_DS_REPL_GET_CHANGES_ALL not in _eff(raw).access_guids

def test_deny_keycred_suppresses_control():
    raw = sd([ace(ACE_ACCESS_DENIED_OBJECT, RIGHT_DS_WRITE_PROP, S, guid=GUID_KEY_CREDENTIAL_LINK),
              ace(ACE_ACCESS_ALLOWED_OBJECT, RIGHT_DS_WRITE_PROP, S, guid=GUID_KEY_CREDENTIAL_LINK)])
    rights = [r[0] for r in _control_from_effective(_eff(raw))]
    assert "Write msDS-KeyCredentialLink" not in rights

def test_allow_keycred_kept_with_granting_sid():
    raw = sd([ace(ACE_ACCESS_ALLOWED_OBJECT, RIGHT_DS_WRITE_PROP, S, guid=GUID_KEY_CREDENTIAL_LINK)])
    ctrl = _control_from_effective(_eff(raw))
    assert ctrl and ctrl[0][0] == "Write msDS-KeyCredentialLink"
    assert ctrl[0][3] == S                             # granting SID attached

def test_unrelated_deny_leaves_other_right():
    raw = sd([ace(ACE_ACCESS_DENIED_OBJECT, RIGHT_DS_WRITE_PROP, S, guid=GUID_MEMBER),
              ace(ACE_ACCESS_ALLOWED_OBJECT, RIGHT_DS_WRITE_PROP, S, guid=GUID_KEY_CREDENTIAL_LINK)])
    rights = [r[0] for r in _control_from_effective(_eff(raw))]
    assert "Write member" not in rights
    assert "Write msDS-KeyCredentialLink" in rights


# --- INHERIT_ONLY ACEs (v2.25.0) ---------------------------------------------

def test_inherit_only_ace_dropped():
    raw = sd([ace(ACE_ACCESS_ALLOWED, GENERIC_ALL, S, flags=INHERIT_ONLY_ACE)])
    assert len(_parse_dacl(raw)) == 0
    assert _effective_danger(_eff(raw))[0] is False

def test_inherited_not_inherit_only_kept():
    raw = sd([ace(ACE_ACCESS_ALLOWED, GENERIC_ALL, S, flags=0x10)])  # INHERITED_ACE
    assert len(_parse_dacl(raw)) == 1


# --- conditional / callback ACEs (v2.25.0) -----------------------------------

def test_conditional_allow_is_parsed_and_surfaces():
    raw = sd([ace(ACE_ACCESS_ALLOWED_CALLBACK, GENERIC_ALL, S, trailer=COND_BLOB)])
    parsed = _parse_dacl(raw)
    assert len(parsed) == 1 and parsed[0]["conditional"] is True
    assert _effective_danger(_eff(raw)) == (True, "GenericAll")

def test_conditional_deny_does_not_suppress():
    raw = sd([ace(ACE_ACCESS_DENIED_CALLBACK, GENERIC_ALL, S, trailer=COND_BLOB),
              ace(ACE_ACCESS_ALLOWED, GENERIC_ALL, S)])
    assert _effective_danger(_eff(raw)) == (True, "GenericAll")

def test_hard_deny_still_suppresses_vs_conditional():
    raw = sd([ace(ACE_ACCESS_DENIED, GENERIC_ALL, S),
              ace(ACE_ACCESS_ALLOWED, GENERIC_ALL, S)])
    assert _effective_danger(_eff(raw))[0] is False

def test_conditional_object_allow_by_guid():
    raw = sd([ace(ACE_ACCESS_ALLOWED_CALLBACK_OBJECT, RIGHT_DS_WRITE_PROP, S,
                  guid=GUID_KEY_CREDENTIAL_LINK, trailer=COND_BLOB)])
    rights = [r[0] for r in _control_from_effective(_eff(raw))]
    assert "Write msDS-KeyCredentialLink" in rights

def test_default_parse_excludes_conditional_deny():
    raw = sd([ace(ACE_ACCESS_DENIED_CALLBACK, GENERIC_ALL, S, trailer=COND_BLOB),
              ace(ACE_ACCESS_ALLOWED_CALLBACK, WRITE_DACL, S, trailer=COND_BLOB)])
    default = _parse_dacl(raw)
    assert all(a["type"] != ACE_ACCESS_DENIED for a in default)
    assert len(default) == 1
