"""FSMO role identification (modules/domain.py, _guess_role).

The three domain-NC roles live on distinct objects and must not be conflated;
the match is exact/base-relative (v2.25.0).
"""
import tests.sd_helpers  # noqa: F401  (puts repo root on sys.path)
from modules.domain import DomainModule

B = "DC=corp,DC=lab"


def _role(dn):
    return DomainModule._guess_role(dn, B, "", "")


def test_domain_head_is_pdc_only():
    assert _role(B) == "PDC Emulator"

def test_rid_manager_object_is_rid_master():
    assert _role(f"CN=RID Manager$,CN=System,{B}") == "RID Master"

def test_infrastructure_object():
    assert _role(f"CN=Infrastructure,{B}") == "Infrastructure Master"

def test_dns_partition_infrastructure_not_matched():
    # DNS application partitions have their own Infrastructure object — it must
    # NOT be reported as an extra domain Infrastructure Master row.
    assert _role(f"CN=Infrastructure,DC=DomainDnsZones,{B}") == ""
    assert _role(f"CN=Infrastructure,DC=ForestDnsZones,{B}") == ""

def test_case_insensitive():
    assert _role(f"cn=rid manager$,cn=system,{B.lower()}") == "RID Master"

def test_unrelated_object():
    assert _role(f"CN=Something,{B}") == ""
