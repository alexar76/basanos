from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

SafeId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
CapabilityId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*@[vV][0-9]+$")]

Verdict = Literal["PASS", "REVIEW", "FAIL"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ScanInput(StrictModel):
    """What a caller may ask BASANOS to look at.

    Roots are *names* from the inventory (``acex``, ``lottery``, ``core``, ``fixtures``)
    or omitted to scan the default ecosystem set. Arbitrary filesystem paths are
    rejected — that would turn /invoke into a local-file oracle.
    """

    roots: list[str] = Field(default_factory=list, max_length=8)
    ingest_intel: bool = False


class InvokeEnvelope(StrictModel):
    input: ScanInput = Field(default_factory=ScanInput)
    product_id: str = Field(default="basanos", max_length=128)
    capability_id: str = Field(default="agent.security.contract-assurance@v1", max_length=192)
    #: Who routed the call. The Hub always sends it (api.py builds
    #: {"capability_id", "input", "product_id", "source_hub"}), and this model forbids extras
    #: — so without this field every federated invoke was a 422 the buyer saw as a 502. It is
    #: recorded, never trusted: nothing in a scan depends on the caller's claim about itself.
    source_hub: str = Field(default="", max_length=256)


class Finding(StrictModel):
    detector_id: str
    category: str
    severity: Severity
    title: str
    detail: str
    path: str
    line: int = 0
    swc: str = ""


def finding_dict(
    *,
    detector_id: str,
    category: str,
    severity: Severity,
    title: str,
    detail: str,
    path: str,
    line: int = 0,
    swc: str = "",
) -> dict[str, Any]:
    return Finding(
        detector_id=detector_id,
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        path=path,
        line=line,
        swc=swc,
    ).model_dump()
