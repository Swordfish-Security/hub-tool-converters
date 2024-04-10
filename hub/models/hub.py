from dataclasses import dataclass, asdict
from typing import Any

from hub.models.location import LocationStack
from hub.models.source import Source


@dataclass(kw_only=True, eq=False, order=False, init=True)
class ScanResult:
    rules: list[Any]
    locations: list[Any]
    findings: list[Any]


@dataclass(kw_only=True, eq=False, order=False, init=True)
class ScanDetail:
    id: str
    description: str


@dataclass(kw_only=True, eq=False, order=False, init=True)
class Scan:
    scanDetails: ScanDetail
    source: list[Source]
    tool: dict[str, str]
    results: list[ScanResult]


@dataclass(kw_only=True, eq=False, order=False, init=True)
class Report:
    schema: str = "https://docs.appsec-hub.ru/"
    version: str = "1.0.1"
    scans: list[Scan]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["$schema"] = self.schema
        del result["schema"]
        return result


@dataclass(kw_only=False, eq=False, order=False)
class FindingHub:
    type: str
    id: str
    ruleId: str
    locationId: str
    line: int
    code: str
    status: str
    description: str
    stacks: list[LocationStack]

    def __init__(
            self,
            idx: str,
            ruleId: str,
            locationId: str,
            line: int,
            code: str,
            description: str,
            status: str,
            type: str
    ):
        self.type = type
        self.id = idx
        self.ruleId = ruleId
        self.locationId = locationId
        self.line = line
        self.code = code
        self.description = description
        self.status = status

        if self.code and self.line:
            self.stacks = [
                LocationStack(locationId=self.locationId, line=self.line, code=self.code)
            ]
        super().__init__()
