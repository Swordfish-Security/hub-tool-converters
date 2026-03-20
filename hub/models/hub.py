from dataclasses import dataclass, asdict
from typing import Any

from hub.models.location import LocationStack
from hub.models.source import SourceSast


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
    source: list[SourceSast]
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
        # Clean up optional DAST fields (httpRequest/httpResponse) when not set
        self._remove_optional_dast_fields(result)
        return result

    @staticmethod
    def _remove_optional_dast_fields(d):
        """Remove httpRequest/httpResponse keys when they are None (v1.0.1 compat)."""
        if isinstance(d, dict):
            for key in ("httpRequest", "httpResponse"):
                if key in d and d[key] is None:
                    del d[key]
            for v in d.values():
                Report._remove_optional_dast_fields(v)
        elif isinstance(d, list):
            for item in d:
                Report._remove_optional_dast_fields(item)


@dataclass(kw_only=False, eq=False, order=False)
class FindingHubSast:
    type: str
    id: str
    ruleId: str
    locationId: str
    line: int
    code: str
    status: str
    description: str
    stacks: list[LocationStack] = None

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
        if self.line is not None:
            self.stacks = [
                LocationStack(locationId=self.locationId, line=self.line, code=self.code)
            ]
        super().__init__()


@dataclass(kw_only=False, eq=False, order=False)
class HttpMessage:
    """Structured HTTP message for v1.0.2 schema."""
    header: str = ""
    body: str = ""


@dataclass(kw_only=False, eq=False, order=False)
class FindingHubDast:
    type: str
    id: str
    ruleId: str
    locationId: str
    url: str
    status: str
    description: str
    httpRequest: HttpMessage = None
    httpResponse: HttpMessage = None

    def __init__(
            self,
            idx: str,
            ruleId: str,
            locationId: str,
            url: str,
            description: str,
            status: str,
            type: str,
            httpRequest: HttpMessage = None,
            httpResponse: HttpMessage = None
    ):
        self.type = type
        self.id = idx
        self.ruleId = ruleId
        self.locationId = locationId
        self.url = url
        self.description = description
        self.status = status
        self.httpRequest = httpRequest
        self.httpResponse = httpResponse
        super().__init__()


@dataclass(kw_only=False, eq=False, order=False)
class FindingHubScaS:
    type: str
    id: str
    ruleId: str
    locationId: str
    status: str
    description: str

    def __init__(
            self,
            idx: str,
            ruleId: str,
            locationId: str,
            description: str,
            status: str,
            type: str
    ):
        self.type = type
        self.id = idx
        self.ruleId = ruleId
        self.locationId = locationId
        self.description = description
        self.status = status
        super().__init__()
