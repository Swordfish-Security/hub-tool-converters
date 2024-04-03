from dataclasses import dataclass

from config.enums import SourceTypes


@dataclass(kw_only=True, init=True, eq=False, order=False)
class Location:
    type: SourceTypes | None = None
    id: str | None = None
    sourceId: str | None = None
    fileName: str | None = None
    language: str = "Any"


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationStack:
    locationId: str
    sequence: int = 1
    code: str
    line: int
