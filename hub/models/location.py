from dataclasses import dataclass

from config.enums import SourceTypes


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationSast:
    type: SourceTypes
    id: str
    sourceId: str
    fileName: str
    language: str = "Any"


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationDast:
    type: SourceTypes
    id: str
    sourceId: str
    url: str
    description: str


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationStack:
    locationId: str
    sequence: int = 1
    code: str
    line: int
