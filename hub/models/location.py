from dataclasses import dataclass

from config.enums import SourceTypes


@dataclass(kw_only=True, init=True, eq=False, order=False)
class Location:
    type: SourceTypes
    id: str
    sourceId: str
    fileName: str
    language: str = "Any"


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationStack:
    locationId: str
    sequence: int = 1
    code: str
    line: int
