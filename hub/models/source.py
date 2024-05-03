import uuid
from dataclasses import dataclass

from config.enums import SourceTypes, Stage


@dataclass(kw_only=True, init=True, eq=False, order=False)
class SourceSast:
    id: str = str(uuid.uuid4())
    type: SourceTypes = SourceTypes.CODEBASE.value
    name: str
    url: str
    checkoutPath: str = "/"
    branch: str
    commit: str
    vcsType: str = 'git'


@dataclass(kw_only=True, init=True, eq=False, order=False)
class SourceDast:
    id: str = str(uuid.uuid4())
    type: SourceTypes = SourceTypes.INSTANCE.value
    name: str
    url: str
    stage: Stage | None = None
