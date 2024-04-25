import uuid
from dataclasses import dataclass

from config.enums import SourceTypes


@dataclass(kw_only=True, init=True, eq=False, order=False)
class Source:
    id: str = str(uuid.uuid4())
    type: SourceTypes | None = None
    name: str
    url: str
    checkoutPath: str = "/"
    branch: str
    commit: str
    vcsType: str = 'git'
