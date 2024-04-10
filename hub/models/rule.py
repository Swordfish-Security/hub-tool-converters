from dataclasses import dataclass

from config.enums import ScannerTypes


@dataclass(kw_only=False, eq=False, order=False)
class RuleCwe:
    id: int = 0

    def __init__(
            self,
            name: str | None = None,
            link: str | None = None,
            idx: int = 0,
    ):
        self.id = idx
        if name:
            self.name = name
        if link:
            self.link = link
        super().__init__()


@dataclass(kw_only=True, eq=False, order=False)
class Rule:
    type: ScannerTypes | None = None
    name: str | None = None
    id: str | None = None
    severity: str | None = None
    cwe: list[RuleCwe] | None = None
    description: str | None = None

    def __init__(
            self,
            type: ScannerTypes | None = None,
            name: str | None = None,
            severity: str | None = None,
            description: str | None = None,
            cwe: list[RuleCwe] = 0
    ):
        self.type = type
        self.name = name
        self.id = name
        self.severity = severity
        self.description = description
        self.cwe = cwe
        super().__init__()
