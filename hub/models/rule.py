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
    type: ScannerTypes
    name: str
    id: str
    severity: str
    cwe: list[RuleCwe]
    description: str

    def __init__(
            self,
            type: ScannerTypes,
            name: str,
            severity: str,
            description: str,
            cwe: list[RuleCwe]
    ):
        self.type = type
        self.name = name
        self.id = name
        self.severity = severity
        self.description = description
        self.cwe = cwe
        super().__init__()


@dataclass(kw_only=True, eq=False, order=False)
class RuleSCA(Rule):
    cveId: str
    cvssv3: str
    cvssv3_score: float
    references: list[str]

    def __init__(
            self,
            type: ScannerTypes,
            name: str,
            severity: str,
            description: str,
            cwe: list[RuleCwe],
            references: list[str],
            cvssv3: str,
            cvssv3_score: float
    ):
        self.cveId = name
        self.cvssv3 = cvssv3
        self.cvssv3_score = cvssv3_score
        self.references = references
        super().__init__(type, name, severity, description, cwe)
