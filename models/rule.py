from dataclasses import dataclass, field

from config.enums import ScannerTypes


@dataclass(kw_only=True, eq=False, order=False)
class Rule:
    type: ScannerTypes | None = None
    name: str | None = None
    id: str | None = None
    severity: str | None = None
    cwe: list[dict[str, str | int]] | None = None
    description: str | None = None

    def __init__(
            self,
            type: ScannerTypes | None = None,
            name: str | None = None,
            severity: str | None = None,
            description: str | None = None,
    ):
        self.type = type
        self.name = name
        self.id = name
        self.severity = severity
        self.description = description
        self.cwe = [
            {
                "id": 798,
                "name": "Use of Hard-coded Credentials",
                "link": "https://cwe.mitre.org/data/definitions/798.html"
            }
        ]
        super().__init__()
