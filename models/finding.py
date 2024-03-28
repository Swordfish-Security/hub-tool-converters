from dataclasses import dataclass

from models.location import LocationStack


@dataclass(kw_only=False, eq=False, order=False)
class Finding:
    type: str | None = None
    id: str | None = None
    ruleId: str | None = None
    locationId: str | None = None
    line: int | None = None
    code: str | None = None
    status: str | None = None
    description: str | None = None
    stacks: list[LocationStack] | None = None

    def __init__(
            self,
            idx: str | None = None,
            ruleId: str | None = None,
            locationId: str | None = None,
            line: int | None = None,
            code: str | None = None,
            description: str | None = None,
            status: str | None = None,
            type: str | None = None
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
