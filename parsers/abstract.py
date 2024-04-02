import json
import uuid
from abc import ABC, abstractmethod
from typing import Any

from config.enums import SourceTypes
from models.finding import FindingOwn
from models.hub import ScanResult, Scan, ScanDetail, Report
from models.location import Location
from models.rule import Rule
from models.source import Source


class BasicParser(ABC):

    def __init__(self, args: Any):

        self.args = args
        self.source: Source = Source(
            name=args.source_name,
            url=args.source_url,
            branch=args.source_branch,
            commit=args.source_commit,
            type=SourceTypes.CODE.value
        )
        self.rules: dict[str, Rule] = {}
        self.locations: dict[str, Location] = {}
        self.findings: dict[str, FindingOwn] = {}

        self.output_path = args.output
        super().__init__()

    @abstractmethod
    def parse(self, *args: Any, **kwargs: Any) -> Any:
        pass

    def get_report(self) -> dict:
        scan_result = ScanResult(
            rules=list(self.rules.values()),
            locations=list(self.locations.values()),
            findings=list(self.findings.values())
        )
        scan = Scan(
            scanDetails=ScanDetail(
                id=str(uuid.uuid4()),
                description=f"Import {self.args.scanner} results"
            ),
            source=[self.source],
            results=[scan_result],
            tool={'product': f"{self.args.scanner}"}
        )
        report = Report(
            scans=[scan]
        )
        return report.to_dict()

    def save_report(self):
        with open(self.output_path, "w") as outfile:
            json.dump(self.get_report(), fp=outfile, indent=4)

