import json
import uuid
from typing import Any

from config.enums import SourceTypes, ScannerTypes
from dojo.models import Finding
from hub.models.hub import ScanResult, Scan, ScanDetail, Report, FindingHub
from hub.models.location import Location
from hub.models.rule import Rule, RuleCwe
from hub.models.source import Source


class HubParser:

    def __init__(self, args: Any, dojo_results: list[Finding]):
        self.dojo_results = dojo_results

        source_type = self.__get_source_type()

        self.args = args

        self.source: Source = Source(
            name=args.source_name,
            url=args.source_url,
            branch=args.source_branch,
            commit=args.source_commit,
            type=source_type
        )
        self.rules: dict[str, Rule] = {}
        self.locations: dict[str, Location] = {}
        self.findings: dict[str, FindingHub] = {}

        self.output_path = args.output

        super().__init__()

    def __get_source_type(self):
        # TODO: Add parsing
        return SourceTypes.CODE.value

    def __get_scanner_type(self, finding: Finding):
        if finding.static_finding:
            return ScannerTypes.SAST.value
        elif finding.dynamic_finding:
            return ScannerTypes.DAST.value
        return ScannerTypes.SCA.value

    def __parse_finding(self, finding: Finding):

        scanner_type = self.__get_scanner_type(finding)

        finding_hub = FindingHub(
            idx=finding.dupe_key,
            ruleId=finding.ruleId,
            locationId=finding.file_key,
            line=finding.line,
            code=finding.secret,
            description=finding.description,
            status="Open",
            type=scanner_type
        )

        if finding.dupe_key not in self.findings:
            self.findings[finding.dupe_key] = finding_hub

    def __parse_location(self, finding: Finding):
        if finding.file_key not in self.locations:
            self.locations[finding.file_key] = Location(
                type=self.__get_source_type(),
                id=finding.file_key,
                sourceId=self.source.id,
                fileName=finding.file_path
            )

    def __parse_rule(self, finding: Finding):
        if finding.ruleId not in self.rules:
            self.rules[finding.ruleId] = Rule(
                type=ScannerTypes.SAST.value,
                name=finding.ruleId,
                severity=finding.severity,
                description=finding.rule_description,
                cwe=[RuleCwe(id=finding.cwe)] if finding.cwe else None
            )
        elif finding.cwe and (not self.rules[finding.ruleId].cwe or
                              finding.cwe not in [c.id for c in self.rules[finding.ruleId].cwe]):
            if not self.rules[finding.ruleId].cwe:
                self.rules[finding.ruleId].cwe = []
            self.rules[finding.ruleId].cwe.append(RuleCwe(id=finding.cwe))

    def parse(self):
        for finding in self.dojo_results:
            finding.parse_additional_fields()
            finding.check_additional_fields()

            self.__parse_finding(finding)
            self.__parse_location(finding)
            self.__parse_rule(finding)

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

    def save(self):
        with open(self.output_path, "w") as outfile:
            json.dump(self.get_report(), fp=outfile, indent=4)
