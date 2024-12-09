import json
import uuid
from typing import Any, Optional

from config.enums import SourceTypes, ScannerTypes
from config.constances import PARSERS_NAMES_TO_FIX
from converters.models import Finding
from hub.models.hub import ScanResult, Scan, ScanDetail, Report, FindingHubSast, FindingHubDast, FindingHubScaS
from hub.models.location import LocationSast, LocationDast, LocationSca, LocationStack
from hub.models.rule import Rule, RuleCwe, RuleSCA
from hub.models.source import SourceSast, SourceDast, SourceArtifact

import markdown


class HubParser:

    def __init__(self, args: Any, results: list[Finding]):
        self.results = results

        self.args = args
        self.__create_source()

        self.rules: dict[str, Rule] = {}
        self.locations: dict[str, LocationSast | LocationDast | LocationSca] = {}
        self.findings: dict[str, FindingHubSast | FindingHubDast] = {}

        self.output_path = args.output

        super().__init__()

    def __create_source(self):
        if self.args.type == SourceTypes.CODEBASE.value:
            self.source: SourceSast = SourceSast(
                name=self.args.name,
                url=self.args.url,
                branch=self.args.branch,
                commit=self.args.commit,
                buildTool=self.args.build_tool.lower()
            )
        elif self.args.type == SourceTypes.INSTANCE.value:
            self.source: SourceDast = SourceDast(
                name=self.args.name,
                url=self.args.url,
                stage=self.args.stage
            )
        elif self.args.type == SourceTypes.ARTIFACT.value:
            self.source: SourceArtifact = SourceArtifact(
                name=self.args.name,
                url=self.args.url
            )
        else:
            raise ValueError("Invalid source type")

    def __get_scanner_type(self, finding: Finding):
        if finding.static_finding:
            return ScannerTypes.SAST.value
        elif finding.dynamic_finding:
            return ScannerTypes.DAST.value
        return ScannerTypes.SCA_S.value

    def __parse_reqresps(self, finding: Finding):
        """
        Save request and responses in descriptions
        """
        if hasattr(finding, "unsaved_req_resp") and isinstance(finding.unsaved_req_resp, list):
            for req_resp in finding.unsaved_req_resp:
                text = ''
                if isinstance(req_resp, dict):
                    for key, value in req_resp.items():
                        text += f'\n{key}: {value}\n'
                        text = markdown.markdown(text, extensions=['nl2br']).replace('\n', '')
                self.findings[finding.dupe_key].description += text

    def __parse_finding_stacks(self, finding_stacks, location_id) -> Optional[list[LocationStack]]:
        stacks = []
        if finding_stacks:
            for finding_stack in finding_stacks:
                stacks.append(
                    LocationStack(
                        locationId=location_id,
                        sequence=finding_stack["sequence"],
                        code=finding_stack["code"],
                        line=finding_stack["line"]
                    ))
            return stacks

    def __parse_finding(self, finding: Finding):
        scanner_type = self.__get_scanner_type(finding)
        if scanner_type == ScannerTypes.SAST.value:
            finding_hub = FindingHubSast(
                idx=finding.dupe_key,
                ruleId=finding.ruleId,
                locationId=finding.file_key,
                line=finding.line,
                code=finding.code,
                description=finding.description,
                status=self.__get_status(finding),
                type=scanner_type,
                stacks=self.__parse_finding_stacks(finding.finding_stacks, finding.file_key)
            )

        elif scanner_type == ScannerTypes.DAST.value:
            finding_hub = FindingHubDast(
                idx=finding.dupe_key,
                ruleId=finding.ruleId,
                locationId=finding.file_key,
                url=finding.url,
                description=finding.description,
                status=self.__get_status(finding),
                type=scanner_type
            )
        else:
            finding_hub = FindingHubScaS(
                idx=finding.dupe_key,
                ruleId=finding.ruleId,
                locationId=finding.file_key,
                description=finding.description,
                status=self.__get_status(finding),
                type=scanner_type
            )

        # Markdown to HTML
        if finding_hub.description:
            finding_hub.description = markdown.markdown(finding_hub.description, extensions=['nl2br']).replace('\n', '')

        if finding.dupe_key not in self.findings:
            self.findings[finding.dupe_key] = finding_hub

    def __parse_location(self, finding: Finding):
        if finding.file_key not in self.locations:
            scanner_type = self.__get_scanner_type(finding)
            if scanner_type == ScannerTypes.SAST.value:
                self.locations[finding.file_key] = LocationSast(
                    type=self.args.type,
                    id=finding.file_key if finding.file_key else 'Unknown',
                    sourceId=self.source.id,
                    fileName=finding.file_path if finding.file_path else 'Unknown'
                )
            elif scanner_type == ScannerTypes.DAST.value:
                self.locations[finding.file_key] = LocationDast(
                    type=self.args.type,
                    id=finding.file_key if finding.file_key else 'Unknown',
                    sourceId=self.source.id,
                    url=finding.url if finding.url else None,
                    description=finding.description if finding.description else None
                )
            elif scanner_type == ScannerTypes.SCA_S.value:
                self.locations[finding.file_key] = LocationSca(
                    type='component',
                    id=finding.file_key if finding.file_key else 'Unknown',
                    sourceId=self.source.id,
                    componentName=finding.component_name,
                    componentVersion=finding.component_version
                )

    def __parse_rule(self, finding: Finding):
        if finding.ruleId not in self.rules:
            finding_type = self.__get_scanner_type(finding)
            if finding_type == ScannerTypes.SCA_S.value:
                self.rules[finding.ruleId] = RuleSCA(
                    type=self.__get_scanner_type(finding),
                    name=finding.ruleId,
                    severity='Low' if finding.severity == 'Info' else finding.severity,
                    description=finding.description,
                    cwe=[RuleCwe(idx=finding.cwe)] if finding.cwe else None,
                    references=finding.references,
                    cvss3_vector=finding.cvss3_vector,
                    cvss3_score=finding.cvss3_score
                )
            else:
                self.rules[finding.ruleId] = Rule(
                    type=self.__get_scanner_type(finding),
                    name=finding.ruleId,
                    severity='Low' if finding.severity == 'Info' else finding.severity,
                    description=finding.rule_description,
                    cwe=[RuleCwe(idx=finding.cwe)] if finding.cwe else None
                )
        elif finding.cwe and (not self.rules[finding.ruleId].cwe or
                              finding.cwe not in [c.id for c in self.rules[finding.ruleId].cwe]):
            if not self.rules[finding.ruleId].cwe:
                self.rules[finding.ruleId].cwe = []
            self.rules[finding.ruleId].cwe.append(RuleCwe(idx=finding.cwe))

    def __check_rule_id(self, finding: Finding):
        if not finding.ruleId:
            finding.ruleId = f"{self.args.scanner} {finding.severity}"

    def __get_status(self, finding: Finding):
        if finding.verified:
            return "Confirmed"
        elif finding.false_p:
            return "False Positive"
        elif finding.risk_accepted:
            return "Accepted risk"
        return "To Verify"

    def parse(self):
        for finding in self.results:
            finding.parse_additional_fields()

            self.__check_rule_id(finding)
            self.__parse_finding(finding)
            self.__parse_location(finding)
            self.__parse_rule(finding)
            self.__parse_reqresps(finding)
            finding.check_additional_fields()

    def get_report(self) -> dict:
        if self.args.scanner in PARSERS_NAMES_TO_FIX:
            self.args.scanner = self.args.scanner.replace("_", "-")
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
        report = report.to_dict()
        return report

    def save(self):
        with open(self.output_path, "w") as outfile:
            json.dump(self.get_report(), fp=outfile, indent=4)
