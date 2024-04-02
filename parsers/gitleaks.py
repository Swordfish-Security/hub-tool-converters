import hashlib
import json
from typing import TextIO

from models.finding import FindingOwn
from models.location import Location
from models.rule import Rule
from parsers import BasicParser
from config.enums import ScannerTypes, SourceTypes


class GitleaksParser(BasicParser):
    """
    A class that can be used to parse the Gitleaks JSON report files
    """

    def parse(
            self,
            filename: TextIO,
    ):
        """
        Converts a Gitleaks report to DefectDojo findings
        """
        issues = json.load(filename)
        # empty report are just null object
        if issues is None:
            return list()

        for issue in issues:
            if issue.get("rule"):
                self.get_finding_legacy(
                    issue,
                    self.source,
                    self.rules,
                    self.locations,
                    self.findings
                )
            elif issue.get("Description"):
                self.get_finding_current(
                    issue,
                    self.source,
                    self.rules,
                    self.locations,
                    self.findings
                )
            else:
                raise ValueError("Format is not recognized for Gitleaks")

    def get_finding_legacy(self, issue, codebase, rules, locations, findings):
        line = None
        file_path = issue["file"]
        reason = issue["rule"]
        title_text = "Hard Coded " + reason
        description = (
                "**Commit:** " + issue["commitMessage"].rstrip("\n") + "\n"
        )
        description += "**Commit Hash:** " + issue["commit"] + "\n"
        description += "**Commit Date:** " + issue["date"] + "\n"
        description += (
                "**Author:** "
                + issue["author"]
                + " <"
                + issue["email"]
                + ">"
                + "\n"
        )
        description += "**Reason:** " + reason + "\n"
        description += "**Path:** " + file_path + "\n"
        if "lineNumber" in issue:
            description += "**Line:** %i\n" % issue["lineNumber"]
            line = issue["lineNumber"]
        if "operation" in issue:
            description += "**Operation:** " + issue["operation"] + "\n"
        if "leakURL" in issue:
            description += (
                    "**Leak URL:** ["
                    + issue["leakURL"]
                    + "]("
                    + issue["leakURL"]
                    + ")\n"
            )
        description += (
                "\n**String Found:**\n\n```\n"
                + issue["line"].replace(issue["offender"], "REDACTED")
                + "\n```"
        )

        severity = "High"
        if "Github" in reason or "AWS" in reason or "Heroku" in reason:
            severity = "Critical"

        if reason not in rules:
            rules[reason] = Rule(
                type=ScannerTypes.SAST.value,
                name=reason,
                severity=severity,
                description=title_text
            )

        file_key = hashlib.md5(
            file_path.encode('utf-8')
        ).hexdigest()

        if file_key not in locations:
            locations[file_key] = Location(
                type=SourceTypes.CODE.value,
                id=file_key,
                sourceId=codebase.id,
                fileName=file_path
            )

        dupe_key = hashlib.sha256(
            (issue["offender"] + file_path + str(line)).encode("utf-8")
        ).hexdigest()

        finding = FindingOwn(
            idx=dupe_key,
            ruleId=reason,
            locationId=file_key,
            line=line,
            code=issue['line'],
            description=description,
            status="Open",
            type=ScannerTypes.SAST.value
        )

        if dupe_key not in findings:
            findings[dupe_key] = finding

    def get_finding_current(self, issue, codebase, rules, locations, findings):
        reason = issue.get("Description")
        line = issue.get("StartLine")
        if line:
            line = int(line)
        else:
            line = 0
        match = issue.get("Match")
        secret = issue.get("Secret")
        file_path = issue.get("File")
        commit = issue.get("Commit")
        date = issue.get("Date")
        message = issue.get("Message")
        rule_id = issue.get("RuleID")

        title = f"Hard coded {reason} found in {file_path}"
        rule_description = f"Hard coded {reason}"

        description = ""
        if secret:
            description += f"**Secret:** {secret}\n"
        if match:
            description += f"**Match:** {match}\n"
        if message:
            if len(message.split("\n")) > 1:
                description += (
                        "**Commit message:**"
                        + "\n```\n"
                        + message.replace("```", "\\`\\`\\`")
                        + "\n```\n"
                )
            else:
                description += f"**Commit message:** {message}\n"
        if commit:
            description += f"**Commit hash:** {commit}\n"
        if date:
            description += f"**Commit date:** {date}\n"
        if rule_id:
            description += f"**Rule Id:** {rule_id}"
        if description[-1] == "\n":
            description = description[:-1]

        severity = "High"

        if rule_id not in rules:
            rules[rule_id] = Rule(
                type=ScannerTypes.SAST.value,
                name=rule_id,
                severity=severity,
                description=rule_description
            )

        file_key = hashlib.md5(
            file_path.encode('utf-8')
        ).hexdigest()

        if file_key not in locations:
            locations[file_key] = Location(
                type=SourceTypes.CODE.value,
                id=file_key,
                sourceId=codebase.id,
                fileName=file_path
            )

        dupe_key = hashlib.md5(
            (title + secret + str(line)).encode("utf-8")
        ).hexdigest()

        finding = FindingOwn(
            idx=dupe_key,
            ruleId=rule_id,
            locationId=file_key,
            line=line,
            code=secret,
            description=description,
            status="Open",
            type=ScannerTypes.SAST.value
        )

        if dupe_key not in findings:
            findings[dupe_key] = finding
