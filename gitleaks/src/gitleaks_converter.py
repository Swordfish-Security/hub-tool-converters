import argparse
import hashlib
import json
import logging
import uuid
from datetime import date, time


class ScanDetails(object):
    def __init__(self, id, description):
        self.id = id
        self.description = description


class Source(object):
    def __init__(self, name, url, branch, commit):
        self.id = str(uuid.uuid4())
        self.type = "codebase"
        self.name = name
        self.url = url
        self.checkoutPath = "/"
        self.branch = branch
        self.commit = commit
        self.vcsType = "git"


class Rule(object):
    def __init__(self, name, severity, description):
        self.type = "sast"
        self.id = name
        self.name = name
        self.severity = severity
        self.cwe = [
            {"id": 798,
             "name": "Use of Hard-coded Credentials",
             "link": "https://cwe.mitre.org/data/definitions/798.html"}
        ]
        self.description = description


class Location(object):
    def __init__(self, location_id, source_id, file_name):
        self.type = "codebase"
        self.id = location_id
        self.sourceId = source_id
        self.fileName = file_name
        self.language = "Any"


class LocationStack(object):
    def __init__(self, location_id, code, line):
        self.locationId = location_id
        self.sequence = 1
        self.code = code
        self.line = line


class Finding(object):
    def __init__(self, id, rule_id, location_id, line, code, description):
        self.type = "sast"
        self.id = id
        self.ruleId = rule_id
        self.locationId = location_id
        self.line = line
        self.code = code
        self.status = "Open"
        self.description = description
        if code and line:
            self.stacks = [LocationStack(location_id, code, line)]


class ScanResult(object):
    def __init__(self, rules, locations, findings):
        self.rules = rules
        self.locations = locations
        self.findings = findings


class Scan(object):
    def __init__(self, codebase, result):
        self.scanDetails = ScanDetails(str(uuid.uuid4()), "Import GitLeaks results")
        self.source = [codebase]
        self.tool = {"product": "gitleaks"}
        self.results = [result]


class GitleaksParser(object):
    """
    A class that can be used to parse the Gitleaks JSON report files
    """

    def get_findings(self, filename, codebase, rules, locations, findings):
        with open(filename, 'r') as openfile:
            issues = json.load(openfile)
        # empty report are just null object
        if issues is None:
            return

        for issue in issues:
            if issue.get("rule"):
                self.get_finding_legacy(issue, codebase, rules, locations, findings)
            elif issue.get("Description"):
                self.get_finding_current(issue, codebase, rules, locations, findings)
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
            rules[reason] = Rule(reason, severity, title_text)

        file_key = hashlib.md5(
            file_path.encode("utf-8")
        ).hexdigest()

        if file_key not in locations:
            locations[file_key] = Location(file_key, codebase.id, file_path)

        dupe_key = hashlib.md5(
            (issue["offender"] + file_path + str(line)).encode("utf-8")
        ).hexdigest()

        finding = Finding(dupe_key, reason, file_key, line, issue["line"], description)

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
            rules[rule_id] = Rule(rule_id, severity, rule_description)

        file_key = hashlib.md5(
            file_path.encode("utf-8")
        ).hexdigest()

        if file_key not in locations:
            locations[file_key] = Location(file_key, codebase.id, file_path)

        dupe_key = hashlib.md5(
            (title + secret + str(line)).encode("utf-8")
        ).hexdigest()

        finding = Finding(dupe_key, rule_id, file_key, line, secret, description)

        if dupe_key not in findings:
            findings[dupe_key] = finding


def serialize(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, date):
        serial = obj.isoformat()
        return serial

    if isinstance(obj, time):
        serial = obj.isoformat()
        return serial

    return obj.__dict__


# Пример запуска
# python gitleaks_converter.py -gitLeaksReport gitleaks8_many.json -hubReport hub.json
# -sourceName maven-repository-master -sourceUrl https://gitlab.service.swordfishsecurity.com/open/maven-repository.git
# -sourceBranch master -sourceCommit master
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("-gitLeaksReport", help="path to input Gitleaks report", type=str)
    parser.add_argument("-hubReport", help="path to output Hub report", type=str)
    parser.add_argument("-sourceName", help="name of the repository", type=str)
    parser.add_argument("-sourceUrl", help="URL of the repository", type=str)
    parser.add_argument("-sourceBranch", help="repository branch", type=str)
    parser.add_argument("-sourceCommit", help="repository commit", type=str)
    args = parser.parse_args()
    if not args.gitLeaksReport or not args.hubReport:
        parser.print_help()
        exit(0)
    source = Source(args.sourceName, args.sourceUrl, args.sourceBranch, args.sourceCommit)
    rules = {}
    locations = {}
    findings = {}
    parser = GitleaksParser()
    parser.get_findings(args.gitLeaksReport, source, rules, locations, findings)
    scanResult = ScanResult(list(rules.values()), list(locations.values()), list(findings.values()))
    scan = Scan(source, scanResult)
    report = {
        "$schema": "https://docs.appsec-hub.ru/",
        "version": "1.0.1",
        "scans": [scan]
    }
    with open(args.hubReport, "w") as outfile:
        json.dump(report, fp=outfile, default=serialize, indent=4)
