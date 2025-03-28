import json
import logging
import re
import textwrap

from converters.models import Finding

logger = logging.getLogger(__name__)

CWE_REGEX = r"cwe-\d+"


class SarifParser(object):
    """OASIS Static Analysis Results Interchange Format (SARIF) for version 2.1.0 only.

    https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif
    """

    def get_scan_types(self):
        return ["SARIF"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "SARIF report file can be imported in SARIF format."

    def get_findings(self, filehandle, test):
        """For simple interface of parser contract we just aggregate everything"""
        tree = json.load(filehandle)
        items = list()
        # for each runs we just aggregate everything
        for run in tree.get("runs", list()):
            items.extend(self.__get_items_from_run(run))
        return items

    def __get_items_from_run(self, run):
        items = list()
        # load rules
        rules = get_rules(run)
        artifacts = get_artifacts(run)
        # get the timestamp of the run if possible
        run_date = self.__get_last_invocation_date(run)
        for result in run.get("results", list()):
            item = get_item(result, rules, artifacts, run_date)
            if item is not None:
                items.extend(item)
        return items

    def __get_last_invocation_date(self, data):
        invocations = data.get("invocations", [])
        if len(invocations) == 0:
            return None
        # try to get the last 'endTimeUtc'
        raw_date = invocations[-1].get("endTimeUtc")
        if raw_date is None:
            return None

        # if the data is here we try to convert it to datetime
        return raw_date


def get_rules(run):
    rules = {}
    rules_array = run["tool"]["driver"].get("rules", [])
    if len(rules_array) == 0 and run["tool"].get("extensions") is not None:
        rules_array = run["tool"]["extensions"][0].get("rules", [])
    for item in rules_array:
        rules[item["id"]] = item
    return rules


# Rules and results have de sames scheme for tags
def get_properties_tags(value):
    if not value:
        return []
    return value.get("properties", {}).get("tags", [])


def search_cwe(value, cwes):
    matches = re.search(CWE_REGEX, value, re.IGNORECASE)
    if matches:
        cwes.append(int(matches[0].split("-")[1]))


def get_rule_cwes(rule):
    cwes = []
    # data of the specification
    if "relationships" in rule and isinstance(rule["relationships"], list):
        for relationship in rule["relationships"]:
            value = relationship["target"]["id"]
            search_cwe(value, cwes)
        return cwes

    for tag in get_properties_tags(rule):
        search_cwe(tag, cwes)
    return cwes


def get_result_cwes_properties(result):
    """Some tools like njsscan store the CWE in the properties of the result"""
    cwes = []
    if "properties" in result and "cwe" in result["properties"]:
        value = result["properties"]["cwe"]
        search_cwe(value, cwes)
    return cwes


def get_artifacts(run):
    artifacts = {}
    custom_index = 0  # hack because some tool doesn't generate this attribute
    for tree_artifact in run.get("artifacts", []):
        artifacts[tree_artifact.get("index", custom_index)] = tree_artifact
        custom_index += 1
    return artifacts


def get_message_from_multiformatMessageString(data, rule):
    """Get a message from multimessage struct

    See here for the specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317468
    """
    if rule is not None and "id" in data:
        text = rule["messageStrings"][data["id"]].get("text")
        arguments = data.get("arguments", [])
        # argument substitution
        for i in range(6):  # the specification limit to 6
            substitution_str = "{" + str(i) + "}"
            if substitution_str in text:
                text = text.replace(substitution_str, arguments[i])
            else:
                return text
    else:
        # TODO manage markdown
        return data.get("text")


def cve_try(val):
    # Match only the first CVE!
    cveSearch = re.search("(CVE-[0-9]+-[0-9]+)", val, re.IGNORECASE)
    if cveSearch:
        return cveSearch.group(1).upper()
    else:
        return None


def get_rule_description(result, rule):
    rule_description = ""
    references = ""
    if result.get("message") and result.get("message").get("text"):
        rule_description = result["message"]["text"]
    if result.get("properties") and result.get("properties").get("reference"):
        references = f"\n{result['properties']['reference']}"
    if not rule_description and rule.get("name"):
        rule_description = rule["name"]
    if not references and rule:
        if rule.get("helpUri"):
            references = f"\n{rule['helpUri']}"
    return f"{rule_description}{references}"


def get_title(result, rule):
    title = None
    if "message" in result:
        title = get_message_from_multiformatMessageString(
            result["message"], rule
        )
    if title is None and rule is not None:
        if "shortDescription" in rule:
            title = get_message_from_multiformatMessageString(
                rule["shortDescription"], rule
            )
        elif "fullDescription" in rule:
            title = get_message_from_multiformatMessageString(
                rule["fullDescription"], rule
            )
        elif "name" in rule:
            title = rule["name"]
        elif "id" in rule:
            title = rule["id"]

    if title is None:
        raise ValueError("No information found to create a title")

    return textwrap.shorten(title, 150)


def get_snippet(result, location_number):
    snippet = None
    if "locations" in result:
        location = result["locations"][location_number]
        if "physicalLocation" in location:
            if "region" in location["physicalLocation"]:
                if "snippet" in location["physicalLocation"]["region"]:
                    if (
                        "text"
                        in location["physicalLocation"]["region"]["snippet"]
                    ):
                        snippet = location["physicalLocation"]["region"][
                            "snippet"
                        ]["text"]
            if (
                snippet is None
                and "contextRegion" in location["physicalLocation"]
            ):
                if "snippet" in location["physicalLocation"]["contextRegion"]:
                    if (
                        "text"
                        in location["physicalLocation"]["contextRegion"][
                            "snippet"
                        ]
                    ):
                        snippet = location["physicalLocation"][
                            "contextRegion"
                        ]["snippet"]["text"]
    return snippet


def get_codeFlowsDescription(codeFlows):
    description = ""
    for codeFlow in codeFlows:
        for threadFlow in codeFlow.get('threadFlows', []):
            if "locations" not in threadFlow:
                continue

            description = "**Code flow:**\n"
            line = 1

            for location in threadFlow.get('locations', []):
                physicalLocation = location.get('location', {}).get('physicalLocation', {})
                region = physicalLocation.get("region", {})
                uri = physicalLocation.get("artifactLocation").get("uri")

                start_line = ""
                start_column = ""
                snippet = ""

                if "startLine" in region:
                    start_line = f":L{str(region.get('startLine'))}"

                if "startColumn" in region:
                    start_column = f":C{str(region.get('startColumn'))}"

                if "snippet" in region:
                    snippet = f"\t-\t{region.get('snippet').get('text')}"

                description += f"{line}. {uri}{start_line}{start_column}{snippet}\n"

                if 'message' in location.get('location', {}):
                    message_field = location.get('location', {}).get('message', {})
                    if 'markdown' in message_field:
                        message = message_field.get('markdown', '')
                    else:
                        message = message_field.get('text', '')

                    description += f"\t{message}\n"

                line += 1

    return description


def get_description(result, rule, location_number):
    description = ""
    message = ""
    if "message" in result:
        message = get_message_from_multiformatMessageString(
            result["message"], rule
        )
        description += "**Result message:** {}\n".format(message)
    if (snippet := get_snippet(result, location_number)) is not None:
        description += "**Snippet:**\n```{}```\n".format(snippet)
    if rule is not None:
        if "name" in rule and rule.get("name"):
            description += f"**Rule name:** {rule.get('name')}\n"
        shortDescription = ""
        if "shortDescription" in rule:
            shortDescription = get_message_from_multiformatMessageString(
                rule["shortDescription"], rule
            )
            if shortDescription != message:
                description += f"**Rule short description:** {shortDescription}\n"
        if "fullDescription" in rule:
            fullDescription = get_message_from_multiformatMessageString(
                rule["fullDescription"], rule
            )
            if (
                fullDescription != message
                and fullDescription != shortDescription
            ):
                description += f"**Rule full description:** {fullDescription}\n"

    if len(result.get("codeFlows", [])) > 0:
        description += get_codeFlowsDescription(result["codeFlows"])

    if description.endswith("\n"):
        description = description[:-1]

    return description


def get_references(rule):
    reference = None
    if rule is not None:
        if "helpUri" in rule:
            reference = rule["helpUri"]
        elif "help" in rule:
            helpText = get_message_from_multiformatMessageString(
                rule["help"], rule
            )
            if helpText and helpText.startswith("http"):
                reference = helpText

    return reference


def cvss_to_severity(cvss):
    severity_mapping = {
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    if cvss >= 9:
        return severity_mapping.get(5)
    elif cvss >= 7:
        return severity_mapping.get(4)
    elif cvss >= 4:
        return severity_mapping.get(3)
    elif cvss > 0:
        return severity_mapping.get(2)
    else:
        return severity_mapping.get(1)


def get_severity(result, rule):
    severity = result.get("level")
    if severity is None and rule is not None:
        # get the severity from the rule
        if "defaultConfiguration" in rule:
            severity = rule["defaultConfiguration"].get("level")

    if "note" == severity:
        return "Info"
    elif "warning" == severity:
        return "Medium"
    elif "error" == severity:
        return "High"
    else:
        return "Medium"


def get_item(result, rules, artifacts, run_date):
    findings = []
    # see
    # https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html
    # / 3.27.9
    kind = result.get("kind", "fail")
    if kind != "fail":
        return None

    # if finding is suppressed, mark it as False Positive
    # Note: see
    # https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html#_Toc10127852
    suppressed = False
    if result.get("suppressions"):
        suppressed = True

    # if there is a location get it
    file_path = None
    line = None
    location_number = 0
    locations = result.get("locations", [])

    for location in locations:
        if "physicalLocation" in location:
            file_path = location["physicalLocation"]["artifactLocation"]["uri"]

            # 'region' attribute is optionnal
            if "region" in location["physicalLocation"]:
                # https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html / 3.30.1
                # need to check whether it is byteOffset
                if "byteOffset" in location["physicalLocation"]["region"]:
                    pass
                else:
                    line = location["physicalLocation"]["region"]["startLine"]

        # test rule link
        rule = rules.get(result.get("ruleId"))

        finding = Finding(
            title=get_title(result, rule),
            severity=get_severity(result, rule),
            description=get_description(result, rule, location_number),
            static_finding=True,  # by definition
            dynamic_finding=False,  # by definition
            false_p=suppressed,
            active=not suppressed,
            file_path=file_path,
            line=line,
            references=get_references(rule),
            rule_description=get_rule_description(result, rule)
        )

        location_number += 1

        if "ruleId" in result:
            finding.vuln_id_from_tool = result["ruleId"]
            # for now we only support when the id of the rule is a CVE
            if cve_try(result["ruleId"]):
                finding.unsaved_vulnerability_ids = [cve_try(result["ruleId"])]
        # some time the rule id is here but the tool doesn't define it
        if rule is not None:
            cwes_extracted = get_rule_cwes(rule)
            if len(cwes_extracted) > 0:
                finding.cwe = cwes_extracted[-1]

            # Some tools such as GitHub or Grype return the severity in properties
            # instead
            if "properties" in rule and "security-severity" in rule["properties"]:
                cvss = float(rule["properties"]["security-severity"])
                severity = cvss_to_severity(cvss)
                finding.cvssv3_score = cvss
                finding.severity = severity

        # manage the case that some tools produce CWE as properties of the result
        cwes_properties_extracted = get_result_cwes_properties(result)
        if len(cwes_properties_extracted) > 0:
            finding.cwe = cwes_properties_extracted[-1]

        # manage fixes provided in the report
        if "fixes" in result:
            finding.mitigation = "\n".join(
                [fix.get("description", {}).get("text") for fix in result["fixes"]]
            )

        if run_date:
            finding.date = run_date

        # manage tags provided in the report and rule and remove duplicated
        tags = list(set(get_properties_tags(rule) + get_properties_tags(result)))
        tags = [s.removeprefix('external/cwe/') for s in tags]
        finding.tags = tags

        # manage fingerprints
        # fingerprinting in SARIF is more complete than in current implementation
        # SARIF standard make it possible to have multiple version in the same report
        # for now we just take the first one and keep the format to be able to
        # compare it
        if result.get("fingerprints"):
            hashes = get_fingerprints_hashes(result["fingerprints"])
            first_item = next(iter(hashes.items()))
            finding.unique_id_from_tool = first_item[1]["value"]
        elif result.get("partialFingerprints"):
            # for this one we keep an order to have id that could be compared
            hashes = get_fingerprints_hashes(result["partialFingerprints"])
            sorted_hashes = sorted(hashes.keys())
            finding.unique_id_from_tool = "|".join(
                [f'{key}:{hashes[key]["value"]}' for key in sorted_hashes]
            )
        findings.append(finding)
    return findings


def get_fingerprints_hashes(values):
    """
    Method that generate a `unique_id_from_tool` data from the `fingerprints` attribute.
     - for now, we take the value of the last version of the first hash method.
    """
    fingerprints = dict()
    for key in values:
        if "/" in key:
            key_method = key.split("/")[-2]
            key_method_version = int(key.split("/")[-1].replace("v", ""))
        else:
            key_method = key
            key_method_version = 0
        value = values[key]
        if fingerprints.get(key_method):
            if fingerprints[key_method]["version"] < key_method_version:
                fingerprints[key_method] = {
                    "version": key_method_version,
                    "value": value,
                }
        else:
            fingerprints[key_method] = {
                "version": key_method_version,
                "value": value,
            }
    return fingerprints
