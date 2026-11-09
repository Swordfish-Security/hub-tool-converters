import dateutil.parser
import json
import logging
import re

from converters.models import Finding

from cvss import CVSS3

LOGGER = logging.getLogger(__name__)


def _get_cvssv3(cvss_dict: dict):
    """Extracts and returns a CVSS3 object from a CVSS dictionary.
    This function sorts the dictionary by the V3Score value in descending order and searches for elements
    that match the priority keys. If an element with a V3Score is found, it is returned as a tuple
    containing the CVSS vector and the V3Score value."""

    priority_order_keys = ["nvd", "bdu", "exploitationinfo", "redhat", "ros"]
    sorted_cvss_dict = dict(sorted(cvss_dict.items(), key=lambda item: item[1].get("V3Score", 0.0), reverse=True))
    if cvss_dict:
        for priority_key in priority_order_keys:
            for key in cvss_dict.keys():
                if key.lower().startswith(priority_key):
                    if cvss_dict[key].get("V3Score") and cvss_dict[key].get("V3Vector"):
                        return cvss_dict[key]["V3Vector"], str(cvss_dict[key]["V3Score"])
                    else:
                        sorted_cvss_dict.pop(key)
        if sorted_cvss_dict:
            greater_cvss = next(iter(sorted_cvss_dict))
            score = str(sorted_cvss_dict[greater_cvss].get("V3Score")) if sorted_cvss_dict[greater_cvss].get("V3Score") else None
            vector = sorted_cvss_dict[greater_cvss].get("V3Vector") if score else None
            return vector, score
    return None, None


def _get_cwes_id(cwes: list):
    return [int(cwe.split("-")[1]) for cwe in cwes]


def _fix_severity(severity):
    possible_severities = ["Low", "Medium", "High", "Critical"]
    severity = severity.capitalize() if isinstance(severity, str) else None
    if severity is None or severity not in possible_severities:
        severity = "Medium"
    return severity

_EXPLOIT_CODE_MATURITY = re.compile(r"(?:^|/)E:([XUPFH])(?=/|$)")
_EXPLOIT_EXISTS = {"P", "F", "H"}

def _get_has_exploit(cvss_dict) -> bool | None:
    if not isinstance(cvss_dict, dict):
        return None
    exploitation_info = next(
        (value for key, value in cvss_dict.items() if key.lower() == "exploitationinfo"), None
    )
    if not isinstance(exploitation_info, dict):
        return None
    match = _EXPLOIT_CODE_MATURITY.search(exploitation_info.get("V3Vector") or "")
    if not match or match.group(1) == "X":
        return None
    return match.group(1) in _EXPLOIT_EXISTS


_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_NO_VENDOR_FIX = {"", "-"}


def _parse_report_date(value):
    """Дата отчёта KCS: ISO в выгрузке через API, «ДД.ММ.ГГГГ, ЧЧ:ММ:СС» в выгрузке из веб-интерфейса."""
    if not value:
        return None
    try:
        return dateutil.parser.parse(value, dayfirst=not _ISO_DATE.match(value))
    except (ValueError, OverflowError):
        LOGGER.warning(f"unsupported report date format: {value}")
        return None


def _split_resource(resource):
    """«<пакет> <версия>» из поля resource отчёта Images Detailed Report."""
    parts = (resource or "").strip().split(" ", 1)
    name = parts[0] or None
    version = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
    return name, version


class KasperskyCSJSONParser:
    def _get_findings_json(self, file, test):
        """Load a KasperskyCS file in JSON format"""
        data = json.load(file)
        if isinstance(data, dict) and isinstance(data.get("images"), list):
            return self._get_findings_images_report(data, test)
        return self._get_findings_scan_report(data, test)

    def _get_findings_images_report(self, data, test):
        """Отчёт «Images Detailed Report» из веб-интерфейса KCS 2.x: images[].vulnerabilities[]."""
        findings = []
        for image in data.get("images") or []:
            report_date = _parse_report_date(image.get("scanDate")) or _parse_report_date(data.get("generatedAt"))
            for vulnerability in image.get("vulnerabilities") or []:
                vulnerability_id = vulnerability.get("name")
                component_name, component_version = _split_resource(vulnerability.get("resource"))
                vendor_fix = (vulnerability.get("vendorFix") or "").strip()
                references = [link.get("link") for link in vulnerability.get("dbLinks") or [] if link.get("link")]
                exploit = vulnerability.get("exploit")

                description = f"**Resource:** {vulnerability.get('resource')}"
                if vendor_fix not in _NO_VENDOR_FIX:
                    description += f"\n**Fixed version:** {vendor_fix}"

                finding = Finding(
                    title=f"{component_name}:{component_version} | {vulnerability_id}",
                    test=test,
                    description=description,
                    severity=_fix_severity(vulnerability.get("severity")),
                    mitigation=f"Upgrade to version {vendor_fix}" if vendor_fix not in _NO_VENDOR_FIX else "",
                    component_name=component_name,
                    component_version=component_version,
                    references=references,
                    static_finding=False,
                    dynamic_finding=False,
                    vuln_id_from_tool=vulnerability_id,
                    has_exploit=exploit if isinstance(exploit, bool) else None
                )
                if report_date:
                    finding.date = report_date
                findings.append(finding)
        return findings

    def _get_findings_scan_report(self, data, test):
        """Отчёт сканирования KCS в формате Results[] (выгрузка через API / CLI)."""
        # Отчёт KCS содержит несколько блоков результатов (пакеты ОС, языковые пакеты, лицензии...);
        # уязвимости читаются из всех блоков, где они есть.
        results_blocks = data.get("Results") or []

        report_date = None
        if data.get("ScanFinishedAt"):
            report_date = dateutil.parser.parse(
                data.get("ScanFinishedAt")
            )

        findings = []
        for results in results_blocks:
            for vulnerability in results.get("Vulnerabilities") or []:
                title = f"{vulnerability.get('PkgName')}:{vulnerability.get('InstalledVersion')} | {vulnerability.get('lnerabilityID')}"
                description = vulnerability.get("Description")

                severity = _fix_severity(vulnerability.get("Severity"))

                if not description:
                    description = "Description was not provided."

                cvss3_vector, cvss3_score = _get_cvssv3(vulnerability.get("CVSS"))

                finding = Finding(
                    title=title,
                    test=test,
                    description=description,
                    severity=severity,
                    mitigation="",  # todo add if necessary
                    component_name=vulnerability.get("PkgName"),
                    component_version=vulnerability.get("InstalledVersion"),
                    references=vulnerability.get("References"),
                    static_finding=False,
                    dynamic_finding=False,
                    vuln_id_from_tool=vulnerability.get("VulnerabilityID"),
                    cvss3_vector=cvss3_vector,
                    cvss3_score=cvss3_score,
                    has_exploit=_get_has_exploit(vulnerability.get("CVSS"))
                )

                if report_date:
                    finding.date = report_date

                vulnerability_ids = []

                if vulnerability.get("VulnerabilityID"):
                    vulnerability_ids.append(vulnerability.get("VulnerabilityID"))

                cwes = _get_cwes_id(vulnerability.get("CweIDs"))
                if cwes and len(cwes) > 1:
                    # FIXME support more than one CWE
                    LOGGER.debug(
                        f"more than one CWE for a finding {cwes}. NOT supported by parser API"
                    )
                if cwes and len(cwes) > 0:
                    finding.cwe = cwes[0]
                findings.append(finding)
        return findings


class KasperskyCSParser:
    def get_scan_types(self):
        return ["KasperskyCS Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "KasperskyCS Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Support KasperskyCS JSON report formats."

    def get_findings(self, file, test):
        if file.name.strip().lower().endswith(".json"):
            return KasperskyCSJSONParser()._get_findings_json(file, test)
