import base64
import hashlib
import json
import logging

from converters.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class SolidpointParser(object):
    """
    Parser for SolidPoint DAST scanner JSON reports.

    SolidPoint reports contain two sections:
      - endpoints: HTTP endpoints scanned with HAR data
      - resources: web pages/resources analyzed

    Each section contains tags with vulnerability findings.
    Only tags with type="IssueFound" are processed.
    """

    def get_scan_types(self):
        return ["SolidPoint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "SolidPoint Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import SolidPoint DAST findings in JSON format. "
            "The parser processes both 'endpoints' and 'resources' sections "
            "and extracts IssueFound tags with payloads, CWE, CVSS data."
        )

    def get_findings(self, filename, test):
        data = json.load(filename)
        items = {}

        # Process endpoints
        for endpoint in data.get("endpoints", []):
            har = endpoint.get("har", {})
            for tag in endpoint.get("tags", []):
                finding = self._parse_tag(tag, har=har)
                if finding:
                    self._merge_finding(items, finding)

        # Process resources
        for resource in data.get("resources", []):
            res_info = resource.get("resource", {})
            for tag in resource.get("tags", []):
                finding = self._parse_tag(tag, resource_info=res_info)
                if finding:
                    self._merge_finding(items, finding)

        return list(items.values())

    def _merge_finding(self, items, finding):
        """Merge or add finding using unique_id_from_tool as dedup key."""
        dupe_key = finding.unique_id_from_tool
        if dupe_key in items:
            existing = items[dupe_key]
            # Merge endpoints
            if finding.unsaved_endpoints:
                existing.unsaved_endpoints = (
                    (existing.unsaved_endpoints or []) + finding.unsaved_endpoints
                )
            # Merge request/response pairs
            if finding.unsaved_req_resp:
                existing.unsaved_req_resp = (
                    (existing.unsaved_req_resp or []) + finding.unsaved_req_resp
                )
        else:
            items[dupe_key] = finding

    def _parse_tag(self, tag, har=None, resource_info=None):
        """Parse a single tag and return a Finding if it's an IssueFound."""
        attrs = tag.get("attributes", {})

        if attrs.get("type") != "IssueFound":
            return None

        issue_name = attrs.get("issue", "Unknown Issue")
        issue_id = attrs.get("issueId", "")
        severity = self._normalize_severity(attrs.get("severity", "info"))
        analyzer = attrs.get("analyzer", "")
        module_name = attrs.get("moduleName", "")
        confidence = attrs.get("confidence", "")
        description_text = attrs.get("description", "")

        # URL from tag attributes or HAR or resource
        url = attrs.get("url", "")
        if not url and har:
            url = har.get("url", "")
        if not url and resource_info:
            url = resource_info.get("url", "")

        # HTTP method from HAR
        method = ""
        if har:
            method = har.get("method", "")

        # CWE
        cwe_list = attrs.get("cwe", [])
        cwe = 0
        if cwe_list:
            # Extract numeric CWE ID from "CWE-XXX" format
            cwe_str = cwe_list[0]
            try:
                cwe = int(cwe_str.replace("CWE-", ""))
            except (ValueError, AttributeError):
                cwe = 0

        # CVSS
        cvss_list = attrs.get("cvss", [])
        cvss3_score = None
        cvss3_vector = None
        if cvss_list:
            cvss_entry = cvss_list[0]
            cvss3_score = str(cvss_entry.get("score", ""))
            cvss3_vector = cvss_entry.get("metrics", "")

        # Build description
        description_parts = []
        if method and url:
            description_parts.append(f"**URL:** {method} {url}")
        elif url:
            description_parts.append(f"**URL:** {url}")

        if analyzer:
            description_parts.append(f"**Analyzer:** {analyzer}")
        if module_name and module_name != analyzer:
            description_parts.append(f"**Module:** {module_name}")
        if confidence:
            description_parts.append(f"**Confidence:** {confidence}")
        if description_text:
            description_parts.append(f"\n{description_text}")

        # Process payloads
        unsaved_req_resp = []
        payload_descriptions = []
        payloads = attrs.get("payloads", [])
        for payload_entry in payloads:
            # Payload details text
            details = payload_entry.get("details", "")
            if details:
                payload_descriptions.append(details)

            # Payload data
            payload_data_list = payload_entry.get("payload", [])
            for pd in payload_data_list:
                data_value = pd.get("data", "")
                if data_value:
                    payload_descriptions.append(f"**Payload:** `{data_value}`")

            # Request/Response blobs (base64 encoded)
            request_blob = payload_entry.get("request", {})
            response_blob = payload_entry.get("response", {})

            req_text = self._decode_blob(request_blob)
            resp_text = self._decode_blob(response_blob)

            if req_text or resp_text:
                unsaved_req_resp.append({
                    "req": req_text or "",
                    "resp": resp_text or ""
                })

        if payload_descriptions:
            description_parts.append("\n**Payloads:**")
            for pd in payload_descriptions:
                description_parts.append(pd)

        full_description = "\n".join(description_parts)

        # Build the Finding object
        # Build impact/mitigation from description or empty
        impact = description_text if description_text else ""
        mitigation = ""

        finding = Finding(
            title=issue_name,
            url=url,
            severity=severity,
            description=full_description,
            impact=impact,
            mitigation=mitigation,
            cwe=cwe,
            cvss3_score=cvss3_score,
            cvss3_vector=cvss3_vector,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            dynamic_finding=True,
            static_finding=False,
            unique_id_from_tool=issue_id,
            vuln_id_from_tool=issue_name,
        )

        # Set dupe_key based on issueId to prevent false deduplication
        # (e.g. multiple "HTTP Missing Security Headers" with same title/description but different issueId)
        finding.dupe_key = hashlib.md5(issue_id.encode("utf-8")).hexdigest()

        # Endpoint
        if url:
            try:
                finding.unsaved_endpoints = [Endpoint.from_uri(url)]
            except (ValueError, Exception) as e:
                logger.warning(f"Failed to parse endpoint URL '{url}': {e}")
                finding.unsaved_endpoints = []
        else:
            finding.unsaved_endpoints = []

        # Request/Response pairs
        finding.unsaved_req_resp = unsaved_req_resp

        return finding

    def _decode_blob(self, blob_obj):
        """Decode a base64 blob object to text."""
        if not blob_obj or not isinstance(blob_obj, dict):
            return ""
        blob_data = blob_obj.get("blob", "")
        blob_type = blob_obj.get("type", "")
        if not blob_data or blob_type != "blob":
            return ""
        try:
            return base64.b64decode(blob_data).decode("utf-8", "replace")
        except Exception:
            try:
                # If full decode fails, try to get at least the header
                raw = base64.b64decode(blob_data)
                parts = raw.split(b"\r\n\r\n", 1)
                header = parts[0].decode("utf-8", "replace")
                return header + "\r\n\r\n<Binary Redacted Data>"
            except Exception:
                return ""

    def _normalize_severity(self, severity):
        """Normalize SolidPoint severity to Hub-compatible format."""
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "informational": "Info",
        }
        return severity_map.get(severity.lower(), "Info")
