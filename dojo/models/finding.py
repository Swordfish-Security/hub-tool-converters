import datetime
from dataclasses import dataclass
from typing import Optional

import hyperlink

from dojo.models.additional import AdditionalFields


@dataclass(kw_only=False, eq=False, order=False)
class Product:
    WEB_PLATFORM = 'web'
    IOT = 'iot'
    DESKTOP_PLATFORM = 'desktop'
    MOBILE_PLATFORM = 'mobile'
    WEB_SERVICE_PLATFORM = 'web service'
    PLATFORM_CHOICES = (
        (WEB_SERVICE_PLATFORM, 'API'),
        (DESKTOP_PLATFORM, 'Desktop'),
        (IOT, 'Internet of Things'),
        (MOBILE_PLATFORM, 'Mobile'),
        (WEB_PLATFORM, 'Web'),
    )

    CONSTRUCTION = 'construction'
    PRODUCTION = 'production'
    RETIREMENT = 'retirement'
    LIFECYCLE_CHOICES = (
        (CONSTRUCTION, 'Construction'),
        (PRODUCTION, 'Production'),
        (RETIREMENT, 'Retirement'),
    )

    THIRD_PARTY_LIBRARY_ORIGIN = 'third party library'
    PURCHASED_ORIGIN = 'purchased'
    CONTRACTOR_ORIGIN = 'contractor'
    INTERNALLY_DEVELOPED_ORIGIN = 'internal'
    OPEN_SOURCE_ORIGIN = 'open source'
    OUTSOURCED_ORIGIN = 'outsourced'
    ORIGIN_CHOICES = (
        (THIRD_PARTY_LIBRARY_ORIGIN, 'Third Party Library'),
        (PURCHASED_ORIGIN, 'Purchased'),
        (CONTRACTOR_ORIGIN, 'Contractor Developed'),
        (INTERNALLY_DEVELOPED_ORIGIN, 'Internally Developed'),
        (OPEN_SOURCE_ORIGIN, 'Open Source'),
        (OUTSOURCED_ORIGIN, 'Outsourced'),
    )

    VERY_HIGH_CRITICALITY = 'very high'
    HIGH_CRITICALITY = 'high'
    MEDIUM_CRITICALITY = 'medium'
    LOW_CRITICALITY = 'low'
    VERY_LOW_CRITICALITY = 'very low'
    NONE_CRITICALITY = 'none'
    BUSINESS_CRITICALITY_CHOICES = (
        (VERY_HIGH_CRITICALITY, 'Very High'),
        (HIGH_CRITICALITY, 'High'),
        (MEDIUM_CRITICALITY, 'Medium'),
        (LOW_CRITICALITY, 'Low'),
        (VERY_LOW_CRITICALITY, 'Very Low'),
        (NONE_CRITICALITY, 'None'),
    )

    name: str | None = None
    description: str | None = None
    product_manager: str | None = None
    technical_contact: str | None = None
    team_manager: str | None = None
    created: datetime.datetime | None = None
    # prod_type: ProductType | None = None
    updated: datetime.datetime | None = None
    # sla_configuration: SLAConfiguration | None = None
    tid: int | None = None
    members: list[str] | None = None
    authorization_groups: list[str] | None = None
    prod_numeric_grade: int | None = None

    # Metadata
    business_criticality: str | None = None
    platform: str | None = None
    lifecycle: str | None = None
    origin: str | None = None
    user_records: int | None = None  # Estimate the number of user records within the application
    revenue: int | None = None  # Estimate the application's revenue
    external_audience: bool | None = None  # Specify if the application is used by people outside the organization
    internet_accessible: bool | None = None  # Specify if the application is accessible from the public internet
    # regulations: list[Regualation] | None = None
    tags: list[
              str] | None = None  # Add tags that help describe this product. Choose from the list or add new tags. Press Enter key to add
    enable_product_tag_inheritance: bool | None = None  # Enables product tag inheritance. Any tags added on a product will automatically be added to all Engagements, Tests, and Findings
    enable_simple_risk_acceptance: bool | None = None  # Allows simple risk acceptance by checking/unchecking a checkbox
    enable_full_risk_acceptance: bool | None = None  # Allows full risk acceptance using a risk acceptance form, expiration date, uploaded proof, etc
    disable_sla_breach_notifications: bool | None = None  # Disable SLA breach notifications if configured in the global settings
    async_updating: bool = False  # Findings under this Product or SLA configuration are asynchronously being updated


@dataclass(kw_only=False, eq=False, order=False)
class Endpoint:
    protocol: str | None = None  # The communication protocol/scheme such as 'http', 'ftp', 'dns', etc.
    userinfo: str | None = None  # User info as 'alice', 'bob', etc.
    host: str | None = None  # The host name or IP address. It must not include the port number. For example '127.0.0.1', 'localhost', 'yourdomain.com'.
    port: int | None = None  # The network port associated with the endpoint
    path: str | None = None  # The location of the resource, it must not start with a '/'. For example endpoint/420/edit
    query: str | None = None  # The query string, the question mark should be omitted. For example 'group=4&team=8'
    fragment: str | None = None  # The fragment identifier which follows the hash mark. The hash mark should be omitted. For example 'section-13', 'paragraph-2'.
    product: Product | None = None
    # endpoint_params: list[EndpointParams] | None = None
    findings: list['Finding'] | None = None
    tags: list[
              str] | None = None  # Add tags that help describe this endpoint. Choose from the list or add new tags. Press Enter key to add
    inherited_tags: list[
                        str] | None = None  # Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field

    @staticmethod
    def from_uri(uri):
        try:
            url = hyperlink.parse(url=uri)
        except UnicodeDecodeError:
            from urllib.parse import urlparse
            url = hyperlink.parse(url="//" + urlparse(uri).netloc)
        except hyperlink.URLParseError as e:
            raise ValueError('Invalid URL format: {}'.format(e))

        query_parts = []  # inspired by https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L1768
        for k, v in url.query:
            if v is None:
                query_parts.append(k)
            else:
                query_parts.append(u"=".join([k, v]))
        query_string = u"&".join(query_parts)

        protocol = url.scheme if url.scheme != '' else None
        userinfo = ':'.join(url.userinfo) if url.userinfo not in [(), ('',)] else None
        host = url.host if url.host != '' else None
        port = url.port
        path = '/'.join(url.path)[:500] if url.path not in [None, (), ('',)] else None
        query = query_string[:1000] if query_string is not None and query_string != '' else None
        fragment = url.fragment[:500] if url.fragment is not None and url.fragment != '' else None

        return Endpoint(
            protocol=protocol,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
        )


@dataclass(kw_only=False, eq=False, order=False)
class Finding(AdditionalFields):
    test: str | None = None
    title: str | None = None  # A short description of the flaw
    date: datetime.date | None = None  # The date the flaw was discovered
    sla_start_date: datetime.date | None = None  # (readonly)The date used as start date for SLA calculation. Set by expiring risk acceptances. Empty by default, causing a fallback to 'date'
    sla_expiration_date: datetime.date | None = None  # (readonly)The date SLA expires for this finding. Empty by default, causing a fallback to 'date'
    cwe: int = 0  # The CWE number associated with this flaw
    cve: str | None = None  # Vulnerability Id
    epss_score: float | None = None  # EPSS score for the CVE. Describes how likely it is the vulnerability will be exploited in the next 30 days
    epss_percentile: float | None = None  # EPSS percentile for the CVE. Describes how many CVEs are scored at or below this one
    cvssv3: str | None = None  # Common Vulnerability Scoring System version 3 (CVSSv3) score associated with this flaw
    cvssv3_score: float | None = None  # Numerical CVSSv3 score for the vulnerability. If the vector is given, the score is updated while saving the finding. The value must be between 0-10.
    url: str | None = None  # External reference that provides more information about this flaw
    severity: str | None = None  # The severity level of this flaw (Critical, High, Medium, Low, Informational)
    description: str | None = None  # Longer more descriptive information about the flaw
    mitigation: str | None = None  # Text describing how to best fix the flaw
    impact: str | None = None  # Text describing the impact this flaw has on systems, products, enterprise, etc
    steps_to_reproduce: str | None = None  # Text describing the steps that must be followed in order to reproduce the flaw / bug
    severity_justification: str | None = None  # Text describing why a certain severity was associated with this flaw
    endpoints: list[
                   Endpoint] | None = None  # The hosts within the product that are susceptible to this flaw. + The status of the endpoint associated with this flaw (Vulnerable, Mitigated, ...).
    references: str | None = None  # The external documentation available for this flaw
    active: bool = True  # Denotes if this flaw is active or not
    verified: bool = False  # Denotes if this flaw has been manually verified by the tester
    false_p: bool = False  # Denotes if this flaw has been deemed a false positive by the tester
    duplicate: bool = False  # Denotes if this flaw is a duplicate of other flaws reported
    duplicate_finding: Optional['Finding'] = None  # Link to the original finding if this finding is a duplicate
    out_of_scope: bool = False  # Denotes if this flaw falls outside the scope of the test and/or engagement
    risk_accepted: bool = False  # Denotes if this finding has been marked as an accepted risk
    under_review: bool = False  # Denotes is this flaw is currently being reviewed
    last_status_update: datetime.datetime | None = None  # Timestamp of latest status update (change in status related fields)
    review_requested_by: str | None = None  # Documents who requested a review for this finding
    reviewers: list[str] | None = None  # Documents who reviewed the flaw
    under_defect_review: bool = False  # Denotes if this finding is under defect review
    defect_review_requested_by: str | None = None  # Documents who requested a defect review for this flaw
    is_mitigated: bool = False  # Denotes if this flaw has been fixed
    thread_id: int = 0  # Thread ID
    mitigated: datetime.datetime | None = None  # Denotes if this flaw has been fixed by storing the date it was fixed
    mitigated_by: str | None = None  # Documents who has marked this flaw as fixed
    reporter: str | None = None  # Documents who reported the flaw
    # notes: list[Notes] | None = None  # Stores information pertinent to the flaw or the mitigation
    numerical_severity: str | None = None  # The numerical representation of the severity (S0, S1, S2, S3, S4)
    last_reviewed: datetime.datetime | None = None  # Provides the date the flaw was last 'touched' by a tester
    last_reviewed_by: str | None = None  # Provides the person who last reviewed the flaw
    # files: list[FileUpload] | None = None  # Files(s) related to the flaw
    param: str | None = None  # Parameter used to trigger the issue (DAST).
    payload: str | None = None  # Payload used to attack the service / application and trigger the bug / problem
    hash_code: str | None = None  # A hash over a configurable set of fields that is used for findings deduplication
    line: int | None = None  # Source line number of the attack vector.
    file_path: str | None = None  # Identified file(s) containing the flaw
    component_name: str | None = None  # Name of the affected component (library name, part of a system, ...).
    component_version: str | None = None  # Version of the affected component
    found_by: list[str] | None = None  # The name of the scanner that identified the flaw
    static_finding: bool = False  # Flaw has been detected from a Static Application Security Testing tool (SAST).
    dynamic_finding: bool = True  # Flaw has been detected from a Dynamic Application Security Testing tool (DAST).
    created: datetime.datetime | None = None  # The date the finding was created inside DefectDojo
    scanner_confidence: int | None = None  # Confidence level of vulnerability which is supplied by the scanner
    sonarqube_issue: str | None = None  # The SonarQube issue associated with this finding
    unique_id_from_tool: str | None = None  # Vulnerability technical id from the source tool. Allows to track unique vulnerabilities
    vuln_id_from_tool: str | None = None  # Non-unique technical id from the source tool associated with the vulnerability type
    sast_source_object: str | None = None  # Source object (variable, function...) of the attack vector
    sast_sink_object: str | None = None  # Sink object (variable, function...) of the attack vector
    sast_source_line: int | None = None  # Source line number of the attack vector
    sast_source_file_path: str | None = None  # Source file path of the attack vector
    nb_occurences: int | None = None  # Number of occurences in the source tool when several vulnerabilites were found and aggregated by the scanner
    publish_date: datetime.date | None = None  # Date when this vulnerability was made publicly available
    service: str | None = None  # A service is a self-contained piece of functionality within a Product. This is an optional field which is used in deduplication of findings when set
    planned_remediation_date: datetime.date | None = None  # The date the flaw is expected to be remediated
    planned_remediation_version: str | None = None  # The target version when the vulnerability should be fixed / remediated
    effort_for_fixing: str | None = None  # Effort for fixing / remediating the vulnerability (Low, Medium, High)
    tags: list[
              str] | None = None  # Add tags that help describe this finding. Choose from the list or add new tags. Press Enter key to add
    inherited_tags: list[
                        str] | None = None  # Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field

    SEVERITIES = {'Info': 4, 'Low': 3, 'Medium': 2,
                  'High': 1, 'Critical': 0}
