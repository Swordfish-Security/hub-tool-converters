import json

import pytest
from jsonschema import validate

from config.constances import PARSER_CLASSES
from config.enums import report_version_at_least
from converters.models import Finding
from converters.parsers.kaspersky_cs import _get_has_exploit
from hub.parsers.hub_parser import HubParser
from tests.test_parsers import ArgsArtifact, ArgsInstance

CVE = 'CVE-2024-0001'
KCS_FIXTURE = './tests/artifact/kaspersky_cs/sca-kcs-exploit.json'
BASE_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'


def _sca_finding(component: str = 'libfoo', **kwargs) -> Finding:
    return Finding(
        title=f'{component}:1.0 | {CVE}',
        description=f'description of {CVE} in {component}',
        severity='High',
        component_name=component,
        component_version='1.0',
        static_finding=False,
        dynamic_finding=False,
        vuln_id_from_tool=CVE,
        cvss3_vector=BASE_VECTOR,
        cvss3_score='9.8',
        references=[f'https://example.com/{CVE}'],
        **kwargs,
    )


def _report(findings: list[Finding], report_version: str, args=None) -> dict:
    args = args or ArgsArtifact()
    args.scanner = 'kaspersky-cs'
    args.filename = 'report.json'
    args.report_version = report_version
    parser = HubParser(args=args, results=findings)
    parser.parse()
    return parser.get_report()


def _schema() -> dict:
    with open('./tests/hub_schema.json', 'r') as f:
        return json.load(f)


def _single_rule_and_finding(report: dict) -> tuple[dict, dict]:
    result = report['scans'][0]['results'][0]
    return result['rules'][0], result['findings'][0]


def _rules_by_cve(report: dict) -> dict[str, dict]:
    return {rule['cveId']: rule for rule in report['scans'][0]['results'][0]['rules']}


def _kcs_findings() -> list[Finding]:
    with open(KCS_FIXTURE, 'r', encoding='utf-8') as f:
        return PARSER_CLASSES['kaspersky_cs']().get_findings(f, '')


# --- версия схемы и поле hasExploit в отчёте Hub ---

@pytest.mark.parametrize('version', ['1.0.1', '1.0.2'])
def test_has_exploit_is_not_emitted_for_older_schema_versions(version):
    report = _report([_sca_finding(has_exploit=True)], version)
    rule, _ = _single_rule_and_finding(report)

    assert report['version'] == version
    assert 'hasExploit' not in rule
    validate(report, _schema())


@pytest.mark.parametrize('value', [True, False])
def test_has_exploit_is_emitted_for_schema_1_0_3(value):
    # false тоже должен попасть в отчёт: фильтр Hub «by exploit = false» ищет явное значение, а не отсутствие поля
    report = _report([_sca_finding(has_exploit=value)], '1.0.3')
    rule, _ = _single_rule_and_finding(report)

    assert report['version'] == '1.0.3'
    assert rule['hasExploit'] is value
    validate(report, _schema())


def test_unset_has_exploit_is_omitted_for_schema_1_0_3():
    report = _report([_sca_finding()], '1.0.3')
    rule, _ = _single_rule_and_finding(report)

    assert 'hasExploit' not in rule
    validate(report, _schema())


def test_has_exploit_is_merged_across_findings_of_the_same_rule():
    findings = [
        _sca_finding(component='libfoo'),
        _sca_finding(component='libbar', has_exploit=True),
        _sca_finding(component='libbaz', has_exploit=False),
    ]
    report = _report(findings, '1.0.3')
    result = report['scans'][0]['results'][0]

    assert len(result['rules']) == 1
    assert result['rules'][0]['hasExploit'] is True
    assert len(result['findings']) == 3


def test_false_is_kept_when_no_finding_reports_exploit():
    report = _report([_sca_finding(component='libfoo', has_exploit=False), _sca_finding(component='libbar')], '1.0.3')
    rule, _ = _single_rule_and_finding(report)

    assert rule['hasExploit'] is False


def test_dast_http_messages_are_structured_for_schema_1_0_3():
    finding = Finding(
        title='Reflected XSS',
        description='XSS description',
        severity='High',
        url='https://app.example.com/search',
        static_finding=False,
        dynamic_finding=True,
        vuln_id_from_tool='xss-1',
    )
    finding.unsaved_req_resp = [{'req': 'GET /search HTTP/1.1\r\nHost: app.example.com\r\n\r\n',
                                 'resp': 'HTTP/1.1 200 OK\r\n\r\n<html></html>'}]
    report = _report([finding], '1.0.3', args=ArgsInstance())
    hub_finding = report['scans'][0]['results'][0]['findings'][0]

    assert hub_finding['httpRequest']['header'].startswith('GET /search')
    assert hub_finding['httpResponse']['body'] == '<html></html>'
    validate(report, _schema())


@pytest.mark.parametrize('version, minimum, expected', [
    ('1.0.3', '1.0.2', True),
    ('1.0.3', '1.0.3', True),
    ('1.0.2', '1.0.3', False),
    ('1.0.10', '1.0.3', True),  # строковое сравнение дало бы False
])
def test_report_version_at_least(version, minimum, expected):
    assert report_version_at_least(version, minimum) is expected


# --- конвертер KCS: признак эксплойта из CVSS.ExploitationInfo ---

def _exploitation_info(vector: str, key: str = 'ExploitationInfo') -> dict:
    return {'nvd': {'V3Vector': BASE_VECTOR, 'V3Score': 9.8}, key: {'V3Vector': vector, 'V3Score': 9.3}}


@pytest.mark.parametrize('cvss, expected', [
    (None, None),
    ({}, None),
    ({'nvd': {'V3Vector': BASE_VECTOR, 'V3Score': 9.8}}, None),
    ({'ExploitationInfo': {}}, None),
    ({'ExploitationInfo': None}, None),
    (_exploitation_info(BASE_VECTOR), None),               # вектор без метрики E
    (_exploitation_info(BASE_VECTOR + '/E:X'), None),      # не определено
    (_exploitation_info(BASE_VECTOR + '/E:U'), False),     # Unproven
    (_exploitation_info(BASE_VECTOR + '/E:P'), True),      # Proof-of-Concept
    (_exploitation_info(BASE_VECTOR + '/E:F'), True),      # Functional
    (_exploitation_info(BASE_VECTOR + '/E:H'), True),      # High
    (_exploitation_info(BASE_VECTOR + '/E:P/RL:O/RC:C'), True),   # E в середине вектора
    (_exploitation_info('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H'), True),  # вектор без префикса CVSS:3.x
    (_exploitation_info(BASE_VECTOR + '/E:H', key='exploitationinfo'), True),  # регистр ключа
    (_exploitation_info(BASE_VECTOR + '/RE:P'), None),     # похожий, но другой компонент
])
def test_kaspersky_cs_has_exploit(cvss, expected):
    assert _get_has_exploit(cvss) is expected


def test_kaspersky_cs_reads_vulnerabilities_from_all_results_blocks():
    findings = _kcs_findings()

    assert len(findings) == 6
    assert {f.component_name for f in findings} == {
        'libalpha', 'libbeta', 'libgamma', 'example.local/delta', 'example.local/epsilon', 'example.local/zeta'
    }
    assert {f.vuln_id_from_tool: f.has_exploit for f in findings if f.component_name != 'example.local/zeta'} == {
        'CVE-2024-10001': True, 'CVE-2024-10002': True, 'CVE-2024-10003': None,
        'CVE-2024-10004': False, 'CVE-2024-10005': None,
    }


def test_kaspersky_cs_fixture_has_exploit_in_schema_1_0_3_report():
    report = _report(_kcs_findings(), '1.0.3')
    rules = _rules_by_cve(report)

    assert rules['CVE-2024-10001']['hasExploit'] is True   # libalpha E:P; zeta без ExploitationInfo не сбрасывает
    assert rules['CVE-2024-10002']['hasExploit'] is True   # E:H
    assert 'hasExploit' not in rules['CVE-2024-10003']     # ExploitationInfo нет
    assert rules['CVE-2024-10004']['hasExploit'] is False  # E:U
    assert 'hasExploit' not in rules['CVE-2024-10005']     # вектор без метрики E
    assert len(report['scans'][0]['results'][0]['findings']) == 6
    validate(report, _schema())


def test_kaspersky_cs_fixture_report_1_0_1_has_no_has_exploit():
    report = _report(_kcs_findings(), '1.0.1')

    assert all('hasExploit' not in rule for rule in report['scans'][0]['results'][0]['rules'])
    validate(report, _schema())


# --- тип зависимости (relation) у sca_s-находки ---

def _single_finding(report: dict) -> dict:
    return report['scans'][0]['results'][0]['findings'][0]


@pytest.mark.parametrize('version', ['1.0.1', '1.0.2'])
def test_relation_is_not_emitted_for_older_schema_versions(version):
    report = _report([_sca_finding(relation='direct')], version)

    assert 'relation' not in _single_finding(report)
    validate(report, _schema())


@pytest.mark.parametrize('value, expected', [
    ('direct', 'direct'),
    ('Indirect', 'indirect'),
    ('transitive', 'indirect'),   # синоним, в Hub хранится как INDIRECT
])
def test_relation_is_emitted_for_schema_1_0_3(value, expected):
    report = _report([_sca_finding(relation=value)], '1.0.3')

    assert _single_finding(report)['relation'] == expected
    validate(report, _schema())


@pytest.mark.parametrize('value', [None, '', 'optional'])
def test_unknown_or_unset_relation_is_omitted_for_schema_1_0_3(value):
    # неизвестное значение не пишем: бэкенд отклонил бы находку целиком
    report = _report([_sca_finding(relation=value)], '1.0.3')

    assert 'relation' not in _single_finding(report)
    validate(report, _schema())


# --- KCS: отчёт «Images Detailed Report» из веб-интерфейса (images[].vulnerabilities[]) ---

KCS_IMAGES_FIXTURE = './tests/artifact/kaspersky_cs/kcs-images-detailed-report.json'


def _kcs_images_findings() -> list[Finding]:
    with open(KCS_IMAGES_FIXTURE, 'r', encoding='utf-8') as f:
        return PARSER_CLASSES['kaspersky_cs']().get_findings(f, '')


def test_kaspersky_cs_images_report_is_parsed():
    findings = {f.vuln_id_from_tool: f for f in _kcs_images_findings()}

    assert set(findings) == {'CVE-2024-1001', 'CVE-2024-1002', 'CVE-2024-1003', 'TEMP-0000001-ABCDEF'}

    critical = findings['CVE-2024-1001']
    assert (critical.component_name, critical.component_version) == ('libsample', '1.2.3-1')
    assert critical.title == 'libsample:1.2.3-1 | CVE-2024-1001'
    assert critical.severity == 'Critical'
    assert critical.has_exploit is True
    assert critical.mitigation == 'Upgrade to version 1.2.4-1'
    assert critical.references == [
        'https://nvd.nist.gov/vuln/detail/CVE-2024-1001', 'https://www.exploit-db.com/exploits/00001'
    ]
    assert (critical.date.year, critical.date.month, critical.date.day) == (2026, 10, 22)  # ДД.ММ.ГГГГ

    no_fix = findings['CVE-2024-1002']
    assert (no_fix.component_name, no_fix.component_version) == ('libother', '2:3.4.5.astra-1')
    assert no_fix.has_exploit is False
    assert no_fix.mitigation == ''

    negligible = findings['TEMP-0000001-ABCDEF']
    assert negligible.severity == 'Medium'    # Negligible нет в шкале Hub, как и в отчёте Results[]
    assert negligible.has_exploit is None     # поля exploit нет


def test_kaspersky_cs_images_report_converts_to_valid_hub_report():
    report = _report(_kcs_images_findings(), '1.0.3')
    rules = _rules_by_cve(report)
    result = report['scans'][0]['results'][0]

    assert rules['CVE-2024-1001']['hasExploit'] is True
    assert rules['CVE-2024-1002']['hasExploit'] is False
    assert 'hasExploit' not in rules['TEMP-0000001-ABCDEF']
    assert len(result['findings']) == 4
    assert len(result['locations']) == 3   # libsample встречается в двух уязвимостях
    validate(report, _schema())


def test_kaspersky_cs_images_report_1_0_1_is_valid():
    report = _report(_kcs_images_findings(), '1.0.1')

    assert all('hasExploit' not in rule for rule in report['scans'][0]['results'][0]['rules'])
    validate(report, _schema())
