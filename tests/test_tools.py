import pytest

from converters.parsers.kaspersky_cs import _get_cvssv3

TEST_CVSS_DATA = [
    {
        "bdu": {
            "V3Vector": "bdu",
            "V3Score": 1.0
        },
        "nvd": {
            "V3Vector": "nvd",
            "V3Score": 2.0
        }
    },
    {
        "ExploitationInfo": {
            "V3Vector": "ExploitationInfo",
            "V3Score": 2.0
        },
        "bdu": {
            "V3Vector": "bdu",
            "V3Score": 3.0
        }
    },
    {
        "redhat": {
            "V3Vector": "redhat",
            "V3Score": 3.0
        },
        "ExploitationInfo": {
            "V3Vector": "ExploitationInfo",
            "V3Score": 4.0
        }
    },
    {
        "ros": {
            "V3Vector": "ros",
            "V3Score": 4.0
        },
        "redhat": {
            "V3Vector": "redhat",
            "V3Score": 5.0
        }
    },
    {
        "any_source": {
            "V3Vector": "any_source",
            "V3Score": 5.0
        },
        "ros": {
            "V3Vector": "ros",
            "V3Score": 6.0
        }
    },
    {
        "any_source_1": {
            "V3Vector": "any_source_1",
            "V3Score": 6.0
        },
        "any_source_2": {
            "V3Vector": "any_source_2",
            "V3Score": 7.0
        },
        "any_source_3": {
            "V3Vector": "any_source_3",
            "V3Score": 8.0
        }
    },
    {
        "ros": {
            "V3Vector": "ros",
            "V3Score": 0.0
        },
        "any_source_1": {
            "V3Vector": "any_source_1",
            "V3Score": 9.0
        }
    },
    {
        "bdu": {
            "V3Vector": "bdu",
            "V3Score": 1.0
        },
        "nvd": {
            "V3Vector": "nvd",
            "V3Score": 0.0
        }
    },
    {
        "bdu": {
            "V3Vector": "bdu",
            "V3Score": 0.0
        },
        "nvd": {
            "V3Vector": "nvd",
            "V3Score": 0.0
        }
    },
    {
        "any_source_1": {
            "V3Vector": "any_source_1",
            "V3Score": 0.0
        },
        "any_source_2": {
            "V3Vector": "any_source_2",
            "V3Score": 0.0
        }
    },

]

TEST_EMPTY_CVSS_DATA = {}
TEST_EMPTY_CVSS_EXPECTED_RESULT = (None, None)

TEST_CVSS_EXPECTED_RESULT = [
    ("nvd", "2.0"),
    ("bdu", "3.0"),
    ("ExploitationInfo", "4.0"),
    ("redhat", "5.0"),
    ("ros", "6.0"),
    ("any_source_3", "8.0"),
    ("any_source_1", "9.0"),
    ("bdu", "1.0"),
    (None, None),
    (None, None),
]


@pytest.mark.parametrize("cvss_data, expected_result",
                         [(TEST_CVSS_DATA[0], TEST_CVSS_EXPECTED_RESULT[0]),
                          (TEST_CVSS_DATA[1], TEST_CVSS_EXPECTED_RESULT[1]),
                          (TEST_CVSS_DATA[2], TEST_CVSS_EXPECTED_RESULT[2]),
                          (TEST_CVSS_DATA[3], TEST_CVSS_EXPECTED_RESULT[3]),
                          (TEST_CVSS_DATA[4], TEST_CVSS_EXPECTED_RESULT[4]),
                          (TEST_CVSS_DATA[5], TEST_CVSS_EXPECTED_RESULT[5]),
                          (TEST_CVSS_DATA[6], TEST_CVSS_EXPECTED_RESULT[6]),
                          (TEST_CVSS_DATA[7], TEST_CVSS_EXPECTED_RESULT[7]),
                          (TEST_CVSS_DATA[8], TEST_CVSS_EXPECTED_RESULT[8]),
                          (TEST_CVSS_DATA[9], TEST_CVSS_EXPECTED_RESULT[9]),
                          (TEST_EMPTY_CVSS_DATA, TEST_EMPTY_CVSS_EXPECTED_RESULT)])
def test_kaspersky_cs_cvssv3(cvss_data, expected_result):
    assert _get_cvssv3(cvss_data) == expected_result
