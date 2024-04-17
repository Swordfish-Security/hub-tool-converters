import json
import os
import unittest
from typing import Any

from jsonschema import validate

from config.constances import PARSER_CLASSES
from hub.parsers.hub_parser import HubParser
from main import check_keys_parser_classes


class Args:
    scanner: str
    filename: str
    output: str
    source_name: str
    source_url: str
    source_branch: str = "master"
    source_commit: str = "master"


class ParsersTest(unittest.TestCase):

    def setUp(self):
        self.args = Args()
        self.args.output = ''
        self.args.source_name = 'hub-tool-converters'
        self.args.source_url = 'https://github.com/Swordfish-Security/hub-tool-converters.git'

        self.dojo_results: dict[str, Any] = {}
        self.dojo_reports: dict[str, Any] = {}
        self.__get_dojo_reports()

    def __get_dojo_reports(self):
        for name, parser in PARSER_CLASSES.items():

            tests_filenames = os.listdir(f'./tests/{name}')
            for filename in tests_filenames:
                if '_hub' in filename:
                    continue
                self.args.filename = f'./tests/{name}/{filename}'

                self.args.scanner = name
                dojo_parser = parser()

                with open(self.args.filename, "r") as f:
                    dojo_results = dojo_parser.get_findings(f, '')
                    self.dojo_results.update({f'{name} - {filename}': dojo_results})
                hub_parser = HubParser(args=self.args, dojo_results=dojo_results)
                hub_parser.parse()

                self.dojo_reports.update({f'{name} - {filename}': hub_parser.get_report()})

    def __delete_independent_ids(self, report):

        for scan in report['scans']:
            scan['scanDetails']['id'] = None

            for source in scan['source']:
                source['id'] = None

            for result in scan['results']:
                for location in result['locations']:
                    location['sourceId'] = None

    def test_all_parsers_are_included(self):
        check_keys_parser_classes()

    def test_validating_schema(self):
        with open("./tests/hub_schema.json", 'r') as f:
            schema = json.load(f)

        for name, report in self.dojo_reports.items():
            print(f"\nValidating {name}")
            validate(report, schema)

    def test_unique_ids(self):
        for name in self.dojo_reports.keys():
            findings: list = self.dojo_reports[name]['scans'][0]['results'][0]['findings']
            self.assertEqual(len(findings), len(self.dojo_results[name]), f'{name} - {findings} != {self.dojo_results[name]}')

    def test_output_files(self):
        for name, report in self.dojo_reports.items():
            scanner, filename = name.split(' - ')
            filename = filename.replace('.json', '')
            with open(f'./tests/{scanner}/{filename}_hub.json', 'r') as f:
                output = json.load(f)

            self.__delete_independent_ids(report)
            self.__delete_independent_ids(output)

            print(f"\nComparing {name}")
            self.assertEqual(report, output)
