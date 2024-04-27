import json
import os
import unittest
from typing import Any

from jsonschema import validate

from config.constances import PARSER_CLASSES, TOOL_FORMAT
from config.enums import SourceTypes, Stage
from hub.parsers.hub_parser import HubParser
from main import check_keys_parser_classes


class ArgsBase:
    type: SourceTypes
    scanner: str
    filename: str
    output: str = ''
    name: str = 'hub-tool-converters'
    url: str = 'https://github.com/Swordfish-Security/hub-tool-converters.git'


class ArgsCodebase(ArgsBase):
    type = SourceTypes.CODEBASE.value
    branch: str = "master"
    commit: str = "master"


class ArgsInstance(ArgsBase):
    type = SourceTypes.INSTANCE.value
    stage: Stage.ST = Stage.ST.value


class ParsersTest(unittest.TestCase):

    def setUp(self):
        self.dojo_results: dict[str, Any] = {}
        self.dojo_reports: dict[str, Any] = {}

        self.args_codebase = ArgsCodebase()
        self.__test(self.args_codebase)

        self.args_instance = ArgsInstance()
        self.__test(self.args_instance)

        self.args = (self.args_instance, self.args_codebase)

    def __test(self, args):
        self.dojo_results.update({args.type: {}})
        self.dojo_reports.update({args.type: {}})
        self.__get_dojo_reports(args)

    def __get_dojo_reports(self, args):
        for name, parser in PARSER_CLASSES.items():
            if name in TOOL_FORMAT:
                name = TOOL_FORMAT[name]

            if not os.path.exists(f'./tests/{args.type}/{name}'):
                continue

            tests_filenames = os.listdir(f'./tests/{args.type}/{name}')
            for filename in tests_filenames:
                if '_hub' in filename:
                    continue
                args.filename = f'./tests/{args.type}/{name}/{filename}'

                args.scanner = name
                dojo_parser = parser()

                with open(args.filename, "r") as f:
                    dojo_results = dojo_parser.get_findings(f, '')
                    self.dojo_results[args.type].update({f'{name} - {filename}': dojo_results})
                hub_parser = HubParser(args=args, dojo_results=dojo_results)
                hub_parser.parse()

                self.dojo_reports[args.type].update({f'{name} - {filename}': hub_parser.get_report()})

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

        for arg in self.args:
            for name, report in self.dojo_reports[arg.type].items():
                print(f"\nValidating {name}")
                validate(report, schema)
                print(f"\nValidated {name}")

    def test_unique_ids(self):
        for arg in self.args:
            for name in self.dojo_reports[arg.type].keys():
                findings: list = self.dojo_reports[arg.type][name]['scans'][0]['results'][0]['findings']
                self.assertEqual(len(findings), len(self.dojo_results[arg.type][name]), f'{name} - {findings} != {self.dojo_results[arg.type][name]}')

    def test_output_files(self):
        for arg in self.args:
            for name, report in self.dojo_reports[arg.type].items():
                scanner, filename = name.split(' - ')
                filename = filename.replace('.json', '')
                with open(f'./tests/{arg.type}/{scanner}/{filename}_hub.json', 'r') as f:
                    output = json.load(f)

                self.__delete_independent_ids(report)
                self.__delete_independent_ids(output)

                print(f"\nComparing {name}")
                self.assertEqual(report, output)
