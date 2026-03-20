import argparse
from dataclasses import dataclass
from typing import Optional

from config.constances import PARSER_CLASSES
from config.enums import SourceTypes, BuildTool, Stage
from hub.parsers.hub_parser import HubParser
from utils import check_keys_parser_classes, validate_args


@dataclass
class Argument:
    type: str
    scanner: str
    format: Optional[str] = None
    filename: Optional[str] = None
    output: Optional[str] = None
    name: Optional[str] = None
    url: Optional[str] = None
    branch: Optional[str] = None
    commit: Optional[str] = None
    build_tool: Optional[str] = None
    stage: Optional[str] = None

class Converter:
    def __init__(self, args: Argument):
        validate_args(args)
        parser = PARSER_CLASSES[args.format]()

        with open(args.filename, "r", encoding='utf-8') as f:
            results = parser.get_findings(f, '')

        hub_parser = HubParser(args=args, results=results)
        hub_parser.parse()
        hub_parser.save()

def _prepare_choice(choices):
    fixed_choices = list()
    for choice in choices:
        fixed_choices.append(choice)
        fixed_choices.append(choice.lower())
        fixed_choices.append(choice.replace('_', ' '))
        fixed_choices.append(choice.replace('_', ' ').lower())
    return set(fixed_choices)


if __name__ == '__main__':
    # TODO: Delete for production
    # Only for tests here
    check_keys_parser_classes()

    parser = argparse.ArgumentParser(
        prog="Converter",
        description="Converts scanners output to HUB format",
    )
    parser.add_argument(
        "-t", "--type",
        type=str,
        choices=_prepare_choice(SourceTypes.__members__.keys()),
        help="Source type",
        required=True
    )
    parser.add_argument(
        "-s", "--scanner",
        type=str,
        help="Scanner name",
        required=True
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=_prepare_choice(PARSER_CLASSES.keys()),
        help="Tool from format",
        required=False
    )
    parser.add_argument(
        "-f", "--filename",
        type=str,
        help="Filename",
        required=True
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output filename",
        required=True
    )
    parser.add_argument(
        "-n", "--name",
        type=str,
        help="AppSec.Hub repository's/artifact/instance name",
        required=True
    )
    parser.add_argument(
        "-u", "--url",
        type=str,
        help="AppSec.Hub repository's/artifact/instance URL",
        required=True
    )
    parser.add_argument(
        "-b", "--branch",
        type=str,
        help="AppSec.Hub repository's branch (default: master)",
        default="master"
    )
    parser.add_argument(
        "-c", "--commit",
        type=str,
        help="AppSec.Hub repository's commit"
    )
    parser.add_argument(
        "-bt", "--build-tool",
        type=str,
        choices=_prepare_choice(BuildTool.__members__.keys()),
        help="Build tool used to compile this source code. Default: maven",
        default=BuildTool.MAVEN.value.lower()
    )
    parser.add_argument(
        "--stage",
        type=str,
        choices=Stage.__members__.keys(),
        help="Stage of instance",
        required=False
    )
    parser.add_argument(
        "--report-version",
        type=str,
        choices=["1.0.1", "1.0.2"],
        help="AppSec.Hub report schema version (default: 1.0.1)",
        default="1.0.1",
        dest="report_version"
    )

    args = parser.parse_args()

    validate_args(args)

    parser = PARSER_CLASSES[args.format]()

    with open(args.filename, "r", encoding='utf-8') as f:
        results = parser.get_findings(f, '')

    hub_parser = HubParser(args=args, results=results)
    hub_parser.parse()
    hub_parser.save()
