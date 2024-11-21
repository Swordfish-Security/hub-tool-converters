import argparse

from config.constances import PARSER_CLASSES
from config.enums import SourceTypes, BuildTool, Stage
from hub.parsers.hub_parser import HubParser
from utils import check_keys_parser_classes, validate_args


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
        help="AppSec.Hub repository's commit (default: master)",
        default="master"
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

    args = parser.parse_args()

    validate_args(args)

    parser = PARSER_CLASSES[args.format]()

    with open(args.filename, "r", encoding="utf-8") as f:
        results = parser.get_findings(f, '')

    hub_parser = HubParser(args=args, results=results)
    hub_parser.parse()
    hub_parser.save()
