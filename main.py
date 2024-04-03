import argparse

from config.constances import PARSER_CLASSES
from hub.parsers.hub_parser import HubParser
from utils import check_keys_parser_classes

if __name__ == '__main__':
    # TODO: Delete for production
    # Only for tests here
    check_keys_parser_classes()

    parser = argparse.ArgumentParser(
        prog="Converter",
        description="Converts scanners output to HUB format",
    )
    parser.add_argument(
        "-s", "--scanner",
        type=str,
        choices=PARSER_CLASSES.keys(),
        help="Scanner name",
        required=True
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
        "-sn", "--source-name",
        type=str,
        help="AppSec.Hub repository's name",
        required=True
    )
    parser.add_argument(
        "-su", "--source-url",
        type=str,
        help="AppSec.Hub repository's URL",
        required=True
    )
    parser.add_argument(
        "-sb", "--source-branch",
        type=str,
        help="AppSec.Hub repository's branch (default: master)",
        default="master"
    )
    parser.add_argument(
        "-sc", "--source-commit",
        type=str,
        help="AppSec.Hub repository's commit (default: master)",
        default="master"
    )

    args = parser.parse_args()

    dojo_parser = PARSER_CLASSES[args.scanner]()

    with open(args.filename, "r") as f:
        dojo_results = dojo_parser.get_findings(f, '')

    hub_parser = HubParser(args=args, dojo_results=dojo_results)
    hub_parser.parse()
    hub_parser.save()
