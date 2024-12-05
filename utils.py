import os

from config.constances import PARSER_CLASSES, TESTS_PATH, PARSERS_PATH
from config.enums import SourceTypes


def check_keys_parser_classes():
    """
    Check that all parsers are in PARSER_CLASSES const
    :return:
    """
    parsers_dir = os.listdir(PARSERS_PATH)
    set_parsers_classes = set(PARSER_CLASSES.keys())
    exists_parsers: set[str] = set()
    for parser_file in parsers_dir:
        parser_file = parser_file.replace(".py", "")
        if (
                parser_file not in ("__init__", "abstract", "__pycache__")
        ):
            if parser_file not in PARSER_CLASSES:
                raise ValueError(f"Parser {parser_file} not in PARSER_CLASSES")
            exists_parsers.add(parser_file)

    for directory in os.listdir(TESTS_PATH):
        if os.path.isdir(os.path.join(TESTS_PATH, directory)):
            for scanner in os.listdir(os.path.join(TESTS_PATH, directory)):
                if scanner in PARSER_CLASSES:
                    exists_parsers.add(scanner)

    if xor_set := exists_parsers.symmetric_difference(set_parsers_classes):
        raise ValueError(f"{xor_set} scanners are not provided")


def validate_args(args):
    # Приведение к нижнему регистру и замена "-" на "_"
    args.type = args.type.lower()
    args.scanner = args.scanner.replace('-', '_')
    if args.format is None:
        if args.scanner not in PARSER_CLASSES.keys():
            raise ValueError("scanner is not supported, provide format if available")
        args.format = args.scanner

    if args.type == SourceTypes.CODEBASE.value:
        if not args.url or not args.name:
            raise ValueError("url and name are required for CODEBASE source_type")

    elif args.type == SourceTypes.INSTANCE.value:
        if not args.url or not args.name:
            raise ValueError("url is required for INSTANCE source_type")

    elif args.type == SourceTypes.ARTIFACT.value:
        if not args.url or not args.name:
            raise ValueError("url is required for ARTIFACT source_type")

    else:
        raise ValueError("Invalid source type")

