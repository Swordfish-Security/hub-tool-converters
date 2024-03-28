import os

from config.constances import PARSER_CLASSES


def check_keys_parser_classes():
    """
    Check that all parsers are in PARSER_CLASSES const
    :return:
    """
    parsers_dir = os.listdir("parsers")
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
    if xor_set := exists_parsers.symmetric_difference(set_parsers_classes):
        raise ValueError(f"{xor_set} scanners are not provided")
