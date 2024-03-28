from typing import Type

from parsers import BasicParser, GitleaksParser, SemgrepParser

PARSER_CLASSES: dict[str, Type[BasicParser]] = {
    "gitleaks": GitleaksParser,
    "semgrep": SemgrepParser
}
