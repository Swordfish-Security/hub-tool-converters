import importlib
import inspect
import os
from typing import Any

PARSER_CLASSES: dict[str, Any] = {}
PARSERS_PATH = os.path.dirname(__file__) + "/../converters/parsers"
TESTS_PATH = os.path.dirname(__file__) + "/../tests/"
PARSERS_NAMES_TO_FIX = ["kaspersky_cs", "kaspersky-cs"]


def import_classes_from_directory(directory_path):
    for file_name in os.listdir(directory_path):
        if file_name.endswith(".py") and file_name != "__init__.py":
            module_name = file_name.replace(".py", "")
            module = importlib.import_module(f"converters.parsers.{module_name}")

            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and name != "Finding" and name[0].isupper() and 'Parser' in name:
                    globals()[name] = obj
                    format_name = file_name.split(".")[0]
                    PARSER_CLASSES.update({format_name: obj})


# Import classes from the directory
import_classes_from_directory(PARSERS_PATH)


def add_without_parser_scanners_to_parser_classes(xdir):
    for directory in os.listdir(xdir):
        if os.path.isdir(os.path.join(xdir, directory)):
            for scanner in os.listdir(os.path.join(xdir, directory)):
                if scanner not in PARSER_CLASSES and '__' not in scanner and '.' not in scanner:
                    PARSER_CLASSES.update({scanner: None})


add_without_parser_scanners_to_parser_classes(TESTS_PATH)
