import importlib
import inspect
import os
from typing import Any

PARSER_CLASSES: dict[str, Any] = {}
PARSERS_PATH = "converters/parsers"
TOOL_FORMAT: dict[str, str] = {
    'svace': 'sarif',
    'pvs-studio': 'sarif'
}


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
                    for tool_name in TOOL_FORMAT.keys():
                        if format_name == TOOL_FORMAT[tool_name]:
                            PARSER_CLASSES.update({tool_name: obj})


# Import classes from the directory
import_classes_from_directory(PARSERS_PATH)
