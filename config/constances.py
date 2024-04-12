import importlib
import inspect
import os
from typing import Any

PARSER_CLASSES: dict[str, Any] = {}
PARSERS_PATH = "dojo/parsers"


def import_classes_from_directory(directory_path):
    for file_name in os.listdir(directory_path):
        if file_name.endswith(".py") and file_name != "__init__.py":
            module_name = file_name.replace(".py", "")
            module = importlib.import_module(f"dojo.parsers.{module_name}")

            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and name != "Finding" and name[0].isupper() and 'Parser' in name:
                    globals()[name] = obj
                    PARSER_CLASSES.update({file_name.split(".")[0]: obj})


# Import classes from the dojo/parsers directory
import_classes_from_directory(PARSERS_PATH)
