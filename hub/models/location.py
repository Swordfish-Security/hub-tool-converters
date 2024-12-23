from dataclasses import dataclass

from config.enums import SourceTypes


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationSast:
    type: SourceTypes
    id: str
    sourceId: str
    fileName: str
    language: str = "Any"

    def __post_init__(self):
        self.parse_language_from_filename()

    def parse_language_from_filename(self):
        if "." in self.fileName:
            file_format = self.fileName.split(".")[-1]

            if file_format in ["java", "class", "jar", "war"]:
                self.language = "Java"
            elif file_format in ["js", "mjs", "cjs"]:
                self.language = "JavaScript"
            elif file_format in ["ts", "tsx"]:
                self.language = "TypeScript"
            elif file_format in ["py", "pyc", "pyo", "pyw", "pyd"]:
                self.language = "Python"
            elif file_format in ["cs", "csproj"]:
                self.language = "C#"
            elif file_format in ["conf", "ini", "cfg", "yaml", "yml", "json", "xml"]:
                self.language = "CONFIG"
            elif file_format in ["php", "phtml", "php3", "php4", "php5"]:
                self.language = "PHP"
            elif file_format in ["sql", "pls", "pck", "pkb", "pks"]:
                self.language = "PL/SQL"
            elif file_format in ["groovy", "gvy", "gsh", "gy"]:
                self.language = "Groovy"
            elif file_format in ["html", "htm"]:
                self.language = "HTML5"
            elif file_format in ["go"]:
                self.language = "Go"
            elif file_format in ["kt", "kts"]:
                self.language = "Kotlin"
            elif file_format in ["h", "m", "mm", "C"]:
                self.language = "Objc"
            elif file_format in ["c","cc", "cpp", "cxx", "c++", "h", "hh", "hpp", "hxx", "h++"]:
                self.language = "C/C++"


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationDast:
    type: SourceTypes
    id: str
    sourceId: str
    url: str
    description: str


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationSca:
    type: SourceTypes
    id: str
    sourceId: str
    componentName: str
    componentVersion: str


@dataclass(kw_only=True, init=True, eq=False, order=False)
class LocationStack:
    locationId: str
    sequence: int = 1
    code: str
    line: int
