import enum


class ScannerTypes(enum.Enum):
    SAST = "sast"
    DAST = "dast"


class SourceTypes(enum.Enum):
    CODE = 'codebase'
