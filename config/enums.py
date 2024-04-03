import enum


class ScannerTypes(enum.Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"


class SourceTypes(enum.Enum):
    CODE = 'codebase'
