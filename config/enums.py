import enum


class ScannerTypes(enum.Enum):
    SAST = "sast"
    DAST = "dast"
    SCA_S = "sca_s"


class SourceTypes(enum.Enum):
    CODEBASE = 'codebase'
    ARTIFACT = 'artifact'
    INSTANCE = 'instance'


class BuildTool(enum.Enum):
    MAVEN = 'maven'
    GRADLE = 'gradle'
    PIP = 'pip'
    NUGET = 'nuget'
    NPM = 'npm'


class Stage(enum.Enum):
    ST = 'ST'
    UAT = 'UAT'
    IAT = 'IAT'
    STG = 'STG'
    PROD = 'PROD'
