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
    GO_MOD = 'go mod'
    COMPOSER = 'composer'


class Stage(enum.Enum):
    ST = 'ST'
    UAT = 'UAT'
    IAT = 'IAT'
    STG = 'STG'
    PROD = 'PROD'


# Версии схемы отчёта AppSec.Hub, которые умеет формировать конвертер.
REPORT_VERSIONS = ('1.0.1', '1.0.2', '1.0.3')
DEFAULT_REPORT_VERSION = '1.0.1'


def report_version_at_least(version: str, minimum: str) -> bool:
    """True, если версия схемы `version` не ниже `minimum` (сравнение по числовым компонентам, не по строке)."""
    def as_tuple(value: str) -> tuple[int, ...]:
        return tuple(int(part) for part in value.split('.'))

    return as_tuple(version) >= as_tuple(minimum)
