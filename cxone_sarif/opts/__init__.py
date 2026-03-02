from dataclasses import dataclass


@dataclass(frozen=True)
class SastOpts:
    SkipSast: bool
    OmitApiResults: bool
    AppendSimilarityId: bool


@dataclass(frozen=True)
class ScaOpts:
    SkipSca: bool
    GroupBy: str

    # Valid grouping modes
    GROUP_NONE = "none"
    GROUP_PACKAGE_MANIFEST_SEVERITY = "package-manifest-severity"
    GROUP_PACKAGE_MANIFEST = "package-manifest"


@dataclass(frozen=True)
class ReportOpts:
    SastOpts: SastOpts
    ScaOpts: ScaOpts
    SkipKics: bool
    SkipContainers: bool
    SeverityFilter: list  # List of severity levels to include (empty = all)

    # Valid severity levels
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"

    ALL_SEVERITIES = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]


DEFAULT = ReportOpts(
    SastOpts=SastOpts(SkipSast=False, OmitApiResults=False, AppendSimilarityId=False),
    ScaOpts=ScaOpts(SkipSca=False, GroupBy=ScaOpts.GROUP_NONE),
    SkipKics=False,
    SkipContainers=False,
    SeverityFilter=[],  # Empty list means include all severities
)
