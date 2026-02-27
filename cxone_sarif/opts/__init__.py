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


DEFAULT = ReportOpts(
    SastOpts=SastOpts(SkipSast=False, OmitApiResults=False, AppendSimilarityId=False),
    ScaOpts=ScaOpts(SkipSca=False, GroupBy=ScaOpts.GROUP_NONE),
    SkipKics=False,
    SkipContainers=False,
)
