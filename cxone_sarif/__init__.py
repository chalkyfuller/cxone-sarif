import logging
import asyncio
from typing import Dict, List, Any
from cxone_api import CxOneClient
from cxone_api.exceptions import ResponseException
from cxone_api.high.util import CxOneVersions
from cxone_api.low.projects import retrieve_project_info
from cxone_api.util import json_on_ok
from cxone_api.low.scans import retrieve_scan_details
from sarif_om import SarifLog, Run, VersionControlDetails
from jsonpath_ng import parse
from jschema_to_python.to_json import to_json
from cxone_sarif.opts import ReportOpts
from .v210 import get_sast_run, get_sca_run, get_iac_run, get_containers_run
from .__agent__ import __agent__
from .__version__ import __version__


class SerializableSarifLog(SarifLog):

    def asjson(self):
        return to_json(self)


class RunFailures(Exception):

    def __init__(self, non_runs: List[Any], *args):
        super().__init__(args)
        self.__non_runs = non_runs

    @property
    def non_runs(self) -> List[Any]:
        return self.__non_runs


PLATFORM_NAME = "CheckmarxOne"


async def get_sarif_v210_log_for_scan(
    client: CxOneClient,
    opts: ReportOpts,
    scan_id: str,
    throw_on_run_failure=False,
    clone_url: str = None,
    branch: str = None,
) -> SerializableSarifLog:
    """Generate a SARIF v2.1.0 log from CheckmarxOne scan results.

    :param client: A CxOneClient class instance from the cxone-async-api.
    :type client: CxOneClient

    :param opts: Report generation options.
    :type opts: ReportOpts

    :param scan_id: A GUID string representing a scan id in CheckmarxOne.
    :type scan_id: str

    :param throw_on_run_failure: Set to true to throw RunFailures if any run generations fail.  Default: False
    :type throw_on_run_failure: bool, optional

    :param clone_url: The clone URL to be used if it can't be retrieved from the Checkmarx One project.  This is used when
    generating the log and may provide useful display context by the log consumer.  The URL "uri:unknown" is used if
    a clone URL can't be determined.
    :type clone_url: str, optional

    :param branch: The name of the branch to use if it can't be retrieved from the Checkmarx One scan.  This is used when
    generating the log and may provide useful display context by the log consumer.  The value "unknown" is used if
    a suitable value can't be determined.
    :type branch: str, optional

    :rtype: SerializableSarifLog
    """

    def version_control_details_factory(scan_details: Dict) -> VersionControlDetails:
        __handler_type = parse("$.metadata.type")
        __git_repo_url = parse("$.metadata.Handler.GitHandler.repo_url")

        repo_url = None
        handler = __handler_type.find(scan_details).pop().value

        if handler == "git":
            repo_url = __git_repo_url.find(scan_details).pop().value

        if repo_url is None:
            repo_url = "uri:unknown"

        return VersionControlDetails(
            repository_uri=clone_url if clone_url is not None else repo_url,
            branch=(
                branch if branch is not None else scan_details.get("branch", "unknown")
            ),
            as_of_time_utc=scan_details["createdAt"],
            properties={
                "sourceType": scan_details["sourceType"],
                "sourceOrigin": scan_details["sourceOrigin"],
            },
        )

    _log = logging.getLogger(f"get_sarif_v210_log_for_scan:{scan_id}")

    __info_uri = (
        "https://checkmarx.com/resource/documents/en/34965-67042-checkmarx-one.html"
    )
    __org = "Checkmarx"
    __details_engines = parse("$.engines")

    try:

        _log.info("Compiling SARIF log")

        # Semantic versions for tooling.
        versions = await CxOneVersions.factory(client)

        # Scan details
        scan_details = json_on_ok(await retrieve_scan_details(client, scan_id))

        project_id = scan_details["projectId"]
        project_details = json_on_ok(await retrieve_project_info(client, project_id))

        engines = __details_engines.find(scan_details).pop().value

        # 3.13.4 - runs is empty if there are no results.
        futures = []
        if not opts.SastOpts.SkipSast and "sast" in engines:
            futures.append(
                asyncio.get_running_loop().create_task(
                    get_sast_run(
                        client,
                        opts.SastOpts,
                        opts.SeverityFilter,
                        project_id,
                        scan_id,
                        PLATFORM_NAME,
                        versions,
                        __org,
                        __info_uri,
                    )
                )
            )

        if not opts.ScaOpts.SkipSca and "sca" in engines:
            futures.append(
                asyncio.get_running_loop().create_task(
                    get_sca_run(
                        client,
                        opts.ScaOpts,
                        opts.SeverityFilter,
                        project_id,
                        scan_id,
                        PLATFORM_NAME,
                        versions,
                        __org,
                        __info_uri,
                    )
                )
            )

        if not opts.SkipKics and "kics" in engines:
            futures.append(
                asyncio.get_running_loop().create_task(
                    get_iac_run(
                        client,
                        opts.SeverityFilter,
                        project_id,
                        scan_id,
                        PLATFORM_NAME,
                        versions,
                        __org,
                        __info_uri,
                    )
                )
            )

        if not opts.SkipContainers and "containers" in engines:
            futures.append(
                asyncio.get_running_loop().create_task(
                    get_containers_run(
                        client,
                        opts.SeverityFilter,
                        project_id,
                        scan_id,
                        PLATFORM_NAME,
                        versions,
                        __org,
                        __info_uri,
                    )
                )
            )

        if len(futures) > 0:
            completed, _ = await asyncio.wait(futures)
            results = [x.result() for x in completed]
        else:
            _log.warning(
                f"No log types selected or scan {scan_id} did not execute with selected engine types."
            )
            results = []

        _log.info("SARIF log complete")

        vc_details = version_control_details_factory(scan_details)

        for run in results:
            run.version_control_provenance = [vc_details]

        non_runs = [x for x in results if not isinstance(x, Run)]

        if len(non_runs) > 0:
            msg = (
                f"Some engine runs for scan {scan_id} did not produce a Run log entry."
            )
            if throw_on_run_failure:
                raise RunFailures(non_runs, msg)
            else:
                _log.warning(msg)

            counter = 1
            for nr in non_runs:
                _log.debug("----- BEGIN: ERROR {counter} -----")
                if isinstance(nr, Exception):
                    _log.exception(nr)
                else:
                    _log.debug(nr)
                _log.debug("----- END: ERROR {counter} -----")
                counter += 1

        return SerializableSarifLog(
            runs=[x for x in results if isinstance(x, Run)],
            version="2.1.0",
            schema_uri="https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-external-property-file-schema-2.1.0.json",
            properties={
                "platform": PLATFORM_NAME,
                "reportCompiler": f"{__agent__}/{__version__}",
                "scanId": scan_id,
                "scanDetails": scan_details if scan_details is not None else None,
                "projectDetails": project_details,
                "versions": versions.to_dict(),
            },
        )

    except ResponseException as rex:
        _log.warning(f"No Run log entries created for scan {scan_id} due to error.")
        _log.exception(rex)
        if throw_on_run_failure:
            raise rex
    except Exception as ex:
        _log.warning(f"No Run log entries created for scan {scan_id} due to error.")
        _log.exception(ex)
        if throw_on_run_failure:
            raise ex
