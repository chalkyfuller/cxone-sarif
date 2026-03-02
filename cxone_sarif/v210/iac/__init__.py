from cxone_api import CxOneClient
from cxone_api.high.util import CxOneVersions
from sarif_om import Run
from .iac_run import IaCRun


async def get_iac_run(client : CxOneClient, severity_filter : list, project_id : str, scan_id : str, platform : str, versions : CxOneVersions,
                       organization : str, info_uri : str) -> Run:
  return await IaCRun.factory(client, severity_filter, project_id, scan_id, platform, versions.KICS, organization, info_uri)
