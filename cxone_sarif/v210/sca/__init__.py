from cxone_api import CxOneClient
from cxone_api.high.util import CxOneVersions
from cxone_sarif.opts import ScaOpts
from sarif_om import Run
from .sca_run import ScaRun

async def get_sca_run(client : CxOneClient, opts : ScaOpts, severity_filter : list, project_id : str, scan_id : str, platform : str, versions : CxOneVersions,
                       organization : str, info_uri : str) -> Run:
  return await ScaRun.factory(client, opts, severity_filter, project_id, scan_id, platform, versions.CxOne, organization, info_uri)

