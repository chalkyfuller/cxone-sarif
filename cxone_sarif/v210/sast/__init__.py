from cxone_api import CxOneClient
from cxone_api.high.util import CxOneVersions
from cxone_sarif.opts import SastOpts
from sarif_om import Run
from .sast_run import SastRun


async def get_sast_run(client : CxOneClient, opts : SastOpts, severity_filter : list, project_id : str, scan_id : str, platform : str, versions : CxOneVersions,
                       organization : str, info_uri : str) -> Run:
  return await SastRun.factory(client, opts.OmitApiResults, opts.AppendSimilarityId, severity_filter, project_id, scan_id, platform, versions.SAST, organization, info_uri)