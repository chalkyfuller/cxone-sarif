from cxone_sarif.utils import normalize_file_uri
from cxone_sarif.run_factory import RunFactory
from cxone_api import CxOneClient
from cxone_api.util import page_generator
from cxone_api.low.iac import retrieve_iac_security_scan_results
from pathlib import Path
import urllib
from cxone_sarif.utils import SeverityTranslator
from sarif_om import (Run,
                      ReportingDescriptor,
                      MultiformatMessageString,
                      Result,
                      Message,
                      Location,
                      PhysicalLocation,
                      ArtifactLocation,
                      Region,
                      ToolComponent,
                      Tool,
                      RunAutomationDetails
                     )


class IaCRun(RunFactory):

  @staticmethod
  def get_tool_guid() -> str:
    return "93ae2d79-7445-4da2-943f-c6e17e96de7d"
  
  __kics_query_docs_uri = "https://docs.kics.io/latest/queries/all-queries/"
  
  @staticmethod
  def __make_help(description : str) -> MultiformatMessageString:
    return MultiformatMessageString(text=description, 
                                    markdown=description + f" [KICS Documentation]({IaCRun.__kics_query_docs_uri})")

  @staticmethod
  def __make_viewer_uri(display_endpoint : str, scan_id : str, project_id : str, result_id : str) -> str:
    normalized_display_endpoint = display_endpoint.rstrip('/')
    result_path = str(Path('results') / Path(scan_id) / Path (project_id))
    return f"{normalized_display_endpoint}/{result_path}/kics?result-id=" + urllib.parse.quote_plus(result_id)
  

  @staticmethod
  def __make_result_message(actual : str, viewer_uri : str) -> MultiformatMessageString:
    return MultiformatMessageString(text=actual, 
                                    markdown=actual + f" [View in CheckmarxOne]({viewer_uri})")


  @staticmethod
  async def factory(client : CxOneClient, severity_filter : list, project_id : str, scan_id : str, platform : str, version : str, organization : str, info_uri : str) -> Run:
    rules = {}
    results = []

    async for result in page_generator(retrieve_iac_security_scan_results, "results", client=client, scan_id=scan_id):
      state = IaCRun.get_value_safe("state", result)
      if state is not None and state == "NOT_EXPLOITABLE":
        continue

      # Filter by severity if specified
      if len(severity_filter) > 0:
        severity = IaCRun.get_value_safe("severity", result)
        if severity is None or severity.upper() not in severity_filter:
          continue

      query_name = IaCRun.get_value_safe("queryName", result)
      query_platform = IaCRun.get_value_safe("platform", result)
      query_category = IaCRun.get_value_safe("category", result)
      vuln_id = f"{IaCRun.make_pascal_case_identifier(query_platform)}-{IaCRun.make_pascal_case_identifier(query_category)}-{IaCRun.make_pascal_case_identifier(query_name)}"

      if vuln_id not in rules.keys():
        rules[vuln_id] = ReportingDescriptor(
          id = vuln_id,
          name = IaCRun.make_pascal_case_identifier(query_name),
          help_uri = IaCRun.__kics_query_docs_uri,
          help = IaCRun.__make_help(IaCRun.get_value_safe("description", result)),
          short_description = MultiformatMessageString(text=IaCRun.get_value_safe("queryName", result)),
          full_description = MultiformatMessageString(text=IaCRun.get_value_safe("description", result)),
          properties = {
              "security-severity" : SeverityTranslator.translate_severity_to_level(IaCRun.get_value_safe("severity", result))
          }
        )



      location = Location(
            physical_location=PhysicalLocation(
              artifact_location=ArtifactLocation(
                uri=normalize_file_uri(IaCRun.get_value_safe("fileName", result))),
                region=Region(start_line=IaCRun.get_value_safe("line", result))
            ))
      

      viewer_uri = IaCRun.__make_viewer_uri(client.display_endpoint, scan_id, project_id, IaCRun.get_value_safe("ID", result))

      results.append(Result(
        message = IaCRun.__make_result_message(IaCRun.get_value_safe("actualValue", result), viewer_uri),
        rule_id = vuln_id,
        locations = [location],
        hosted_viewer_uri = viewer_uri,
        partial_fingerprints={
          "similarityID" : IaCRun.get_value_safe("similarityID", result),
          "queryKey" : vuln_id
        },
        level=RunFactory.translate_severity_to_level(IaCRun.get_value_safe("severity", result)),
        properties = {
          "severity" : IaCRun.get_value_safe("severity", result),
          "platform" : query_platform,
          "state" : IaCRun.get_value_safe("state", result),
          "status" : IaCRun.get_value_safe("status", result),
          "firstFoundAt" : IaCRun.get_value_safe("firstFoundAt", result),
          "firstScanID" : IaCRun.get_value_safe("firstScanID", result),
          "type" : IaCRun.get_value_safe("type", result),
        }
      ))

    driver = ToolComponent(name="CheckmarxOne-KICS", guid=IaCRun.get_tool_guid(),
                           product_suite=platform,
                           full_name=f"Checkmarx KICS {version}",
                           short_description=MultiformatMessageString(text="Infrastructure-As-Code scanner."),
                           # 3.19.2 at least one of version or semanticVersion SHOULD be present
                           semantic_version=version,
                           information_uri=info_uri,
                           organization=organization,
                           rules = [r for r in rules.values()])

    tool = Tool(driver=driver)

    return Run(tool=tool,
               results=results,
               automation_details=RunAutomationDetails(
                 description=Message(text="Infrastructure-As-Code analysis scan with CheckmarxOne KICS"),
                 id=RunFactory.make_run_id(project_id, scan_id),
                 guid=scan_id,
                 correlation_guid=project_id),  
              column_kind="unicodeCodePoints")

