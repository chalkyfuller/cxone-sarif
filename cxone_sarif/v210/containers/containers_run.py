import base64, urllib
from cxone_sarif.run_factory import RunFactory
from cxone_sarif.utils import normalize_file_uri
from cxone_api import CxOneClient
from cxone_api.util import page_generator
from cxone_api.low.all_scanners_results import retrieve_scan_results_all_scanners
from sarif_om import (Run, 
                      ReportingDescriptor,
                      MultiformatMessageString,
                      Result,
                      Message,
                      Location,
                      Region,
                      PhysicalLocation,
                      ArtifactLocation,
                      RunAutomationDetails,
                      Tool,
                      ToolComponent
                      )

class ContainersRun(RunFactory):

  @staticmethod
  def get_tool_guid() -> str:
    return "3aaeea89-14a9-4b83-a6f3-86b209d7e887"
  
  @staticmethod
  def __make_viewer_uri(display_endpoint : str, project_id : str, scan_id : str, file_path : str, image_name : str, image_tag : str) -> str:
    encoded_file_path = urllib.parse.quote_plus(base64.b64encode(urllib.parse.quote_plus(file_path).encode("UTF-8")).decode())
    encoded_image_tag = urllib.parse.quote_plus(base64.b64encode(urllib.parse.quote_plus(f"{image_name}:{image_tag}").encode("UTF-8")).decode())
    return display_endpoint.rstrip("/") + f"/container-security-results/{project_id}/{scan_id}/results/{encoded_file_path}/{encoded_image_tag}/vulnerabilities"
  

  @staticmethod
  async def factory(client : CxOneClient, severity_filter : list, project_id : str, scan_id : str, platform : str, version : str, organization : str, info_uri : str) -> Run:


    results = []
    rules = {}

    # This is a bit inefficient, maybe one day containers will have its own result API.
    # This data stream lacks some data required for best results.
    async for result in page_generator(retrieve_scan_results_all_scanners, array_element="results",
                                       client=client, scan_id=scan_id, limit=100):

      if not "containers" == ContainersRun.get_value_safe("type", result):
        continue

      # Filter by severity if specified
      if len(severity_filter) > 0:
        severity = ContainersRun.get_value_safe("severity", result)
        if severity is None or severity.upper() not in severity_filter:
          continue

      cve_id = ContainersRun.get_value_safe("id", result)
      vuln_id = cve_id
      vuln_data = ContainersRun.get_value_safe("data", result)
      image_spec = f"{ContainersRun.get_value_safe('imageName', vuln_data)}:{ContainersRun.get_value_safe('imageTag', vuln_data)}"
      package_spec = f"{ContainersRun.get_value_safe('packageName', vuln_data)}:{ContainersRun.get_value_safe('packageVersion', vuln_data)}"
      package_id = f"{image_spec}/{package_spec}"
        

      if vuln_id not in rules.keys():
        details = ContainersRun.get_value_safe("vulnerabilityDetails", result)

        help_uri = ContainersRun.make_cve_help_url(client, cve_id)

        rules[vuln_id] = ReportingDescriptor(
          id = vuln_id,
          name = ContainersRun.make_pascal_case_identifier(f"Advisory {cve_id}"),
          help_uri = help_uri,
          help = ContainersRun.make_cve_description(cve_id, ContainersRun.get_value_safe("description", result), None, help_uri),
          short_description = MultiformatMessageString(text=cve_id),
          full_description = ContainersRun.make_cve_description(cve_id, ContainersRun.get_value_safe("description", result), None, help_uri),
          properties = {
            "cvssScore" : ContainersRun.get_value_safe("cvss", details),
            "cwe" : ContainersRun.get_value_safe("cweId", details),
            "security-severity" : str(ContainersRun.get_value_safe("cvssScore", details)),
          }
        )

      viewer_uri = ContainersRun.__make_viewer_uri(client.display_endpoint, project_id, scan_id, 
                                                   ContainersRun.get_value_safe('imageFilePath', vuln_data),
                                                   ContainersRun.get_value_safe('imageName', vuln_data),
                                                   ContainersRun.get_value_safe('imageTag', vuln_data))

      results.append(Result(
        message = Message(text=f"Detected in {package_spec}. See: {viewer_uri}", markdown=f"[View in CheckmarxOne]({viewer_uri})"),
        rule_id = vuln_id,
        locations = [
          Location(
            physical_location=PhysicalLocation(
              artifact_location=ArtifactLocation(
                uri=normalize_file_uri(ContainersRun.get_value_safe('imageFilePath', vuln_data))),
                region=Region(start_line=1)
            ))
        ],
        hosted_viewer_uri = viewer_uri,
        partial_fingerprints={
          "packageId" : package_id,
          "packageSpec" : package_spec,
          "imageSpec" : image_spec,
          "cve" : cve_id
        },
        level=RunFactory.translate_severity_to_level(ContainersRun.get_value_safe("severity", result)),
        properties = {
          "severity" : ContainersRun.get_value_safe("severity", result),
          "packageId" : package_id,
          "packageSpec" : package_spec,
          "imageSpec" : image_spec,
          "state" : ContainersRun.get_value_safe("state", result),
          "status" : ContainersRun.get_value_safe("status", result),
          "firstFoundAt" : ContainersRun.get_value_safe("firstFoundAt", result),
          "firstScanId" : ContainersRun.get_value_safe("firstScanId", result),
        }
      ))

    driver = ToolComponent(name="CheckmarxOne-Container Security", guid=ContainersRun.get_tool_guid(),
                           product_suite=platform,
                           full_name=f"Checkmarx Container Security {version}",
                           short_description=MultiformatMessageString(text="Container security analysis scanner."),
                           # 3.19.2 at least one of version or semanticVersion SHOULD be present
                           semantic_version=version,
                           information_uri=info_uri,
                           organization=organization,
                           rules = [r for r in rules.values()])

    tool = Tool(driver=driver)

    return Run(tool=tool,
               results=results,
               automation_details=RunAutomationDetails(
                 description=Message(text="Container security analysis scan with CheckmarxOne Container Security"),
                 id=RunFactory.make_run_id(project_id, scan_id),
                 guid=scan_id,
                 correlation_guid=project_id),  
              column_kind="unicodeCodePoints")
        
