from cxone_sarif.utils import normalize_file_uri
from cxone_sarif.run_factory import RunFactory
from cxone_sarif.opts import ScaOpts
from cxone_api import CxOneClient
from cxone_api.util import json_on_ok
from cxone_api.high.sca import get_sca_report, ScaReportOptions, ScaReportType
from typing import Dict, List, Tuple
from pathlib import Path
import urllib
from collections import defaultdict
from sarif_om import (Run,
                      Tool,
                      RunAutomationDetails,
                      ToolComponent,
                      Message,
                      ArtifactLocation,
                      MultiformatMessageString,
                      ReportingDescriptor,
                      Location,
                      PhysicalLocation,
                      Region,
                      Result,
                      CodeFlow,
                      ThreadFlow,
                      ThreadFlowLocation)



class ScaRun(RunFactory):

  @staticmethod
  def get_tool_guid() -> str:
    return "3535ec30-c264-4cfb-a816-67984dc28151"


  @staticmethod
  def __make_result_msg(ep_bullets : List[str], viewer_link : str, package_manager : str, package_name : str, package_version : str) -> Message:
    desc = f"Displaying manifest where package reference is found. Detected in package **{package_name}** " + \
      f"version **{package_version}** from package manager **{package_manager}**."

    if len(ep_bullets) > 0:
      desc += "\n\n"
      desc = desc + "\n\nExploitable Path found some locations where package may be referenced:\n\n"
      for bullet in ep_bullets:
        desc += "\n* " + bullet
      desc += "\n\n"

    return Message(text=desc, markdown=desc + f" [View in CheckmarxOne]({viewer_link})")


  @staticmethod
  def __make_grouped_result_msg(cve_ids : List[str], viewer_link : str, package_manager : str, package_name : str, package_version : str) -> Message:
    cve_list = ", ".join(cve_ids)
    desc = f"This package version contains multiple vulnerabilities: **{cve_list}**. " + \
      f"Detected in package **{package_name}** version **{package_version}** from package manager **{package_manager}**."

    return Message(text=desc, markdown=desc + f"\n\n[View in CheckmarxOne]({viewer_link})")


  @staticmethod
  def __get_max_severity(vulnerabilities: List[Dict]) -> tuple:
    """Determine the maximum severity and corresponding score from a list of vulnerabilities.

    Returns:
      Tuple of (severity_string, score_float)
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    max_severity = "INFO"
    max_rank = 4
    max_score = 0.0

    for vuln in vulnerabilities:
      severity = ScaRun.get_value_safe("Severity", vuln)
      score = ScaRun.get_value_safe("Score", vuln)
      rank = severity_order.get(severity, 4)
      if rank < max_rank:
        max_rank = rank
        max_severity = severity
        max_score = score if score is not None else 0.0

    return max_severity, max_score


  @staticmethod
  def __group_vulnerabilities(vulnerabilities : List[Dict], location_index : Dict[str, List[str]], group_by : str) -> Dict[tuple, List[Dict]]:
    """Group vulnerabilities based on the specified grouping mode.

    Args:
      vulnerabilities: List of vulnerability dictionaries
      location_index: Mapping of package IDs to manifest locations
      group_by: Grouping mode (package-manifest-severity or package-manifest)

    Returns:
      Dictionary mapping group keys to lists of vulnerabilities
    """
    grouped = defaultdict(list)

    for vuln in vulnerabilities:
      package_name = ScaRun.get_value_safe("PackageName", vuln)
      package_version = ScaRun.get_value_safe("PackageVersion", vuln)
      package_id = ScaRun.get_value_safe("PackageId", vuln)
      severity = ScaRun.get_value_safe("Severity", vuln)

      # Get the first manifest file path for this package (used for grouping)
      manifest_path = ""
      if package_id in location_index.keys() and len(location_index[package_id]) > 0:
        manifest_path = location_index[package_id][0]

      # Create grouping key based on mode
      if group_by == ScaOpts.GROUP_PACKAGE_MANIFEST_SEVERITY:
        group_key = (package_name, package_version, manifest_path, severity)
      elif group_by == ScaOpts.GROUP_PACKAGE_MANIFEST:
        group_key = (package_name, package_version, manifest_path)
      else:
        # Should not reach here, but fallback to most granular grouping
        group_key = (package_name, package_version, manifest_path, severity)

      grouped[group_key].append(vuln)

    return grouped


  @staticmethod
  def __get_grouped_vulnerabilities(client : CxOneClient, vulnerabilities : List[Dict], location_index : Dict[str, List[str]], project_id : str, scan_id : str, group_by : str) -> Tuple[List[Result], Dict[str, str]]:
    """Create grouped SCA findings based on the specified grouping mode."""
    results = []
    rules = {}

    grouped_vulns = ScaRun.__group_vulnerabilities(vulnerabilities, location_index, group_by)

    for group_key, vuln_group in grouped_vulns.items():
      # Extract package info from group key
      package_name = group_key[0]
      package_version = group_key[1]
      manifest_path = group_key[2]

      # Collect all CVE IDs in this group
      cve_ids = [ScaRun.get_value_safe("Id", v) for v in vuln_group]

      # Use the first vulnerability for common properties
      first_vuln = vuln_group[0]
      package_id = ScaRun.get_value_safe("PackageId", first_vuln)
      package_manager = ScaRun.get_value_safe("PackageManager", first_vuln)

      # Determine severity and score based on grouping mode
      if group_by == ScaOpts.GROUP_PACKAGE_MANIFEST_SEVERITY:
        severity = group_key[3]
        # Get the maximum score from all vulnerabilities in this severity group
        max_score = max([ScaRun.get_value_safe("Score", v) or 0.0 for v in vuln_group])
      else:
        # For package-manifest grouping, use the maximum severity
        severity, max_score = ScaRun.__get_max_severity(vuln_group)

      # Create unique rule ID based on the grouping mode
      # Sanitize values for use in rule ID (replace special chars with hyphens)
      sanitized_package = package_name.replace('/', '-').replace(':', '-').replace('@', '-').replace('.', '-')
      sanitized_version = package_version.replace('.', '-').replace('/', '-')
      # Create a short hash of the manifest path to keep rule IDs manageable
      import hashlib
      manifest_hash = hashlib.md5(manifest_path.encode()).hexdigest()[:8] if manifest_path else "nomanifest"

      # Build rule ID based on grouping mode
      if group_by == ScaOpts.GROUP_PACKAGE_MANIFEST_SEVERITY:
        rule_id = f"SCA-{sanitized_package}-{sanitized_version}-{manifest_hash}-{severity}"
      else:
        rule_id = f"SCA-{sanitized_package}-{sanitized_version}-{manifest_hash}"

      # Create rule if it doesn't exist yet
      if rule_id not in rules:
        # Extract manifest filename for display
        manifest_display = manifest_path.split('/')[-1] if manifest_path else "unknown manifest"

        rules[rule_id] = ReportingDescriptor(
          id=rule_id,
          name=ScaRun.make_pascal_case_identifier(f"SCA {package_name} {package_version}"),
          short_description=MultiformatMessageString(text=f"SCA: {package_name} {package_version}"),
          full_description=MultiformatMessageString(text=f"Software Composition Analysis findings for package {package_name} version {package_version} in {manifest_display}. Contains {len(cve_ids)} CVE(s) with {severity} severity."),
          help=MultiformatMessageString(text=f"This package version contains known vulnerabilities. Review the CVEs listed in the result details and consider updating to a patched version."),
          properties={
            "security-severity": str(max_score)
          }
        )

      # Build locations from manifest path
      locations = None
      if package_id in location_index.keys():
        locations = []
        for index, artifact_loc in enumerate(location_index[package_id]):
          locations.append(
            Location(
              id=index,
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=normalize_file_uri(artifact_loc)),
                region=Region(start_line=1, start_column=1, end_column=1)
              )))

      # Build viewer URL (use first CVE for the link)
      first_cve = cve_ids[0]
      vuln_path = urllib.parse.quote_plus(f"/vulnerabilities/{urllib.parse.quote_plus(f'{first_cve}:{package_id}')}")
      viewer_url = client.display_endpoint.rstrip("/") + "/" + str(Path(f"results/{project_id}/{scan_id}/sca?internalPath=" + f"{vuln_path}%2FvulnerabilityDetailsGql"))

      # Build fingerprints based on grouping mode
      fingerprints = {
        "packageName": package_name,
        "packageVersion": package_version,
        "manifestPath": manifest_path
      }

      # Include severity in fingerprint only for package-manifest-severity grouping
      if group_by == ScaOpts.GROUP_PACKAGE_MANIFEST_SEVERITY:
        fingerprints["severity"] = severity

      # Create grouped result
      results.append(Result(
        message=ScaRun.__make_grouped_result_msg(cve_ids, viewer_url, package_manager, package_name, package_version),
        rule_id=rule_id,
        level=RunFactory.translate_severity_to_level(severity),
        locations=locations,
        hosted_viewer_uri=viewer_url,
        partial_fingerprints=fingerprints,
        properties={
          "severity": severity,
          "packageName": package_name,
          "packageVersion": package_version,
          "packageManager": package_manager,
          "cveIds": cve_ids,
          "cveCount": len(cve_ids),
          "manifestPath": manifest_path,
          "maxCvssScore": str(max_score),
          "riskType": "package",
          "groupBy": group_by
        }
      ))

    return results, rules


  @staticmethod
  def __get_vulnerabilities(client : CxOneClient, vulnerabilities : List[Dict], location_index : Dict[str, List[str]], project_id : str, scan_id : str, group_by : str = ScaOpts.GROUP_NONE) -> Tuple[List[Result], Dict[str, str]]:

    if group_by != ScaOpts.GROUP_NONE:
      return ScaRun.__get_grouped_vulnerabilities(client, vulnerabilities, location_index, project_id, scan_id, group_by)

    results = []
    rules = {}

    for vuln in vulnerabilities:
      cve_id = ScaRun.get_value_safe("Id", vuln)
      package_id = ScaRun.get_value_safe("PackageId", vuln)
      vuln_id = cve_id

      if vuln_id not in rules.keys():
        rules[vuln_id] = ReportingDescriptor(
          id = vuln_id,
          name = ScaRun.make_pascal_case_identifier(f"Advisory {cve_id}"),
          help_uri = ScaRun.make_cve_help_url(client, cve_id),
          help = ScaRun.make_cve_description(cve_id, ScaRun.get_value_safe("Description", vuln), ScaRun.get_value_safe("References", vuln)),
          short_description = MultiformatMessageString(text=cve_id),
          full_description = ScaRun.make_cve_description(cve_id, ScaRun.get_value_safe("Description", vuln), ScaRun.get_value_safe("References", vuln)),
          properties = {
            "cvss2" : ScaRun.get_value_safe("Cvss2", vuln),
            "cvss3" : ScaRun.get_value_safe("Cvss3", vuln),
            "cvss4" : ScaRun.get_value_safe("Cvss4", vuln),
            "cvePublishDate" : ScaRun.get_value_safe("PublishDate", vuln),
            "cwe" : ScaRun.get_value_safe("Cwe", vuln),
            "epssValue" : str(ScaRun.get_value_safe("EpssValue", vuln)),
            "epssPercentile" : str(ScaRun.get_value_safe("EpssPercentile", vuln)),
            "security-severity" : str(ScaRun.get_value_safe("Score", vuln))
          }
        )

      exploitable_methods = ScaRun.get_value_safe("ExploitableMethods", vuln)
      code_flows = None
      ep_bullets = []
      if ScaRun.get_value_safe("ExploitablePath", vuln) and exploitable_methods is not None and len(exploitable_methods) > 0:
        code_flows = []

        ep_index = 0
        for method in exploitable_methods:
          ep_bullets.append("{}: {} Line: {}".format(
            ScaRun.get_value_safe("FullName", method), ScaRun.get_value_safe('SourceFile', method), ScaRun.get_value_safe("Line", method)))

          # Exploitable path doesn't provide enough information to get a nice flow highlight,
          # so like display is all that is shown.  EP also references code that is in the 
          # package but not in the repo.  It is not possible to tell the difference, so all
          # are shown as paths.
          loc = Location(
              id=ep_index,
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=normalize_file_uri(ScaRun.get_value_safe('SourceFile', method))
                ),
              region=Region(
                start_line=ScaRun.get_value_safe("Line", method),
                start_column=1,
                end_column=1,
                properties={
                  "NameSpace" : ScaRun.get_value_safe("NameSpace", method),
                  "FullName" : ScaRun.get_value_safe("FullName", method),
                  "ShortName" : ScaRun.get_value_safe("ShortName", method),
                })))

          code_flows.append(CodeFlow(thread_flows=[ThreadFlow(locations=[ThreadFlowLocation(location=loc)])]))

          ep_index += 1

      
      locations = None
      
      if package_id in location_index.keys():
        
        if locations is None:
          locations = []
        index = len(locations)

        # There can be many locations where this package is referenced.  Sarif
        # spec says only use more than one location if every location needs to
        # be changed to fix the issue.  GH displays only the first one,
        # but all will be put here for other Sarif consumers.
        for artifact_loc in location_index[package_id]:
          locations.append (
            Location(
              id=index,
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=normalize_file_uri(artifact_loc)),
                  region=Region(start_line=1, start_column=1, end_column=1)
              )))
          index += 1


      vuln_path = urllib.parse.quote_plus(f"/vulnerabilities/{urllib.parse.quote_plus(f'{cve_id}:{package_id}')}")

      viewer_url = client.display_endpoint.rstrip("/") + "/" + str(Path(f"results/{project_id}/{scan_id}/sca?internalPath=" + \
          f"{vuln_path}%2FvulnerabilityDetailsGql"))

      results.append(Result(
        message = ScaRun.__make_result_msg(ep_bullets, viewer_url, 
                                           ScaRun.get_value_safe("PackageManager", vuln), 
                                           ScaRun.get_value_safe("PackageName", vuln),
                                           ScaRun.get_value_safe("PackageVersion", vuln)),
        rule_id = vuln_id,
        level=RunFactory.translate_severity_to_level(ScaRun.get_value_safe("Severity", vuln)),
        locations = locations,
        hosted_viewer_uri = viewer_url,
        code_flows=code_flows,
        partial_fingerprints={
          "packageId" : package_id,
          "cve" : cve_id
        },
        properties = {
          "severity" : ScaRun.get_value_safe("Severity", vuln),
          "packageName" : ScaRun.get_value_safe("PackageName", vuln),
          "packageVersion" : ScaRun.get_value_safe("PackageVersion", vuln),
          "packageManager" : ScaRun.get_value_safe("PackageManager", vuln),
          "fixResolutionText" : ScaRun.get_value_safe("FixResolutionText", vuln),
          "state" : ScaRun.get_value_safe("RiskState", vuln),
          "status" : ScaRun.get_value_safe("RiskStatus", vuln),
          "firstFoundAt" : ScaRun.get_value_safe("FirstFoundAt", vuln),
          "riskType" : "package",
          "isViolatingPolicy" : str(ScaRun.get_value_safe("IsViolatingPolicy", vuln)),
        }
      ))

    return results, rules

  @staticmethod
  async def factory(client : CxOneClient, opts : ScaOpts, project_id : str, scan_id : str, platform : str, version : str, organization : str, info_uri : str) -> Run:
    scan_report = json_on_ok(await get_sca_report(client, scan_id, ScaReportOptions(fileFormat=ScaReportType.ScanReportJson)))
    scan_report_summary = ScaRun.get_value_safe("RiskReportSummary", scan_report)

    packages = ScaRun.get_value_safe("Packages", scan_report)
    package_loc_index = {}

    for package in packages:
      package_loc_index[ScaRun.get_value_safe("Id", package)] = ScaRun.get_value_safe("Locations", package)

    results, rules = ScaRun.__get_vulnerabilities(client, ScaRun.get_value_safe("Vulnerabilities", scan_report), package_loc_index, project_id, scan_id, opts.GroupBy)

    driver = ToolComponent(name="CheckmarxOne-SCA", guid=ScaRun.get_tool_guid(),
                           product_suite=platform,
                           full_name=f"Checkmarx SCA {version}",
                           short_description=MultiformatMessageString(text="Software composition analysis scanner."),
                           # 3.19.2 at least one of version or semanticVersion SHOULD be present
                           semantic_version=version,
                           information_uri=info_uri,
                           organization=organization,
                           rules = [r for r in rules.values()])

    tool = Tool(driver=driver,
                properties={
                  "summary" : scan_report_summary
                  })

    return Run(tool=tool, 
               results=results, 
               automation_details=RunAutomationDetails(
                 description=Message(text="Software composition analysis scan with CheckmarxOne SCA"),
                 id=RunFactory.make_run_id(project_id, scan_id),
                 guid=scan_id,
                 correlation_guid=project_id),  
              column_kind="unicodeCodePoints")
