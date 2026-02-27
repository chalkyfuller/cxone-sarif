from typing import Dict, List, Union
from cxone_api import CxOneClient
from cxone_api.util import json_on_ok, page_generator
from sarif_om import (Run, 
                      ToolComponent, 
                      ReportingDescriptor,
                      MultiformatMessageString, 
                      Result,
                      Message,
                      Location,
                      PhysicalLocation,
                      ArtifactLocation,
                      Region,
                      RunAutomationDetails,
                      Tool,
                      CodeFlow,
                      ThreadFlow,
                      ThreadFlowLocation)
from cxone_api.low.sast_metadata import retrieve_scan_metadata, retrieve_scan_metrics
from cxone_api.low.sast_results import retrieve_sast_scan_results
from cxone_api.low.api import retrieve_apisec_security_risks, retrieve_risk_details
from cxone_sarif.sast_query_cache import QueryCache
from cxone_sarif.run_factory import RunFactory
from cxone_sarif.utils import normalize_file_uri, SeverityTranslator
from jsonpath_ng import parse
import uuid,requests,hashlib,urllib
from pathlib import Path
from dataclasses import dataclass
from dataclasses_json import dataclass_json

@dataclass_json
@dataclass(frozen=True)
class ApiSecResult:
  risk_id : str
  http_method : str
  endpoint_path : str
  similarityID : str
  line_num : int
  source_file : str
  source_node : str

class SastRun(RunFactory):

  __metrics_scannedFiles = parse("$.scannedFilesPerLanguage")
  __results_queryIDs = parse("$.results[*].queryID")

  __cache = QueryCache()


  @staticmethod
  def get_tool_guid() -> str:
    return "1ca3e5a3-f84e-43aa-8b7c-fe39c2cecac4"

  @staticmethod
  async def __partial_file_descriptor_factory(language : str, count : int) -> ReportingDescriptor:
    desc = MultiformatMessageString(text="Some files were only partially parsed during the scan.")

    return ReportingDescriptor(
      id="SAST-PARTIAL-FILES-LANG",
      name="SastPartialFilesByLanguage",
      guid=str(uuid.uuid4()),
      help=RunFactory._default_help,
      help_uri=RunFactory._default_help_uri,
      message_strings={"language" : MultiformatMessageString(text=language),
                       "partiallyGoodFiles" : MultiformatMessageString(text=str(count))},
      short_description=desc, full_description=desc)

  @staticmethod
  async def __bad_file_descriptor_factory(language : str, count : int) -> ReportingDescriptor:
    desc = MultiformatMessageString(text="Some files failed to be parsed.  The contents of the file may not be syntactically valid or is not understood by the parser.")

    return ReportingDescriptor(
      id="SAST-BAD-FILES-LANG",
      name="SastBadFilesByLanguage",
      guid=str(uuid.uuid4()),
      message_strings={"language" : MultiformatMessageString(text=language),
                       "badFiles" : MultiformatMessageString(text=str(count))},
      short_description=desc, full_description=desc)
  
  @staticmethod
  async def __notifications_factory(metrics : Dict) -> List[ReportingDescriptor]:
    descriptors = []
    found = SastRun.__metrics_scannedFiles.find(metrics)

    if len(found) > 0 and found[0].value is not None:
      reported = found[0].value
      for lang in reported.keys():
        if 'partiallyGoodFiles' in reported[lang].keys() and int(reported[lang]['partiallyGoodFiles']) > 0:
          descriptors.append(await SastRun.__partial_file_descriptor_factory(lang, int(reported[lang]['partiallyGoodFiles'])))
        if 'badFiles' in reported[lang].keys() and int(reported[lang]['badFiles']) > 0:
          descriptors.append(await SastRun.__bad_file_descriptor_factory(lang, int(reported[lang]['badFiles'])))
    
    return descriptors
  
  @staticmethod
  async def __fetch_results_with_cached_descriptions(client : CxOneClient, **kwargs) -> requests.Response:
    response = await retrieve_sast_scan_results(client, **kwargs)
    await SastRun.__cache.add (client, set([x.value for x in SastRun.__results_queryIDs.find(json_on_ok(response))]))
    return response
  
  @staticmethod
  def __make_description(description : str, source_node : Dict, sink_node : Dict, apisec_results : List[ApiSecResult], viewer_link : str, similarity_id : Union[str,None]) -> Message:
    text = markdown = description

    def get_or_unknown(node, key):
      if key in node.keys():
        return node[key]
      else:
        return "unknown"

    if source_node is not None:
      text = text.replace("@SourceFile", get_or_unknown(source_node, 'fileName')) \
        .replace("@SourceMethod", get_or_unknown(source_node, 'method')) \
        .replace("@SourceLine", str(get_or_unknown(source_node, 'line'))) \
        .replace("@SourceElement", get_or_unknown(source_node, 'name'))

      markdown = markdown.replace("@SourceFile", f"**{get_or_unknown(source_node, 'fileName')}**") \
        .replace("@SourceMethod", f"**{get_or_unknown(source_node, 'method')}**") \
        .replace("@SourceLine", f"**{str(get_or_unknown(source_node, 'line'))}**") \
        .replace("@SourceElement", f"**{get_or_unknown(source_node, 'name')}**")

    if sink_node is not None:
      text = text.replace("@DestinationFile", get_or_unknown(sink_node, 'fileName')) \
        .replace("@DestinationMethod", get_or_unknown(sink_node, 'method')) \
        .replace("@DestinationLine", str(get_or_unknown(sink_node, 'line'))) \
        .replace("@DestinationElement", get_or_unknown(sink_node, 'name'))

      markdown = markdown.replace("@DestinationFile", f"**{get_or_unknown(sink_node, 'fileName')}**") \
        .replace("@DestinationMethod", f"**{get_or_unknown(sink_node, 'method')}**") \
        .replace("@DestinationLine", f"**{str(get_or_unknown(sink_node, 'line'))}**") \
        .replace("@DestinationElement", f"**{get_or_unknown(sink_node, 'name')}**")

      if viewer_link is not None:
        markdown += f" [View in CheckmarxOne]({viewer_link})"
        text += f"\n[View in CheckmarxOne]{{{viewer_link}}}"

      if apisec_results is not None:
        text += "\n\nAPI Endpoints:\n"
        markdown += "\n\n**API Endpoints:**\n"

        for ares in apisec_results:
          text += f"{ares.http_method} {ares.endpoint_path}\n"
          markdown += f"* {ares.http_method} {ares.endpoint_path}\n"
      
    # Handle similarity ID appending
    if similarity_id is not None:
      similarity_suffix = f"\nSIMID:{similarity_id}\n"
      text += similarity_suffix
      markdown += similarity_suffix

    return Message(text=text, markdown=markdown)

  @staticmethod
  async def __ApiSecResult_factory(client : CxOneClient, risk_result : Dict) -> ApiSecResult:

    risk_id = SastRun.get_value_safe("risk_id", risk_result)
    risk_details = json_on_ok(await retrieve_risk_details(client, risk_id))

    return ApiSecResult(
      risk_id=risk_id,
      http_method=SastRun.get_value_safe("http_method", risk_result),
      endpoint_path=SastRun.get_value_safe("url", risk_result),
      similarityID=SastRun.get_value_safe("similarity_id", risk_details),
      line_num=SastRun.get_value_safe("line_number", risk_details),
      source_file=SastRun.get_value_safe("source_file", risk_details),
      source_node=SastRun.get_value_safe("source_node", risk_details),
    )

  @staticmethod
  async def __make_apisec_index(client : CxOneClient, scan_id : str) -> Dict[str, Dict[str, ApiSecResult]]:
    index = {}

    async for risk in page_generator(retrieve_apisec_security_risks, array_element="entries", 
                                     offset_param="page", offset_init_value=1, 
                                     offset_is_by_count=False, client=client, scan_id=scan_id):
      key = SastRun.get_value_safe("sast_risk_id", risk)
      method = SastRun.get_value_safe("http_method", risk)

      if key not in index.keys():
        index[key] = {method : await SastRun.__ApiSecResult_factory(client, risk)}
      elif method not in index[key].keys():
        index[key][method] = await SastRun.__ApiSecResult_factory(client, risk)
    
    return index
  
  @staticmethod
  async def factory(client : CxOneClient, omit_apisec : bool, append_similarity_id : bool, project_id : str, scan_id : str, 
                    platform : str, version : str, organization : str, info_uri : str) -> Run:


    apisec_index = await SastRun.__make_apisec_index(client, scan_id) if not omit_apisec else {}

    metrics = json_on_ok(await retrieve_scan_metrics(client, scan_id))

    rules = {}
    results = []

    async for result in page_generator(SastRun.__fetch_results_with_cached_descriptions, "results", client=client, scan_id=scan_id, limit=200):
      state = SastRun.get_value_safe("state", result)
      if state is not None and state == "NOT_EXPLOITABLE":
        continue
      
      group = SastRun.get_value_safe("group", result)
      query_name = SastRun.get_value_safe("queryName", result)
      queryId = int(result['queryID'])
      rule_id_key = f"{group}.{query_name}"

      query_desc = await SastRun.__cache.get(client, queryId)

      # Cache the rule if it hasn't been seen before.
      if queryId not in rules.keys():
        rules[queryId] = ReportingDescriptor(
          id = rule_id_key,
          name=SastRun.make_pascal_case_identifier(query_name),
          short_description = 
            MultiformatMessageString(text=SastRun.make_title(SastRun.get_value_safe("languageName", result), SastRun.get_value_safe("queryName", result))),
          full_description = MultiformatMessageString(text=RunFactory.get_value_safe_with_default("risk", query_desc, "Not available.")),
          help = MultiformatMessageString(text=RunFactory.get_value_safe_with_default("generalRecommendations", query_desc, "Not available.")),
          help_uri = SastRun._default_help_uri,
          properties = {
            "queryID" : queryId,
            "security-severity" : str(SastRun.get_value_safe("cvssScore", result)),
          })

      nodes = SastRun.get_value_safe("nodes", result)
      threadflow_locations = None
      cur_loop_loc = None
      filePathsFingerprint = hashlib.sha256()
      if nodes is not None:
        for node in nodes:
          filePathsFingerprint.update(bytes(SastRun.get_value_safe("fileName", node), "UTF-8"))

          def calc_end_column(node : dict):
            column_val = SastRun.get_value_safe("column", node)
            if column_val is None:
              return None

            try:
              column_val = int(column_val)
            except Exception:
              return None
            
            length_val = SastRun.get_value_safe("length", node)
            if length_val is None:
              return None
            
            try:
              length_val = int(length_val)
            except Exception:
              return None
            
            return column_val + length_val
          

          # Last node is the sink, this will be reported as the single
          # location per the Sarif spec.  (Sarif spec says this should
          # have only one element since SAST results don't report related
          # locations for each flow.)  After all the loops, sink_loc will be the
          # sink.
          cur_loop_loc = Location(
              id=0, 
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=normalize_file_uri(SastRun.get_value_safe('fileName', node))
                ),
              region=Region(
                start_line=SastRun.get_value_safe("line", node),
                start_column=SastRun.get_value_safe("column", node),
                end_column=calc_end_column(node),
                source_language=SastRun.get_value_safe("languageName", result),
                properties={
                  "methodName" : SastRun.get_value_safe("method", node),
                  "methodLine" : SastRun.get_value_safe("methodLine", node),
                  "domType" : SastRun.get_value_safe("domType", node),
                  "nodeID" : SastRun.get_value_safe("nodeID", node),
                  "fullName" : SastRun.get_value_safe("fullName", node)
                }
              )))
          
          thread_flow_loc = ThreadFlowLocation(
            location=cur_loop_loc
          )

          if threadflow_locations is None:
            threadflow_locations = [thread_flow_loc]
          else:
            threadflow_locations.append(thread_flow_loc)

      props = {
          "state" : result['state'],
          "status" : result['status'],
          "severity" : result['severity'],
          "queryID" : queryId,
          "foundAt" : result['foundAt'],
          "firstScanID" : result['firstScanID'],
          "firstFoundAt" : result['firstFoundAt'],
          "cweID" : result['cweID'],
          "cvssScore" : result['cvssScore'],
          "confidenceLevel" : result['confidenceLevel'],
          "compliances" : result['compliances'],
        }
          
      if not omit_apisec and result['resultHash'] in apisec_index.keys():
        api_sec_props = list(apisec_index[result['resultHash']].values())
        props['apisec'] = [x.to_dict() for x in api_sec_props]
      else:
        api_sec_props = None

      viewer_link = f"{client.display_endpoint.rstrip('/')}/" + \
          str(Path(f"sast-results/{project_id}/{scan_id}?resultId={urllib.parse.quote_plus(result['pathSystemID'])}"))

      results.append(Result(
        message = SastRun.__make_description(RunFactory.get_value_safe_with_default("resultDescription", query_desc, "Not available."), 
                    nodes[0], nodes[-1:][0], api_sec_props, viewer_link, 
                    str(result['similarityID']) if append_similarity_id else None),
        rule_id = rule_id_key,
        level=RunFactory.translate_severity_to_level(SastRun.get_value_safe('severity', result)),
        locations=[cur_loop_loc] if cur_loop_loc is not None else None,
        hosted_viewer_uri=viewer_link,
        partial_fingerprints={
          "similarityID" : str(result['similarityID']),
          "queryKey" : rule_id_key,
          "nodeFilePathsSha256" : filePathsFingerprint.hexdigest(),
        },
        properties=props,
        code_flows=[CodeFlow(thread_flows=[ThreadFlow(locations=threadflow_locations)])] if threadflow_locations is not None else None
      ))
    

    driver = ToolComponent(name="CheckmarxOne-SAST", guid=SastRun.get_tool_guid(),
                           product_suite=platform,
                           full_name=f"Checkmarx SAST {version}",
                           short_description=MultiformatMessageString(text="Static code analysis scanner."),
                           # 3.19.2 at least one of version or semanticVersion SHOULD be present
                           semantic_version=version,
                           information_uri=info_uri,
                           organization=organization,
                           notifications = await SastRun.__notifications_factory(metrics),
                           rules = [r for r in rules.values()],
                           properties={
                             "scanMetrics" : metrics
                           })

    metadata = json_on_ok(await retrieve_scan_metadata(client, scan_id))
    tool = Tool(driver=driver,
                properties={
                  "scanMetadata" : metadata
                  })
    
    return Run(tool=tool,
               results=results,
               automation_details=RunAutomationDetails(
                 description=Message(text="Static analysis scan with CheckmarxOne SAST"),
                 id=RunFactory.make_run_id(project_id, scan_id),
                 guid=scan_id,
                 correlation_guid=project_id),
               column_kind="unicodeCodePoints")
  