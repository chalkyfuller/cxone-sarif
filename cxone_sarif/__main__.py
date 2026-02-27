import asyncio
import os
import logging
import sys
from typing import Dict
from asyncio import Semaphore
from pathlib import Path
import aiofiles
import importlib
import cxone_api as cx
from cxone_sarif.log import bootstrap
from cxone_sarif import get_sarif_v210_log_for_scan
from cxone_sarif.opts import ReportOpts, SastOpts, ScaOpts
from cxone_sarif.__agent__ import __agent__
from cxone_sarif.__version__ import __version__

DEFAULT_LOGLEVEL = "INFO"


async def main():
    """Usage: cxone-sarif [-h | --help | -v | --version] --tenant TENANT (--region REGION | (--url URL --iam-url IAMURL))
                     (--api-key APIKEY | (--client OCLIENT --secret OSECRET) | --use-env-oauth | --use-env-api-key)
                     [--level LOGLEVEL] [--log-file LOGFILE] [--timeout TIMEOUT] [--delay DELAY] [--retries RETRIES] [--proxy IP:PORT]
                     [--outdir OUTDIR] [--no-sast] [--no-sast-apisec] [--no-sca] [--no-kics] [--no-containers]
                     [--with-sast-simid] [--sca-group-by GROUPBY] [-qk] [-t THREADS] SCANIDS...

    SCANIDS...          One or more space-separated scan ids that will each generate a file containing a SARIF log.

    -h --help           Show this help.

    -v --version        Show version and exit.

    --tenant TENANT     The name of the tenant for use with the specified CheckmarxOne service endpoint.

    Multi-Tenant CheckmarxOne options:
    --region REGION     The multi-tenant region where the tenant is hosted.
                        Use one of: {CXREGIONS}

    Single-Tenant CheckmarxOne options:
    --url URL           The URL for the single-tenant CheckmarxOne portal.
    --iam-url IAMURL    The URL for the single-tenant CheckmarxOne IAM endpoint.

    Authorization Options:

    --api-key APIKEY    The API key to be used for authentication.
    --use-env-api-key   Retrieve the API key from the environment variable CX_APIKEY.

    --client OCLIENT    The name of the OAuth client to be used for authentication.
    --secret OSECRET    The OAuth secret associated with the OAuth client.
    --use-env-oauth     Retrieve the OAuth credentials from the environment variables CX_OCLIENT and CX_OSECRET.

    -- Additional Options --

    CheckmarxOne API Options
    --timeout TIMEOUT   The timeout, in seconds, for API operations.  [default: 60]

    --retries RETRIES   The number of API call retries on failure.   [default: 3]

    --delay DELAY       The maximum seconds to delay between retries for API call failures. [default: 15]

    -k                  Ignore SSL verification failures.

    --proxy HOST_PORT   A value in the form of HOST:PORT that is used as a proxy server.


    SARIF Log Generation Options:
    --no-sast           Suppress static code analysis scan results.
    --no-sast-apisec    Do not augment SAST results with API security scan results.


    --no-sca            Suppress software composition analysis scan results.

    --no-kics           Suppress infrastructure as code scan results.

    --no-containers     Suppress container security scan results.

    --outdir OUTDIR     Directory where to write the SARIF log files.   [default: .]

    -t THREADS          The number of concurrent scan report generations.  [default: 2]
                        Keep at 2 when using with multi-tenant Checkmarx One for
                        best stability.  The maximum is 8.

    SAST Options:
    --with-sast-simid   Append similarity ID to SAST result descriptions. [default: false]

    SCA Options:
    --sca-group-by GROUPBY
                        How to group SCA findings. [default: none]
                        Options:
                          none                        - Individual CVE findings (default)
                          package-manifest-severity   - Group by package version + manifest + severity
                          package-manifest            - Group by package version + manifest (uses max severity)

    Logging Output Options:
    --level LOGLEVEL    Log level [default: INFO]
                        Use: DEBUG, INFO, WARNING, ERROR, CRITICAL

    --log-file LOGFILE  A file where logs are written.

    -q                  Do not output logs to the console.

    """

    try:
        # The docopt module may not be installed unless the [cli] extra is installed
        # so load it dynamically when executing as a script.
        docopt_lib = importlib.import_module("docopt")
        docopt = docopt_lib.docopt

        args = docopt(
            main.__doc__.replace("{CXREGIONS}", ",".join(cx.ApiRegionEndpoints.keys())),
            version=f"cxone-sarif {__version__}",
        )

        bootstrap(
            DEFAULT_LOGLEVEL if args["--level"] is None else args["--level"],
            not args["-q"],
            args["--log-file"],
        )

        _log = logging.getLogger("main")
        _log.info(f"{__agent__}/{__version__} start...")

        if not os.path.isdir(args["--outdir"]):
            _log.error(
                f"Output directory {args['--outdir']} does not exist, exiting..."
            )
            exit(1)
        else:
            _log.info(f"Report files will be written at: {args['--outdir']}")

        if args["--region"] is not None:
            auth_endpoint = cx.AuthRegionEndpoints[args["--region"]](args["--tenant"])
            api_endpoint = cx.ApiRegionEndpoints[args["--region"]]()
        else:
            auth_endpoint = cx.CxOneAuthEndpoint(args["--tenant"], args["--iam-url"])
            api_endpoint = cx.CxOneApiEndpoint(args["--url"])

        if args["--proxy"] is not None:
            proxy = {"http": args["--proxy"], "https": args["--proxy"]}
        else:
            proxy = None

        client = cxone_client_factory(args, auth_endpoint, api_endpoint, proxy)

        concurrency = Semaphore(max(1, min(int(args["-t"]), 8)))

        if len(args["SCANIDS"]) > len(set(args["SCANIDS"])):
            _log.warning(
                "Some scan ids that were defined multiple times, only one log will be produced per unique scan id."
            )

        task_result, _ = await asyncio.wait(
            [
                asyncio.get_running_loop().create_task(
                    execute_on_scanid(
                        client,
                        scanid,
                        args["--outdir"],
                        ReportOpts(
                            SastOpts=SastOpts(
                                SkipSast=args["--no-sast"],
                                OmitApiResults=args["--no-sast-apisec"],
                                AppendSimilarityId=args["--with-sast-simid"],
                            ),
                            ScaOpts=ScaOpts(
                                SkipSca=args["--no-sca"],
                                GroupBy=args["--sca-group-by"] if args["--sca-group-by"] is not None else ScaOpts.GROUP_NONE,
                            ),
                            SkipKics=args["--no-kics"],
                            SkipContainers=args["--no-containers"],
                        ),
                        concurrency,
                    )
                )
                for scanid in set(args["SCANIDS"])
            ]
        )

        exit(max([x.result() for x in task_result]))
    except ModuleNotFoundError:
        print("The CLI interface is not operational since it appears [cli] extra is not installed.")
        exit(2)
    except docopt_lib.DocoptExit as bad_args:
        print("Incorrect arguments provided.")
        print(bad_args)
        exit(1)
    except Exception as ex:
        print(ex)
        exit(1)

    _log.info(f"{__agent__}/{__version__} complete.")


async def execute_on_scanid(
    client: cx.CxOneClient,
    scan_id: str,
    outdir: str,
    opts: ReportOpts,
    concurrency: Semaphore,
) -> None:

    async with concurrency:
        log = logging.getLogger(f"execute_on_scanid:{scan_id}")
        try:

            sarif_log = await get_sarif_v210_log_for_scan(client, opts, scan_id, True)

            async with aiofiles.open(Path(outdir) / f"{scan_id}.sarif", "wt") as fp:
                await fp.write(sarif_log.asjson())
                await fp.flush()

            return 0
        except BaseException as ex:
            log.exception(ex)
            print(scan_id, file=sys.stderr)
            return 100


def cxone_client_factory(
    args: Dict,
    auth_endpoint: cx.CxOneAuthEndpoint,
    api_endpoint: cx.CxOneApiEndpoint,
    proxy: Dict,
) -> cx.CxOneClient:
    if args["--api-key"] is not None or args["--use-env-api-key"]:

        if args["--api-key"] is not None:
            key = args["--api-key"]
        elif "CX_APIKEY" in os.environ.keys():
            key = os.environ["CX_APIKEY"]
        else:
            raise Exception("Environment variable CX_APIKEY is not defined.")

        return cx.CxOneClient.create_with_api_key(
            key,
            f"{__agent__}/{__version__}",
            auth_endpoint,
            api_endpoint,
            timeout=int(args["--timeout"]),
            retries=int(args["--retries"]),
            retry_delay_s=int(args["--delay"]),
            proxy=proxy,
            ssl_verify=not (args["-k"]),
        )

    elif (args["--client"] is not None and args["--secret"] is not None) or args[
        "--use-env-oauth"
    ]:

        if args["--client"] is not None and args["--secret"] is not None:
            client = args["--client"]
            secret = args["--secret"]
        elif "CX_OCLIENT" in os.environ.keys() and "CX_OSECRET" in os.environ.keys():
            client = os.environ["CX_OCLIENT"]
            secret = os.environ["CX_OSECRET"]
        else:
            raise Exception(
                "One or both environment variables CX_OCLIENT and CX_OSECRET are not defined."
            )

        return cx.CxOneClient.create_with_oauth(
            client,
            secret,
            f"{__agent__}/{__version__}",
            auth_endpoint,
            api_endpoint,
            timeout=int(args["--timeout"]),
            retries=int(args["--retries"]),
            retry_delay_s=int(args["--delay"]),
            proxy=proxy,
            ssl_verify=not (args["-k"]),
        )


if __name__ == "__main__":
    asyncio.run(main())


def cli_entry():
    asyncio.run(main())
