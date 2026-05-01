# CVE Coverage – AEM Hacker

This document tracks every check implemented in `aem_hacker.py`, its CVE reference
(where one exists), affected AEM versions, CVSS severity, and the handler name so
engineers can quickly locate and extend the code.

---

## ✅ Checks Currently Implemented

| Handler name | Finding class | CVE / Reference | Type | Severity | Affected versions | Notes |
|---|---|---|---|---|---|---|
| `set_preferences` | SetPreferences | *(no CVE)* | Reflected XSS | Medium | AEM 6.x | `setPreferences.jsp` reflects `keymap` param without encoding |
| `merge_metadata` | MergeMetadataServlet | *(no CVE)* | Reflected XSS | Medium | AEM 6.x | `MergeMetadataServlet` reflects `path` param |
| `get_servlet` | DefaultGetServlet | *(no CVE)* | Info Disclosure | Medium | AEM 6.x | JCR node data returned as JSON without auth |
| `querybuilder_servlet` | QueryBuilderJsonServlet / QueryBuilderFeedServlet | *(no CVE)* | Info Disclosure | Medium | AEM 6.x | `/bin/querybuilder.json` and `.feed` unauthenticated |
| `gql_servlet` | GQLServlet | *(no CVE)* | Info Disclosure | Medium | AEM 6.x | `/bin/wcm/search/gql.json` returns JCR data |
| `guide_internal_submit_servlet` | GuideInternalSubmitServlet | **CVE-2019-8086** | XXE | Critical (9.8) | AEM 6.2–6.5 | `GuideInternalSubmitServlet` processes XML without disabling external entities; APSB19-22 |
| `post_servlet` | POSTServlet | *(no CVE)* | RCE/XSS | High | AEM 6.x | `SlingPostServlet` accessible without auth |
| `create_new_nodes` | CreateJCRNodes | *(no CVE)* | RCE/XSS | High | AEM 6.x | Anonymous or default-cred users can POST new JCR nodes |
| `create_new_nodes2` | CreateJCRNodes 2 | *(no CVE)* | RCE/XSS | High | AEM 6.x | Geometrixx sample users can create JCR nodes |
| `loginstatus_servlet` | LoginStatusServlet / AEM with default credentials | *(no CVE)* | Credential Bruteforce / Default Creds | Medium/Critical | AEM 6.x | `/system/sling/loginstatus` reflects auth state; also tests CREDS list |
| `userinfo_servlet` | UserInfoServlet | *(no CVE)* | Credential Bruteforce | Medium | AEM 6.x | `/libs/cq/security/userinfo.json` |
| `felix_console` | FelixConsole | *(no CVE)* | RCE | Critical | AEM 6.x | Felix OSGi Web Console accessible with `admin:admin` |
| `wcmdebug_filter` | WCMDebugFilter | **CVE-2016-7882** | Reflected XSS | Medium (6.1) | AEM 6.0–6.2 | `?debug=layout` reflects `res=` and `sel=` params; APSB16-38 |
| `wcmsuggestions_servlet` | WCMSuggestionsServlet | *(no CVE)* | Reflected XSS | Medium | AEM 6.x | `pre` param reflected unencoded in suggestions response |
| `crxde_crx` | CRXDE Lite/CRX | *(no CVE)* | Info Disclosure / RCE | High | AEM 6.x | CRXDE Lite, CRX Explorer, CRX search, Package Manager accessible |
| `salesforcesecret_servlet` | SalesforceSecretServlet | **CVE-2018-5006** | SSRF | High (7.5) | AEM 6.1–6.4 | `authorization_url` / `instance_url` params make server-side HTTP requests; APSB18-23 |
| `reportingservices_servlet` | ReportingServicesServlet | **CVE-2018-12809** | SSRF | High (7.5) | AEM 6.1–6.4 | `url` param in ContentInsight proxy makes server-side HTTP requests; APSB18-23 |
| `sitecatalyst_servlet` | SiteCatalystServlet | *(no CVE)* | SSRF → potential RCE | High | AEM 6.x | `datacenter` param used as HTTP target without validation |
| `autoprovisioning_servlet` | AutoProvisioningServlet | *(no CVE)* | SSRF → potential RCE | High | AEM 6.x | `analytics.server` param used as HTTP target; see 0ang3el slides |
| `opensocial_proxy` | Opensocial (shindig) proxy | *(no CVE)* | SSRF | Medium | AEM 6.x | OpenSocial Shindig proxy `url` param |
| `opensocial_makeRequest` | Opensocial (shindig) makeRequest | *(no CVE)* | SSRF | Medium | AEM 6.x | OpenSocial Shindig `makeRequest` endpoint |
| `swf_xss` | Reflected XSS via SWF | *(no CVE)* | Reflected XSS | Medium | AEM 6.x (legacy) | AEM-bundled SWF files allow XSS via Flash params |
| `externaljob_servlet` | ExternalJobServlet | *(no CVE)* | Java Deserialization | High | AEM 6.x | `/libs/dam/cloud/proxy` accepts untrusted serialised data; see 0ang3el slides |
| `webdav` | WebDAV exposed | **CVE-2015-1833** | XXE / Stored XSS | High | AEM 6.x (Jackrabbit) | WebDAV `WWW-Authenticate: WebDAV` triggers check for CVE-2015-1833 |
| `groovy_console` | GroovyConsole | *(no CVE)* | RCE | Critical | AEM 6.x | ACS Groovy Console exposed, allows script execution |
| `acs_tools` | ACSTools | *(no CVE)* | RCE | Critical | AEM 6.x | ACS AEM Tools Fiddle endpoint allows JSP execution |
| `version_disclosure` | AEM Version Disclosure / AEM Version Disclosure (ProductInfo) | *(no CVE)* | Info Disclosure (hardening) | Medium | All AEM versions | Login page and `/system/console/productinfo` leak exact AEM build number |
| `open_redirect` | OpenRedirect | **CVE-2023-29297** | Open Redirect | Medium (6.1) | AEM 6.5.16.0 and earlier | Login `resource` param redirects to arbitrary external URL; APSB23-31 |
| `auth_bypass_cve_2023_38205` | AuthBypassFelixConsole / AuthBypassCRX | **CVE-2023-38205** / Detectify 2021 | Auth Bypass | Critical (9.8) | AEM 6.5.17.0 and earlier | Double-slash dispatcher bypass reaches Felix Console and CRX Package Manager without credentials; APSB23-43 |
| `xss_aem_forms` | XSS in AEM Forms | **CVE-2021-36063** | Reflected XSS | Medium | AEM Forms 6.5.10.0 and earlier | AEM Forms components reflect user input unencoded; APSB21-77 |
| `xss_reflected_cve_2022` | XSS in AEM TouchUI | **CVE-2022-30677** / **CVE-2022-30679** | Reflected XSS | Medium | AEM 6.5.13.0 and earlier | TouchUI and workflow console components reflect URL selectors/params unencoded; APSB22-40 |
| `ssrf_cve_2021_40722` | SSRF CVE-2021-40722 | **CVE-2021-40722** | SSRF | High (7.5) | AEM 6.5.10.0 and earlier (on-prem) | Unauthenticated SSRF via content-sync/replication proxy endpoint; APSB21-99 |

---

## ❌ Known AEM CVEs / Checks NOT Yet Implemented

The following items from the project issue tracker are not yet covered.
PRs are welcome — use the CVE test-reproduction issue template at
`.github/ISSUE_TEMPLATE/cve-test-reproduction.yml` to document your reproduction
before sending a PR.

### Authentication Bypass / Access Control

| CVE | Type | Severity | Notes | PSIRT Bulletin |
|---|---|---|---|---|
| **CVE-2019-8081** | Auth Bypass | High | Auth bypass in AEM 6.2–6.5; allows unauthenticated access to sensitive JCR content | [APSB19-48](https://helpx.adobe.com/security/products/experience-manager/apsb19-48.html) |
| **CVE-2023-29298** | Auth Bypass | Critical | Dispatcher bypass via `;%0a` suffix in URL path, allows reaching protected servlets; the patch for this was itself bypassed by CVE-2023-38205 | [APSB23-31](https://helpx.adobe.com/security/products/experience-manager/apsb23-31.html) |

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

## References

- [Adobe Security Bulletins](https://helpx.adobe.com/security/security-bulletin.html)
- [NVD – Adobe Experience Manager](https://nvd.nist.gov/vuln/search/results?query=adobe+experience+manager)
- [Detectify: CRX Package Manager Bypass (2021)](https://labs.detectify.com/writeups/undocumented-authentication-bypass-issue-in-aem-package-manager-blog-updated/)
- [CVEDetails – AEM](https://www.cvedetails.com/product/33138/Adobe-Experience-Manager.html)
- [0ang3el – Hunting for Security Bugs in AEM (Hacktivity)](https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps)
- [Frans Rosén – A story of the passive aggressive sysadmin of AEM](https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem)
