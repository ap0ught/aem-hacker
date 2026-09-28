#!/usr/bin/env python3
"""Test suite for aem_hacker.py.

Stdlib only (unittest) so it runs anywhere the tool runs:

    python3 -m unittest discover -s tests -v
    ./tests/run_tests.sh

The tests fall into three groups:

  * regression guards -- behaviour that already works and must keep working;
  * bug reproductions -- tests that fail on the unfixed code and pass after;
  * contract tests -- every registered check must be reachable, callable, and
    safe to run against a target that exposes nothing.
"""

import contextlib
import io
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aem_hacker  # noqa: E402
from mock_aem import FELIX_BUNDLES, LOGIN_PAGE, MockAEM, Route  # noqa: E402


@contextlib.contextmanager
def scanner(**attrs):
    """Import-time globals aem_hacker relies on, neutralised for fast tests.

    ``d`` (the SSRF callback store) and ``token`` are reset too: they are module
    globals that outlive a single check, so a leaked callback from one test would
    otherwise make the next test report a phantom finding.
    """
    keys = ("request_delay", "time", "d", "token", "extra_headers", "credentials")
    old = {k: getattr(aem_hacker, k) for k in keys}
    aem_hacker.d = {}
    aem_hacker.token = "TESTTOKEN"
    for k, v in attrs.items():
        setattr(aem_hacker, k, v)
    try:
        yield
    finally:
        for k, v in old.items():
            setattr(aem_hacker, k, v)


def no_sleep(_seconds):
    """Drop-in for time.sleep; counts calls so tests can assert on pacing."""
    no_sleep.calls.append(_seconds)
    return None


no_sleep.calls = []


def free_port():
    """Ask the OS for an unused TCP port and release it again."""
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_handler(handler, mock_target, my_host=None):
    """Invoke a single registered check against *mock_target*."""
    with scanner(request_delay=0, time=mock.Mock(sleep=no_sleep)):
        return handler(mock_target.url, my_host or "127.0.0.1:1", False, {})


def run_all(mock_target, my_host=None):
    """Run every registered check, returning (name, findings-or-exception)."""
    out = {}
    for name, handler in aem_hacker.registered.items():
        try:
            out[name] = run_handler(handler, mock_target, my_host)
        except Exception as exc:  # a check must never take the scan down
            out[name] = exc
    return out


# ---------------------------------------------------------------------------
# Contract: every check is reachable, callable, and safe
# ---------------------------------------------------------------------------


class TestCheckContract(unittest.TestCase):
    def test_no_silently_dead_checks(self):
        """Checks must be registered, not merely defined.

        Regression: the @register line for these two was commented out, so the
        README advertised checks (CurrentUserServlet, Reports) that could never
        run and --listhandlers never mentioned them.
        """
        for name in ("currentuser_servlet", "reports"):
            self.assertIn(name, aem_hacker.registered, f"{name} check is dead code")

    def test_no_unreachable_handler_functions(self):
        """No top-level function may be a silently dead check.

        Any check decorated with @register is reachable. Everything else must be
        a known helper, otherwise someone wrote a check nobody can invoke. Uses
        the AST rather than a regex so quoting style cannot fool it.
        """
        import ast

        helpers = {
            "random_string",
            "register",
            "normalize_url",
            "content_type",
            "error",
            "http_request",
            "http_request_multipart",
            "preflight",
            "parse_args",
            "run_detector",
            "main",
            "emit",
            "find_free_port",
            "authenticated_as",
            "get_session",
            "build_headers",
            "parse_credential",
            "basic_auth_header",
            "credentials_to_probe",
            "primary_auth_header",
            "username_of",
        }
        with open(aem_hacker.__file__) as fh:
            tree = ast.parse(fh.read())
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            registered = any(
                isinstance(d, ast.Call) and getattr(d.func, "id", None) == "register"
                for d in node.decorator_list
            )
            if not registered and node.name not in helpers:
                self.fail(
                    f"function {node.name} (aem_hacker.py:{node.lineno}) is neither a "
                    f"known helper nor decorated with @register -- it is unreachable"
                )

    def test_every_handler_has_uniform_signature(self):
        for name, handler in aem_hacker.registered.items():
            code = handler.__code__
            self.assertEqual(
                code.co_argcount,
                4,
                f"{name} must accept (base_url, my_host, debug, proxy)",
            )

    def test_all_checks_run_against_empty_target(self):
        """No check may raise when the target exposes nothing."""
        with MockAEM() as target:
            results = run_all(target)
        crashed = {n: r for n, r in results.items() if isinstance(r, Exception)}
        self.assertEqual(crashed, {}, "checks raised against a 404-only target")

    def test_no_findings_against_empty_target(self):
        """A target exposing nothing must produce zero findings (no FP noise)."""
        with MockAEM() as target:
            results = run_all(target)
        findings = {n: r for n, r in results.items() if r}
        self.assertEqual(findings, {}, "false positives on a 404-only target")

    def test_every_check_reports_findings_as_findings(self):
        with MockAEM(routes=[Route(r".*", body=LOGIN_PAGE)]) as target:
            for name, handler in aem_hacker.registered.items():
                for f in run_handler(handler, target):
                    self.assertTrue(f.name, f"{name} produced an unnamed finding")
                    self.assertTrue(f.url, f"{name} produced a finding with no url")
                    self.assertTrue(
                        f.description, f"{name} produced a finding with no description"
                    )


# ---------------------------------------------------------------------------
# Bug reproductions
# ---------------------------------------------------------------------------


class TestCrashIsolation(unittest.TestCase):
    """A single misbehaving check must not discard the whole scan."""

    def _run_main(self, registered, argv):
        """Run main() with *registered* checks, returning (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(aem_hacker, "registered", registered), mock.patch.object(
            sys, "argv", ["aem_hacker.py"] + argv
        ), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), mock.patch.object(
            aem_hacker, "run_detector", lambda p: mock.Mock()
        ), mock.patch.object(
            aem_hacker.time, "sleep", no_sleep
        ), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(
            err
        ):
            try:
                code = aem_hacker.main() or 0
            except SystemExit as exc:
                code = exc.code or 0
        return code, out.getvalue(), err.getvalue()

    def test_raising_handler_does_not_lose_other_findings(self):
        def boom(base_url, my_host, debug=False, proxy=None):
            raise RuntimeError("check exploded")

        def good(base_url, my_host, debug=False, proxy=None):
            return [aem_hacker.Finding("Good", base_url, "found something")]

        code, out, err = self._run_main(
            {"boom": boom, "good": good},
            ["-u", "http://x", "--host", "127.0.0.1"],
        )
        self.assertIn(
            "found something", out, "a crashing check swallowed a real finding"
        )
        self.assertIn("boom", (out + err).lower(), "the failing check was not reported")

    def test_unknown_handler_name_is_an_error(self):
        code, out, err = self._run_main(
            {}, ["-u", "http://x", "--host", "127.0.0.1", "--handler", "typo_handler"]
        )
        self.assertNotEqual(code, 0, "an unknown --handler must not exit 0 silently")
        self.assertIn("typo_handler", out + err)

    def test_json_output_is_parseable(self):
        def good(base_url, my_host, debug=False, proxy=None):
            return [aem_hacker.Finding("Good", base_url, "found something")]

        _, out, _ = self._run_main(
            {"good": good},
            ["-u", "http://x", "--host", "127.0.0.1", "--format", "json"],
        )
        lines = [ln for ln in out.splitlines() if ln.strip()]
        payload = json.loads(lines[0])
        self.assertEqual(payload["name"], "Good")
        self.assertEqual(payload["url"], "http://x")

    def test_exit_code_signals_findings(self):
        def good(base_url, my_host, debug=False, proxy=None):
            return [aem_hacker.Finding("Good", base_url, "found something")]

        def empty(base_url, my_host, debug=False, proxy=None):
            return []

        found, _, _ = self._run_main(
            {"good": good}, ["-u", "http://x", "--host", "127.0.0.1"]
        )
        clean, _, _ = self._run_main(
            {"empty": empty}, ["-u", "http://x", "--host", "127.0.0.1"]
        )
        self.assertNotEqual(found, 0, "findings must be visible in the exit code")
        self.assertEqual(clean, 0, "a clean scan must exit 0")

    def test_ssrf_checks_are_the_only_ones_needing_a_host(self):
        """A Groovy Console scan must not demand a public callback host."""

        def good(base_url, my_host, debug=False, proxy=None):
            return []

        code, out, err = self._run_main({"good": good}, ["-u", "http://x"])
        self.assertEqual(code, 0, "a non-SSRF check was blocked on a missing --host")

    def test_ssrf_check_still_requires_a_host(self):
        def needs_host(base_url, my_host, debug=False, proxy=None):
            return []

        needs_host.ssrf = True
        code, out, err = self._run_main({"needs_host": needs_host}, ["-u", "http://x"])
        self.assertNotEqual(code, 0, "an SSRF check ran without --host")

    def test_findings_are_streamed_not_only_at_the_end(self):
        """A long scan should report as it goes, not stay silent until exit."""

        def good(base_url, my_host, debug=False, proxy=None):
            return [aem_hacker.Finding("Good", base_url, "found something")]

        buf = io.StringIO()
        snapshot = {}

        real_as_completed = aem_hacker.concurrent.futures.as_completed

        def watch(futures):
            for fut in real_as_completed(futures):
                yield fut
                # Resumed only after the first result has been handled, so this
                # captures whether findings were printed as they arrived.
                snapshot.setdefault("output_after_first_result", buf.getvalue())

        with mock.patch.object(
            aem_hacker, "registered", {"good": good}
        ), mock.patch.object(
            sys, "argv", ["aem_hacker.py", "-u", "http://x", "--host", "1.2.3.4"]
        ), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), mock.patch.object(
            aem_hacker, "run_detector", lambda p: mock.Mock()
        ), mock.patch.object(
            aem_hacker.time, "sleep", no_sleep
        ), mock.patch.object(
            aem_hacker.concurrent.futures, "as_completed", watch
        ), contextlib.redirect_stdout(
            buf
        ):
            aem_hacker.main()

        self.assertIn(
            "found something",
            snapshot.get("output_after_first_result", ""),
            "findings were buffered until the whole scan finished",
        )


class TestDefaultCredentialsFalsePositive(unittest.TestCase):
    """A rejected login must never be reported as 'default credentials work'."""

    def test_rejected_login_is_not_a_default_credential_finding(self):
        def currentuser(method, path, headers):
            if not headers.get("Authorization"):
                return b'{"authorizableId":"anonymous","id":"anonymous"}'
            return b"<html><body>401 Unauthorized</body></html>"

        with MockAEM(
            routes=[
                Route(r"/libs/granite/security/currentuser.*", body=currentuser),
                Route(r".*", status=401, body=b"<html>401 Unauthorized</html>"),
            ]
        ) as target:
            findings = run_handler(aem_hacker.registered["currentuser_servlet"], target)

        cred_hits = [
            f for f in findings if "default credentials" in f.description.lower()
        ]
        self.assertEqual(
            cred_hits,
            [],
            "a 401 on every credential was reported as working default credentials",
        )

    def test_non_json_accepted_login_is_still_reported(self):
        """The servlets also answer XML/HTML; a valid login must not be lost."""

        def currentuser(method, path, headers):
            auth = headers.get("Authorization", "")
            if not auth:
                return b'{"authorizableId":"anonymous"}'
            import base64

            decoded = base64.b64decode(auth.split(" ", 1)[-1]).decode()
            if decoded == "admin:admin":
                return b"<user userID='admin' userName='Administrator'/>"
            return b"<html>401 Unauthorized</html>"

        with MockAEM(
            routes=[Route(r"/libs/granite/security/currentuser.*", body=currentuser)]
        ) as target:
            findings = run_handler(aem_hacker.registered["currentuser_servlet"], target)

        cred_hits = [
            f for f in findings if "default credentials" in f.description.lower()
        ]
        self.assertEqual(
            len(cred_hits),
            1,
            "a working default credential in XML form was not reported",
        )

    def test_genuine_default_credential_is_still_reported(self):
        def currentuser(method, path, headers):
            auth = headers.get("Authorization", "")
            if not auth:
                return b'{"authorizableId":"anonymous"}'
            import base64

            decoded = base64.b64decode(auth.split(" ", 1)[-1]).decode()
            if decoded == "admin:admin":
                return b'{"authorizableId":"admin","profile":{}}'
            return b"<html>401 Unauthorized</html>"

        with MockAEM(
            routes=[Route(r"/libs/granite/security/currentuser.*", body=currentuser)]
        ) as target:
            findings = run_handler(aem_hacker.registered["currentuser_servlet"], target)

        cred_hits = [
            f for f in findings if "default credentials" in f.description.lower()
        ]
        self.assertEqual(
            len(cred_hits), 1, "a working default credential was not reported"
        )
        self.assertIn("admin", cred_hits[0].description)
        # The username is reported; the password never is, not even for a
        # publicly known default credential.
        self.assertNotIn("admin:admin", cred_hits[0].description)


class TestRequestPacing(unittest.TestCase):
    """--delay is documented as 'seconds between requests'."""

    def setUp(self):
        no_sleep.calls = []

    def test_delay_is_applied_once_per_request(self):
        with MockAEM() as target, mock.patch.object(aem_hacker.time, "sleep", no_sleep):
            aem_hacker.request_delay = 3
            aem_hacker.http_request(target.url + "/x")
        self.assertEqual(
            len(no_sleep.calls),
            1,
            f"--delay slept {len(no_sleep.calls)}x for a single request, expected 1",
        )

    def test_get_does_not_send_a_redundant_warmup(self):
        """Every request was preceded by an identical warm-up GET.

        Doubling the request count against a target is both slow and rude; the
        warm-up only exists to seed session cookies for state-changing requests.
        """
        with MockAEM() as target, mock.patch.object(aem_hacker.time, "sleep", no_sleep):
            aem_hacker.request_delay = 0
            aem_hacker.http_request(target.url + "/warmup-probe")
        hits = [p for p in target.paths() if "warmup-probe" in p]
        self.assertEqual(
            len(hits),
            1,
            f"one http_request() produced {len(hits)} requests, expected 1",
        )

    def test_post_still_warms_up_the_session(self):
        with MockAEM() as target, mock.patch.object(aem_hacker.time, "sleep", no_sleep):
            aem_hacker.request_delay = 0
            aem_hacker.http_request(
                target.url + "/post-probe", method="POST", data="a=b"
            )
        hits = [p for p in target.paths() if "post-probe" in p]
        self.assertGreaterEqual(
            len(hits),
            2,
            "POST lost its session warm-up; cookie-seeded checks would break",
        )

    def test_connections_are_reused_across_requests(self):
        """A fresh Session per request means a new TCP+TLS handshake every time."""
        with MockAEM() as target, mock.patch.object(aem_hacker.time, "sleep", no_sleep):
            aem_hacker.request_delay = 0
            for i in range(6):
                aem_hacker.http_request(target.url + "/reuse/{0}".format(i))
        self.assertLessEqual(
            target.connections,
            2,
            f"6 requests opened {target.connections} connections; "
            "sessions are not being reused",
        )


class TestSsrfDetection(unittest.TestCase):
    """The SSRF callback chain must still work end to end."""

    def setUp(self):
        aem_hacker.d = {}
        aem_hacker.token = "TOK"

    def test_detector_only_trusts_its_own_token(self):
        import requests

        aem_hacker.d = {}
        aem_hacker.token = "MATCH"
        httpd = aem_hacker.run_detector(free_port())
        try:
            port = httpd.server_address[1]
            requests.get(
                "http://127.0.0.1:{0}/MATCH/probe/hit/".format(port), timeout=5
            )
            requests.get(
                "http://127.0.0.1:{0}/WRONG/probe/hit/".format(port), timeout=5
            )
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertIn("probe", aem_hacker.d, "a valid callback was dropped")
        self.assertEqual(aem_hacker.d["probe"], ["hit"])
        self.assertNotIn("WRONG", " ".join(aem_hacker.d))

    def test_ssrf_handler_reports_a_real_callback(self):
        """Mock the vulnerable endpoint, let it call back for real, assert the finding.

        Two servers are involved: the target (which issues the outbound fetch) and
        the scanner's own detector (which records the callback). Faking either one
        would not prove the back-connect URL is actually well-formed.
        """
        import requests

        ssrf_paths = [r"replication[^?]*\?path=(https?://\S+)"]

        def on_ssrf(url):
            try:
                requests.get(url, timeout=5)
            except Exception:
                pass

        detector_port = free_port()
        httpd = aem_hacker.run_detector(detector_port)
        try:
            with MockAEM(ssrf_paths=ssrf_paths, on_ssrf=on_ssrf) as target:
                findings = run_handler(
                    aem_hacker.registered["ssrf_cve_2021_40722"],
                    target,
                    my_host="127.0.0.1:{0}".format(detector_port),
                )
        finally:
            httpd.shutdown()
            httpd.server_close()

        self.assertTrue(
            any("SSRF" in f.name for f in findings),
            "an SSRF callback that actually arrived was not reported",
        )


# ---------------------------------------------------------------------------
# Detection quality
# ---------------------------------------------------------------------------


class TestDetections(unittest.TestCase):
    def test_querybuilder_exposure_is_reported(self):
        body = b'{"success":true,"hits":[],"results":[]}'
        with MockAEM(
            routes=[
                Route(
                    r"/bin/querybuilder\.json.*",
                    body=body,
                    content_type="application/json",
                ),
                Route(r".*", status=404),
            ]
        ) as target:
            findings = run_handler(
                aem_hacker.registered["querybuilder_servlet"], target
            )
        self.assertTrue(findings, "exposed QueryBuilder was missed")

    def test_felix_console_exposure_is_reported(self):
        with MockAEM(
            routes=[
                Route(r"/system/console.*", body=FELIX_BUNDLES),
                Route(r".*", status=404),
            ]
        ) as target:
            findings = run_handler(aem_hacker.registered["felix_console"], target)
        self.assertTrue(findings, "exposed Felix Console was missed")

    def test_version_disclosure_is_reported(self):
        with MockAEM(
            routes=[Route(r"/libs/granite/core/content/login.*", body=LOGIN_PAGE)]
        ) as target:
            findings = run_handler(aem_hacker.registered["version_disclosure"], target)
        self.assertTrue(findings, "AEM version disclosure was missed")

    def test_open_redirect_needs_an_absolute_external_location(self):
        """A Location that merely echoes the payload in a query string is not a redirect."""
        body = b"<html>login</html>"
        with MockAEM(
            routes=[
                Route(r"/libs/cq/core/content/login.*", status=302, body=body),
                Route(r".*", status=404),
            ]
        ) as target:
            findings = run_handler(aem_hacker.registered["open_redirect"], target)
        self.assertEqual(findings, [], "reported an open redirect that does not exist")


class TestCredentialsFlag(unittest.TestCase):
    """--creds makes the PR:L half of Adobe's CVE surface reachable.

    Most AEM CVEs are low-privilege or need user interaction, so an anonymous
    scanner structurally cannot detect them. The flag has to unlock that without
    changing what a run with no --creds does, and without leaking the password
    into output.
    """

    SECRET = "sup3rs3cr3t"

    def test_parses_user_and_password(self):
        self.assertEqual(aem_hacker.parse_credential("bob:pw"), ("bob", "pw"))

    def test_password_may_contain_colons(self):
        self.assertEqual(aem_hacker.parse_credential("bob:a:b:c"), ("bob", "a:b:c"))

    def test_rejects_missing_colon(self):
        with self.assertRaises(aem_hacker.CredentialError):
            aem_hacker.parse_credential("bob")

    def test_rejects_empty_username(self):
        with self.assertRaises(aem_hacker.CredentialError):
            aem_hacker.parse_credential(":pw")

    def test_rejects_header_injection(self):
        """A credential must not be able to terminate the header it lands in."""
        for bad in (
            "bob:pw\r\nX-Injected: 1",
            "bob:pw\nX-Injected: 1",
            "bo\r\nb:pw",
            "bob:pw\x00",
        ):
            with self.assertRaises(aem_hacker.CredentialError, msg=bad):
                aem_hacker.parse_credential(bad)

    def test_basic_auth_header_encodes_correctly(self):
        import base64

        header = aem_hacker.basic_auth_header(("bob", "pw"))["Authorization"]
        self.assertTrue(header.startswith("Basic "))
        self.assertEqual(base64.b64decode(header[6:]).decode(), "bob:pw")

    def test_falls_back_to_builtin_creds_when_flag_absent(self):
        with scanner(credentials=[]):
            pairs = aem_hacker.credentials_to_probe()
        self.assertEqual(pairs[0], ("admin", "admin"))
        self.assertIn(("author", "author"), pairs)

    def test_supplied_creds_replace_the_builtin_list(self):
        with scanner(credentials=[("bob", self.SECRET)]):
            pairs = aem_hacker.credentials_to_probe()
        self.assertEqual(pairs, [("bob", self.SECRET)])

    def test_duplicate_creds_are_collapsed(self):
        with scanner(credentials=[("bob", "a"), ("bob", "a"), ("eve", "b")]):
            pairs = aem_hacker.credentials_to_probe()
        self.assertEqual(pairs, [("bob", "a"), ("eve", "b")])

    def test_primary_auth_header_is_empty_when_anonymous(self):
        with scanner(credentials=[]):
            self.assertEqual(aem_hacker.primary_auth_header(), {})

    def test_primary_auth_header_honours_an_explicit_fallback(self):
        with scanner(credentials=[]):
            self.assertEqual(
                aem_hacker.primary_auth_header(fallback=("admin", "admin")),
                {"Authorization": "Basic YWRtaW46YWRtaW4="},
            )

    def test_supplied_creds_beat_the_fallback(self):
        with scanner(credentials=[("bob", self.SECRET)]):
            header = aem_hacker.primary_auth_header(fallback=("admin", "admin"))
        import base64

        self.assertEqual(
            base64.b64decode(header["Authorization"][6:]).decode(),
            "bob:" + self.SECRET,
        )

    def test_prl_checks_send_the_credential_when_given(self):
        seen = []

        def route(method, path, headers):
            seen.append(headers.get("Authorization"))
            return b"<html>nothing to see</html>"

        with scanner(credentials=[("bob", self.SECRET)]):
            with MockAEM(routes=[Route(r".*", body=route)]) as target:
                for name in (
                    "open_redirect",
                    "xss_aem_forms",
                    "xss_reflected_cve_2022",
                ):
                    seen.clear()
                    run_handler(aem_hacker.registered[name], target)
                    self.assertTrue(seen, f"{name} sent no requests")
                    self.assertTrue(
                        all(a is not None for a in seen),
                        f"{name} did not send the supplied credential",
                    )

    def test_prl_checks_stay_anonymous_without_the_flag(self):
        seen = []

        def route(method, path, headers):
            seen.append(headers.get("Authorization"))
            return b"<html>nothing to see</html>"

        with scanner(credentials=[]):
            with MockAEM(routes=[Route(r".*", body=route)]) as target:
                for name in (
                    "open_redirect",
                    "xss_aem_forms",
                    "xss_reflected_cve_2022",
                ):
                    seen.clear()
                    run_handler(aem_hacker.registered[name], target)
                    self.assertTrue(
                        all(a is None for a in seen),
                        f"{name} authenticated itself with no --creds given",
                    )

    def test_password_never_reaches_the_report(self):
        """A finding must name the user, never the credential blob."""
        import base64

        def currentuser(method, path, headers):
            auth = headers.get("Authorization", "")
            if not auth:
                return b'{"authorizableId":"anonymous"}'
            if (
                base64.b64decode(auth.split(" ", 1)[-1]).decode()
                == "bob:" + self.SECRET
            ):
                return b'{"authorizableId":"bob"}'
            return b"<html>401 Unauthorized</html>"

        with scanner(credentials=[("bob", self.SECRET)]):
            with MockAEM(routes=[Route(r".*", body=currentuser)]) as target:
                findings = run_handler(
                    aem_hacker.registered["currentuser_servlet"], target
                )
                report = "\n".join(f.description for f in findings)
                report += "\n".join(f.name + f.url for f in findings)
        self.assertTrue(findings, "the working credential was not reported at all")
        self.assertNotIn(self.SECRET, report, "the password leaked into a finding")
        self.assertNotIn(
            base64.b64encode("bob:{}".format(self.SECRET).encode()).decode(),
            report,
            "the base64 credential leaked into a finding",
        )
        self.assertIn("bob", report, "the username should still be reported")

    def test_malformed_creds_exit_nonzero_without_echoing_the_value(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            [
                "aem_hacker.py",
                "-u",
                "http://x",
                "--host",
                "1.2.3.4",
                "--creds",
                "user:{}".format(self.SECRET) + "\r\nX-Injected: 1",
            ],
        ), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), mock.patch.object(
            aem_hacker, "run_detector", lambda p: mock.Mock()
        ), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(
            err
        ):
            with self.assertRaises(SystemExit) as ctx:
                aem_hacker.main()
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertNotIn(self.SECRET, out.getvalue() + err.getvalue())


class TestCveCoverageDoc(unittest.TestCase):
    """CVE_COVERAGE.md must describe the checks that actually exist.

    The two dead checks this suite guards against were dead because the
    decorator was commented out while the README still advertised them. The same
    drift is invisible in a markdown file, so it is asserted here.
    """

    DOC = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "CVE_COVERAGE.md",
    )

    def setUp(self):
        with open(self.DOC, encoding="utf-8") as fh:
            self.text = fh.read()

    def test_every_registered_check_is_documented(self):
        table = self.text.split("## Detailed Entries")[0]
        documented = set(
            re.findall(r"^\|\s*\d+[a-z]?\s*\|\s*`([A-Za-z0-9_]+)`", table, re.M)
        )
        missing = set(aem_hacker.registered) - documented
        self.assertEqual(
            missing, set(), "checks exist in code but not in the coverage table"
        )

    def test_documents_no_check_that_does_not_exist(self):
        table = self.text.split("## Detailed Entries")[0]
        documented = set(
            re.findall(r"^\|\s*\d+[a-z]?\s*\|\s*`([A-Za-z0-9_]+)`", table, re.M)
        )
        phantom = documented - set(aem_hacker.registered)
        self.assertEqual(
            phantom, set(), "coverage table documents checks that do not exist"
        )

    def test_every_check_has_a_detailed_entry(self):
        entries = set(
            re.findall(r"^###\s*\d+[a-z]?\s*·\s*`([A-Za-z0-9_]+)`", self.text, re.M)
        )
        missing = set(aem_hacker.registered) - entries
        self.assertEqual(missing, set(), "checks have no detailed entry")

    def test_table_and_detailed_entries_agree(self):
        table = self.text.split("## Detailed Entries")[0]
        in_table = set(
            re.findall(r"^\|\s*\d+[a-z]?\s*\|\s*`([A-Za-z0-9_]+)`", table, re.M)
        )
        entries = set(
            re.findall(r"^###\s*\d+[a-z]?\s*·\s*`([A-Za-z0-9_]+)`", self.text, re.M)
        )
        self.assertEqual(
            in_table, entries, "the quick-reference table and detailed entries disagree"
        )

    def test_experimental_checks_are_flagged_in_the_table(self):
        table = self.text.split("## Detailed Entries")[0]
        for name, func in aem_hacker.registered.items():
            if not getattr(func, "experimental", False):
                continue
            row = re.search(
                r"^\|\s*\d+[a-z]?\s*\|\s*`{0}`\s*(?:⚠)?\s*\|.*$".format(
                    re.escape(name)
                ),
                table,
                re.M,
            )

            self.assertIsNotNone(row, f"{name} has no table row")
            self.assertIn(
                "⚠",
                row.group(0),
                f"{name} is experimental but not marked as such in the table",
            )

    def test_wrong_cve_attributions_are_not_still_asserted(self):
        """The five corrected misattributions must not reappear as bare claims."""
        forbidden = [
            # (handler, string that must not be attributed to it)
            ("ssrf_cve_2021_40722", "CVE-2021-40722 | SSRF"),
            ("auth_bypass_cve_2023_38205", "CVE-2023-38205"),
            ("open_redirect", "CVE-2023-29297"),
            ("xss_aem_forms", "CVE-2021-36063"),
        ]
        for handler, bad in forbidden:
            # Allowed only inside an explicit audit-correction note.
            for m in re.finditer(
                r"^###\s*\d+[a-z]?\s*·\s*`{0}`.*?(?=^###\s|\Z)".format(
                    re.escape(handler)
                ),
                self.text,
                re.M | re.S,
            ):
                section = m.group(0)
                if bad in section and "Audit correction" not in section:
                    self.fail(
                        f"{handler} section re-asserts {bad} without an audit note"
                    )

    def test_unverified_misattributions_are_corrected_somewhere(self):
        for handler in (
            "ssrf_cve_2021_40722",
            "auth_bypass_cve_2023_38205",
            "open_redirect",
            "xss_aem_forms",
            "xss_reflected_cve_2022",
        ):
            m = re.search(
                r"^###\s*\d+[a-z]?\s*·\s*`{0}`.*?(?=^###\s|\Z)".format(
                    re.escape(handler)
                ),
                self.text,
                re.M | re.S,
            )
            self.assertIsNotNone(m, f"{handler} has no detailed entry")
            self.assertIn(
                "Audit correction",
                m.group(0),
                f"{handler} does not document the audit correction",
            )


class TestSiblingScripts(unittest.TestCase):
    """The other scripts in the repo have their own silent-failure modes.

    aem_enum.py once called ``dpath.util.search()`` while only importing
    ``dpath``; the resulting AttributeError was swallowed by a bare ``except``,
    so the tool found nothing, always, and still exited 0. These tests exist so
    that class of bug cannot come back unnoticed.
    """

    def _load(self, name):
        import importlib.util

        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), name + ".py"
        )
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_enum_actually_extracts_users_and_secrets(self):
        import concurrent.futures

        aem_enum = self._load("aem_enum")
        tree = json.dumps(
            {
                "jcr:primaryType": "nt:unstructured",
                "jcr:createdBy": "alice",
                "db": {"password": "hunter2"},
            }
        ).encode()

        with MockAEM(
            routes=[Route(r".*", body=tree, content_type="application/json")]
        ) as target:
            with concurrent.futures.ThreadPoolExecutor(2) as tpe:
                users, secrets = aem_enum.process_node_get_servlet(
                    tpe, target.url, "/etc", "", 0, 2, 2, {}, True
                )
        self.assertIn("alice", users, "aem_enum found no usernames")
        self.assertTrue(secrets, "aem_enum found no secret paths")

    def test_enum_does_not_swallow_keyboard_interrupt(self):
        """A `return` inside `finally` would make Ctrl-C look like a clean run."""
        import ast
        import concurrent.futures

        aem_enum = self._load("aem_enum")
        with open(aem_enum.__file__) as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Try) and node.finalbody:
                for stmt in node.finalbody:
                    for sub in ast.walk(stmt):
                        if isinstance(sub, (ast.Return, ast.Break, ast.Continue)):
                            self.fail(
                                f"aem_enum.py:{sub.lineno} has a "
                                f"{type(sub).__name__.lower()} inside a finally block"
                            )

    def test_discoverer_reuses_connections(self):
        aem_discoverer = self._load("aem_discoverer")
        with MockAEM() as target:
            for i in range(5):
                aem_discoverer.http_request(target.url + "/probe/{0}".format(i))
        self.assertEqual(
            target.connections,
            1,
            f"5 probes opened {target.connections} connections",
        )


class TestHelpers(unittest.TestCase):
    def test_normalize_url_never_doubles_slashes(self):
        self.assertEqual(aem_hacker.normalize_url("http://a/", "/b"), "http://a/b")
        self.assertEqual(aem_hacker.normalize_url("http://a", "/b"), "http://a/b")

    def test_normalize_url_preserves_intentional_triple_slashes(self):
        """Dispatcher-bypass paths must survive untouched."""
        self.assertEqual(
            aem_hacker.normalize_url("http://a", "///etc"), "http://a///etc"
        )

    def test_content_type_strips_parameters(self):
        self.assertEqual(
            aem_hacker.content_type("text/HTML; charset=UTF-8"), "text/html"
        )

    def test_extra_header_parsing_keeps_colons_in_values(self):
        buf = io.StringIO()
        with mock.patch.object(aem_hacker, "registered", {}), mock.patch.object(
            sys,
            "argv",
            [
                "aem_hacker.py",
                "-u",
                "http://127.0.0.1:1",
                "--host",
                "1.2.3.4",
                "--header",
                "X-A: a:b:c",
            ],
        ), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), mock.patch.object(
            aem_hacker, "run_detector", lambda p: mock.Mock()
        ), mock.patch.object(
            aem_hacker.time, "sleep", no_sleep
        ), contextlib.redirect_stdout(
            buf
        ):
            aem_hacker.main()
        self.assertEqual(aem_hacker.extra_headers.get("X-A"), "a:b:c")

    def test_malformed_header_is_rejected(self):
        buf = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            [
                "aem_hacker.py",
                "-u",
                "http://x",
                "--host",
                "1.2.3.4",
                "--header",
                "nocolon",
            ],
        ), contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                aem_hacker.main()
        self.assertIn("nocolon", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
