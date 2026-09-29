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

import concurrent.futures
import contextlib
import copy
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


class GlobalIsolationTestCase(unittest.TestCase):
    """Restores aem_hacker's module globals around every test.

    ``d``, ``token``, ``credentials``, ``extra_headers`` and ``request_delay`` are
    module-level and outlive a single check, and main() mutates extra_headers in
    place. Alphabetical class ordering was making the leaks benign by luck; this
    makes the suite order-independent.
    """

    _GLOBALS = (
        "d",
        "token",
        "credentials",
        "extra_headers",
        "request_delay",
        "ssrf_timeout",
    )

    def setUp(self):
        super().setUp()
        self._saved = {}
        for name in self._GLOBALS:
            self._saved[name] = copy.copy(getattr(aem_hacker, name))
        aem_hacker.d = {}
        aem_hacker.token = "TESTTOKEN"
        aem_hacker.credentials = []
        aem_hacker.extra_headers = {}
        aem_hacker.request_delay = 0
        self.addCleanup(self._restore)

    def _restore(self):
        for name, value in self._saved.items():
            setattr(aem_hacker, name, value)


def with_liveness(inner):
    """Wrap a synthetic check so it reports one successful request.

    A check that never completes an HTTP request is now reported as inconclusive
    (exit 2) rather than clean, which is right for real checks but would make
    every synthetic check in this file look broken. Liveness itself is covered by
    its own tests against a real target.
    """

    def wrapped(base_url, my_host, debug=False, proxy=None):
        aem_hacker.note_request(True)
        return inner(base_url, my_host, debug, proxy)

    # Carry the metadata main() inspects, or --strict and the --host requirement
    # silently stop seeing these checks.
    wrapped.ssrf = getattr(inner, "ssrf", False)
    wrapped.experimental = getattr(inner, "experimental", False)

    return wrapped


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


def run_all(mock_target, my_host=None, workers=8):
    """Run every registered check, returning (name, findings-or-exception).

    The checks are independent and the tool itself runs them in a thread pool, so
    the harness does too. Sequentially this was ~190s per full sweep, which
    dominated the suite's runtime.
    """
    out = {}
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        futures = {
            pool.submit(run_handler, handler, mock_target, my_host): name
            for name, handler in aem_hacker.registered.items()
        }
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                out[name] = future.result()
            except Exception as exc:  # a check must never take the scan down
                out[name] = exc
    return out


# ---------------------------------------------------------------------------
# Contract: every check is reachable, callable, and safe
# ---------------------------------------------------------------------------


class TestCheckContract(GlobalIsolationTestCase):
    def test_no_silently_dead_checks(self):
        """Checks must be registered, not merely defined.

        Regression: the @register line for these two was commented out, so the
        README advertised checks (CurrentUserServlet, Reports) that could never
        run and --listhandlers never mentioned them. They are registered again,
        and a separate test pins that they stay opt-in (see
        TestOptInChecks) -- reachable, but not in the default sweep.
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
            "decode_callback",
            "note_request",
            "request_tally",
            "run_check",
            "usage_error",
            "load_creds_file",
            "warn_if_world_readable",
            "collect_credentials",
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


class TestCrashIsolation(GlobalIsolationTestCase):
    """A single misbehaving check must not discard the whole scan."""

    def _run_main(self, registered, argv):
        """Run main() with *registered* checks, returning (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(
            aem_hacker,
            "registered",
            {k: with_liveness(v) for k, v in registered.items()},
        ), mock.patch.object(sys, "argv", ["aem_hacker.py"] + argv), mock.patch.object(
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
            aem_hacker, "registered", {"good": with_liveness(good)}
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


class TestLoginSignalCorrectness(GlobalIsolationTestCase):
    """The credential checks must not lose, or invent, a login signal.

    An earlier revision replaced each check's own documented positive signal with
    one generic helper. That regressed loginstatus_servlet -- LoginStatusServlet
    reports a lower-case "userid" and an "authenticated" field, neither of which
    the helper matched -- while the generic non-JSON fallback matched a bare "id"
    inside almost any 200 error page.
    """

    def _resp(self, status, body):
        class R:
            status_code = status
            content = body

        return R()

    def test_loginstatus_body_is_recognised(self):
        body = b'{"authenticated": true, "userid": "admin", "userName": "Admin"}'
        self.assertEqual(
            aem_hacker.authenticated_as(self._resp(200, body), ("admin", "admin")),
            "admin",
        )

    def test_a_200_error_page_is_not_an_authenticated_principal(self):
        err = (
            b'<html><head><title>Error</title></head><body><div id="error">'
            b"Invalid request identifier</div></body></html>"
        )
        self.assertIsNone(
            aem_hacker.authenticated_as(self._resp(200, err), ("admin", "admin"))
        )

    def test_an_explicit_rejection_is_never_an_authenticated_principal(self):
        for body in (b"authenticated=false&userid=", b'{"authenticated": false}'):
            self.assertIsNone(
                aem_hacker.authenticated_as(self._resp(200, body), ("admin", "admin")),
                f"{body!r} was read as a successful login",
            )

    def test_id_is_not_accepted_as_a_bare_substring(self):
        """Regression: "id" matched identifier/invalid/id="..." in error pages."""
        self.assertNotIn("id", aem_hacker.IDENTITY_KEYS)

    def test_loginstatus_check_still_reports_a_working_credential(self):
        def loginstatus(method, path, headers):
            auth = headers.get("Authorization", "")
            if not auth:
                return b'{"authenticated": false}'
            import base64

            if base64.b64decode(auth.split(" ", 1)[-1]).decode() == "admin:admin":
                return b'{"authenticated": true, "userid": "admin"}'
            return b'{"authenticated": false}'

        with MockAEM(routes=[Route(r".*", body=loginstatus)]) as target:
            findings = run_handler(aem_hacker.registered["loginstatus_servlet"], target)
        cred_hits = [
            f for f in findings if "default credentials" in f.description.lower()
        ]
        self.assertEqual(
            len(cred_hits), 1, "a working default credential was not reported"
        )


class TestExitStatusHonesty(GlobalIsolationTestCase):
    """A scan that did not complete must not look like a clean one."""

    def _run_main(self, registered, argv=None):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(
            aem_hacker,
            "registered",
            {k: with_liveness(v) for k, v in registered.items()},
        ), mock.patch.object(
            sys, "argv", ["aem_hacker.py"] + (argv or [])
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

    def test_crashed_checks_are_not_reported_as_clean(self):
        def boom(base_url, my_host, debug=False, proxy=None):
            raise RuntimeError("check exploded")

        code, _, err = self._run_main(
            {"boom": boom}, ["-u", "http://x", "--host", "127.0.0.1"]
        )
        self.assertEqual(
            code, 2, "a run whose only check crashed exited as if it were clean"
        )
        self.assertIn("1 check(s) failed", err)

    def test_a_finding_still_exits_one(self):
        def good(base_url, my_host, debug=False, proxy=None):
            return [aem_hacker.Finding("Good", base_url, "found")]

        code, _, _ = self._run_main(
            {"good": good}, ["-u", "http://x", "--host", "127.0.0.1"]
        )
        self.assertEqual(code, 1)

    def test_a_clean_scan_exits_zero(self):
        def clean(base_url, my_host, debug=False, proxy=None):
            return []

        code, _, _ = self._run_main(
            {"clean": clean}, ["-u", "http://x", "--host", "127.0.0.1"]
        )
        self.assertEqual(code, 0)


class TestSsrfCallbackPort(GlobalIsolationTestCase):
    """The checks must be told the port the listener actually bound.

    run_detector() falls back to a free port when --port is unavailable (the
    default, 80, needs root), so a non-root run always took that path. The checks
    were still told the requested port, which pointed every callback at a dead
    port and made all seven SSRF checks silently return nothing.
    """

    def test_checks_receive_the_bound_port(self):
        captured = []

        def needs_host(base_url, my_host, debug=False, proxy=None):
            captured.append(my_host)
            return []

        needs_host.ssrf = True
        # Port 1 is privileged, so run_detector will fall back to a free port.
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(
            aem_hacker, "registered", {"needs_host": needs_host}
        ), mock.patch.object(
            sys,
            "argv",
            [
                "aem_hacker.py",
                "-u",
                "http://127.0.0.1:1",
                "--host",
                "1.2.3.4",
                "--port",
                "1",
            ],
        ), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), mock.patch.object(
            aem_hacker.time, "sleep", no_sleep
        ), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(
            err
        ):
            try:
                aem_hacker.main()
            except SystemExit:
                pass
        self.assertEqual(len(captured), 1, "the SSRF check did not run")
        port = int(captured[0].rsplit(":", 1)[1])
        self.assertNotEqual(
            port, 1, "the check was told the unavailable port, not the bound one"
        )


class TestDefaultCredentialsFalsePositive(GlobalIsolationTestCase):
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


class TestRequestPacing(GlobalIsolationTestCase):
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


class TestSsrfDetection(GlobalIsolationTestCase):
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


class TestDetections(GlobalIsolationTestCase):
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


class TestCredentialsFlag(GlobalIsolationTestCase):
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

    def test_supplied_creds_extend_the_builtin_list(self):
        """--creds must ADD to the default list, not replace it.

        Substituting instead would mean that reaching a PR:L check with --creds
        silently disabled "AEM with default credentials" detection.
        """
        with scanner(credentials=[("bob", self.SECRET)]):
            pairs = aem_hacker.credentials_to_probe()
        self.assertIn(("bob", self.SECRET), pairs)
        self.assertIn(("admin", "admin"), pairs, "the built-in list was dropped")
        self.assertEqual(
            pairs[0], ("admin", "admin"), "the built-in order should come first"
        )

    def test_duplicate_creds_are_collapsed(self):
        with scanner(credentials=[("bob", "a"), ("bob", "a"), ("eve", "b")]):
            pairs = aem_hacker.credentials_to_probe()
        self.assertEqual(len(pairs), len(set(pairs)), "duplicates survived")
        for pair in (("bob", "a"), ("eve", "b")):
            self.assertIn(pair, pairs)
            self.assertEqual(pairs.count(pair), 1, f"{pair} appears more than once")

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
                    # assert before the all(): all([]) is True, so without this a
                    # check that stopped requesting anything would pass.
                    self.assertTrue(seen, f"{name} sent no requests at all")
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

    def test_every_rejection_path_hides_the_password(self):
        """Every way --creds can fail must not print the secret.

        The CR/LF branch never echoed the value, so a test covering only that one
        was self-fulfilling: the malformed-form and empty-username branches used
        to include the whole value, password and all.
        """
        bad_values = [
            "user:" + self.SECRET + "\r\nX-Injected: 1",  # CR/LF
            ":" + self.SECRET,  # empty username
            self.SECRET,  # no colon
            "user:" + self.SECRET + "\x00",  # NUL
        ]
        for value in bad_values:
            with self.assertRaises(aem_hacker.CredentialError, msg=value):
                aem_hacker.parse_credential(value)
            try:
                aem_hacker.parse_credential(value)
            except aem_hacker.CredentialError as exc:
                self.assertNotIn(
                    self.SECRET,
                    str(exc),
                    "the password leaked for {0!r}: {1}".format(value, exc),
                )

    def test_creds_file_is_parsed(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# comment\n\n  alice:pw1  \nbob:a:b:c\n")
            path = fh.name
        os.chmod(path, 0o600)
        try:
            pairs = aem_hacker.collect_credentials(None, path)
        finally:
            os.unlink(path)
        self.assertEqual(pairs, [("alice", "pw1"), ("bob", "a:b:c")])

    def test_creds_file_combines_with_flag_and_environment(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("alice:pw1\n")
            path = fh.name
        os.chmod(path, 0o600)
        try:
            with mock.patch.dict(os.environ, {aem_hacker.CREDS_ENV_VAR: "dave:pw4"}):
                pairs = aem_hacker.collect_credentials(["carol:pw3"], path)
        finally:
            os.unlink(path)
        self.assertEqual(
            pairs,
            [("carol", "pw3"), ("alice", "pw1"), ("dave", "pw4")],
            "the three credential sources did not combine in order",
        )

    def test_a_malformed_file_line_does_not_echo_the_password(self):
        import tempfile

        secret = self.SECRET
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("alice:" + secret + "\nbroken\n")
            path = fh.name
        try:
            with self.assertRaises(aem_hacker.CredentialError) as ctx:
                aem_hacker.collect_credentials(None, path)
        finally:
            os.unlink(path)
        self.assertIn("line 2", str(ctx.exception))
        self.assertNotIn(secret, str(ctx.exception))

    def test_missing_creds_file_is_reported_clearly(self):
        with self.assertRaises(aem_hacker.CredentialError) as ctx:
            aem_hacker.collect_credentials(None, "/nonexistent/nope.txt")
        self.assertIn("Could not read credentials file", str(ctx.exception))

    def test_world_readable_creds_file_is_flagged(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("alice:pw1\n")
            path = fh.name
        os.chmod(path, 0o644)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                aem_hacker.collect_credentials(None, path)
        finally:
            os.unlink(path)
        self.assertIn("readable by other users", err.getvalue())
        self.assertIn("chmod 600", err.getvalue())

    def test_restrictive_creds_file_is_not_flagged(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("alice:pw1\n")
            path = fh.name
        os.chmod(path, 0o600)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                aem_hacker.collect_credentials(None, path)
        finally:
            os.unlink(path)
        self.assertEqual(err.getvalue(), "")

    def test_rejects_characters_basic_auth_cannot_transmit(self):
        """RFC 7617 is ISO-8859-1; UTF-8 would send mojibake that never validates."""
        with self.assertRaises(aem_hacker.CredentialError):
            aem_hacker.parse_credential("bob:\U0001f600")
        # ...but a Latin-1 representable password round-trips.
        import base64

        user, password = aem_hacker.parse_credential("bob:päss")
        header = aem_hacker.basic_auth_header((user, password))["Authorization"]
        self.assertEqual(base64.b64decode(header[6:]).decode("latin-1"), "bob:päss")

    def test_malformed_creds_exit_nonzero_without_echoing_the_value(self):
        for bad in (
            "user:" + self.SECRET + "\r\nX-Injected: 1",
            ":" + self.SECRET,
            self.SECRET,
        ):
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
                    bad,
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


class TestOptInChecks(GlobalIsolationTestCase):
    """Two checks are reachable but deliberately out of the default sweep.

    git history: a contributor added currentuser_servlet and reports enabled in
    2019, and the maintainer commented both out in 2020-01-03 (0dbb87d,
    "Tooling update") -- in the same commit where they registered four other
    checks. currentuser_servlet brute-forces credentials, which its two
    neighbours (loginstatus_servlet, userinfo_servlet) already do and which
    stayed enabled, so the disabling reads as a deliberate de-duplication.

    So the real defect was the documentation claiming three checks where the
    author ships two. Re-enabling the third by default would override that
    judgement; making them reachable but opt-in fixes the doc bug without
    changing the default blast radius.
    """

    OPT_IN = ("currentuser_servlet", "reports")

    def test_both_are_reachable(self):
        for name in self.OPT_IN:
            self.assertIn(name, aem_hacker.registered)
            self.assertTrue(callable(aem_hacker.registered[name]))

    def test_both_are_opt_in(self):
        for name in self.OPT_IN:
            self.assertFalse(
                getattr(aem_hacker.registered[name], "default", True),
                f"{name} is back in the default sweep",
            )

    def test_every_other_check_is_still_in_the_default_sweep(self):
        opted_in = {
            n
            for n, f in aem_hacker.registered.items()
            if not getattr(f, "default", True)
        }
        self.assertEqual(opted_in, set(self.OPT_IN), "the opt-in set changed")

    def test_naming_one_with_handler_runs_it(self):
        def with_target(reg, argv):
            out, err = io.StringIO(), io.StringIO()
            code = 0
            with mock.patch.object(
                aem_hacker,
                "registered",
                {k: with_liveness(v) for k, v in reg.items()},
            ), mock.patch.object(
                sys, "argv", ["aem_hacker.py"] + argv
            ), mock.patch.object(
                aem_hacker, "preflight", lambda *a, **k: True
            ), mock.patch.object(
                aem_hacker, "run_detector", lambda p: None
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

        ran = []

        def opt_in_check(base_url, my_host, debug=False, proxy=None):
            ran.append(1)
            return [aem_hacker.Finding("Found", base_url, "opt-in check ran")]

        opt_in_check.default = False
        opt_in_check.ssrf = False
        opt_in_check.experimental = False

        with MockAEM() as target:
            code, out, err = with_target(
                {"mine": opt_in_check},
                ["-u", target.url, "--host", "1.2.3.4", "--handler", "mine"],
            )
        self.assertEqual(len(ran), 1, "--handler did not run the opt-in check")
        self.assertIn("opt-in check ran", out)

    def test_a_plain_run_says_what_it_left_out(self):
        """Silently narrowing a scan is the failure mode this tool keeps fixing."""

        def make(default):
            # Distinct function objects: sharing one would share its attributes.
            def check(base_url, my_host, debug=False, proxy=None):
                return []

            check.default = default
            check.ssrf = False
            check.experimental = False
            return check

        registry = {
            "normal": make(True),
            "also_normal": make(True),
            "the_opt_in_one": make(False),
        }

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(aem_hacker, "registered", registry), mock.patch.object(
            sys,
            "argv",
            [
                "aem_hacker.py",
                "-u",
                "http://x",
                "--host",
                "1.2.3.4",
            ],
        ), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), mock.patch.object(
            aem_hacker, "run_detector", lambda p: None
        ), mock.patch.object(
            aem_hacker.time, "sleep", no_sleep
        ), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(
            err
        ):
            try:
                aem_hacker.main()
            except SystemExit:
                pass
        combined = out.getvalue() + err.getvalue()
        self.assertIn("opt-in", combined, "a narrowed scan said nothing")
        self.assertIn("the_opt_in_one", combined, "the excluded check was not named")


class TestCveCoverageDoc(GlobalIsolationTestCase):
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


class TestSsrfCallbackTrust(GlobalIsolationTestCase):
    """A callback is only trusted if it names a URL this check asked for.

    The correlation token is disclosed to every target the scanner touches (it is
    part of the outbound URL) and the listener binds 0.0.0.0, so the target itself
    can seed the store. An empty segment also base16-decodes successfully, which
    produced a finding with a blank URL for a target with no SSRF at all.
    """

    def test_empty_callback_is_rejected(self):
        self.assertIsNone(aem_hacker.decode_callback("", "http://target"))

    def test_non_base16_callback_is_rejected(self):
        self.assertIsNone(aem_hacker.decode_callback("not-hex!!", "http://target"))

    def test_callback_naming_another_origin_is_rejected(self):
        import base64

        forged = base64.b16encode(b"http://evil.example.com/x").decode()
        self.assertIsNone(
            aem_hacker.decode_callback(forged, "http://target"),
            "a foreign URL was accepted",
        )

    def test_our_own_callback_is_accepted(self):
        import base64

        ours = base64.b16encode(b"http://target/libs/x.json?path=http://cb/").decode()
        self.assertEqual(
            aem_hacker.decode_callback(ours, "http://target"),
            "http://target/libs/x.json?path=http://cb/",
        )

    def test_forged_callback_produces_no_finding(self):
        """End to end: a peer seeds the store with junk; the report stays empty."""
        import requests

        def forged_route(method, path, headers):
            return b"<html>404</html>"

        aem_hacker.d = {}
        aem_hacker.token = "TOK"
        with MockAEM(routes=[Route(r".*", body=forged_route)]) as target:
            detector_port = free_port()
            httpd = aem_hacker.run_detector(detector_port)
            try:
                # Exactly what a hostile target would do: it saw the token in the
                # URL we sent it and posted a junk callback back.
                requests.get(
                    "http://127.0.0.1:{0}/TOK/salesforcesecret/".format(detector_port),
                    timeout=5,
                )
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    findings = run_handler(
                        aem_hacker.registered["salesforcesecret_servlet"],
                        target,
                        my_host="127.0.0.1:{0}".format(detector_port),
                    )
            finally:
                httpd.shutdown()
                httpd.server_close()
        self.assertEqual(findings, [], "a forged SSRF callback produced a finding")


class TestListenerBounds(GlobalIsolationTestCase):
    """The callback store is reachable by an unauthenticated peer.

    The listener binds 0.0.0.0 and the correlation token is disclosed to every
    target the scanner touches, so a peer can send arbitrary paths. Capping the
    values per key is not enough on its own; the key count and key length need
    bounds too, or `d` grows without limit.
    """

    def _detector(self, store):
        detector = aem_hacker.Detector.__new__(aem_hacker.Detector)
        detector.d = store
        detector.token = "T"
        return detector

    def test_key_count_is_bounded(self):
        store = {}
        detector = self._detector(store)
        for i in range(detector.max_keys * 4):
            detector.record("key{0}".format(i), "v")
        self.assertLessEqual(
            len(store), detector.max_keys, "an unauthenticated peer grew d unbounded"
        )

    def test_values_per_key_are_bounded(self):
        store = {}
        detector = self._detector(store)
        for i in range(detector.max_values_per_key * 4):
            detector.record("same", "v{0}".format(i))
        self.assertEqual(len(store["same"]), detector.max_values_per_key)

    def test_an_absurdly_long_key_is_rejected(self):
        store = {}
        detector = self._detector(store)
        self.assertFalse(detector.record("k" * (detector.max_key_length + 1), "v"))
        self.assertEqual(store, {})

    def test_a_normal_callback_is_recorded(self):
        store = {}
        detector = self._detector(store)
        self.assertTrue(detector.record("salesforcesecret", "abc"))
        self.assertEqual(store["salesforcesecret"], ["abc"])


class TestExitCodeContract(GlobalIsolationTestCase):
    """0 clean / 1 found / 2 incomplete / 3 could not scan."""

    def _run(self, argv, registered=None, liveness=True):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(
            aem_hacker,
            "registered",
            {
                k: (with_liveness(v) if liveness else v)
                for k, v in (registered or {}).items()
            },
        ), mock.patch.object(sys, "argv", ["aem_hacker.py"] + argv), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), mock.patch.object(
            aem_hacker, "run_detector", lambda p: None
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

    def test_usage_failures_are_not_reported_as_findings(self):
        cases = [
            [],  # no -u
            ["-u", "http://x", "--handler", "nope"],  # unknown handler
            ["-u", "http://x", "--host", "1.2.3.4", "--creds", "malformed"],
            ["-u", "http://x", "--host", "1.2.3.4", "-H", "nocolon"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, _, _ = self._run(argv)
                self.assertEqual(
                    code,
                    3,
                    f"{argv} exited {code}; 1 would claim a finding was made",
                )

    def test_a_dead_target_is_not_a_clean_scan(self):
        """A check whose every request failed must not read as clean.

        Checks swallow their own exceptions, so this returns [] exactly like a
        clean result; only the request tally distinguishes them.
        """
        dead_target = "http://127.0.0.1:1"

        def dead_check(base_url, my_host, debug=False, proxy=None):
            for _ in range(2):
                try:
                    aem_hacker.http_request(dead_target + "/x")
                except Exception:
                    pass
            return []

        code, _, err = self._run(
            ["-u", dead_target, "--host", "1.2.3.4"],
            registered={"dead": dead_check},
            liveness=False,
        )
        self.assertEqual(code, 2, "a check with no successful request read as clean")
        self.assertIn("no successful request", err)

    def test_a_check_that_reaches_the_target_still_exits_zero(self):
        """The rule must not fire on a check that simply found nothing."""
        with MockAEM() as target:

            def quiet_check(base_url, my_host, debug=False, proxy=None):
                try:
                    aem_hacker.http_request(base_url + "/.children.json")
                except Exception:
                    pass
                return []

            code, _, err = self._run(
                ["-u", target.url, "--host", "1.2.3.4"],
                registered={"quiet": quiet_check},
            )
        self.assertEqual(code, 0, f"a clean check was flagged: {err}")


class TestSlurper(GlobalIsolationTestCase):
    """aem_slurper.py must not confuse "could not read" with "nothing there".

    It parsed any response as a child list, so a 401/403/404 — or a dispatcher
    block — was walked character by character and produced no output. A security
    crawl that reports nothing because it was blocked is indistinguishable from
    a clean one, which is the failure mode this suite has now found twice.
    """

    def _load(self):
        import importlib.util

        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "aem_slurper.py",
        )
        spec = importlib.util.spec_from_file_location("aem_slurper", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @contextlib.contextmanager
    def _http_conn(self, target):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", target.port, timeout=10)
        try:
            yield conn
        finally:
            conn.close()

    def test_slurp_returns_the_status(self):
        slurper = self._load()
        with MockAEM() as target, self._http_conn(target) as conn:
            data, conn, status = slurper.slurp(conn, "127.0.0.1", "/.children.json")
        self.assertEqual(status, 404, "a 404 was not surfaced to the caller")

    def test_error_page_is_not_returned_as_a_child_list(self):
        """The caller must be able to tell JSON from an HTML error page."""
        slurper = self._load()
        with MockAEM() as target, self._http_conn(target) as conn:
            data, _, status = slurper.slurp(conn, "127.0.0.1", "/.children.json")
        self.assertNotIsInstance(data, list, "an error page was returned as a list")
        self.assertNotEqual(status, 200)

    def test_real_children_still_parse(self):
        slurper = self._load()
        children = [
            {
                "uri": "/content/page",
                "jcr:primaryType": "cq:Page",
                "jcr:created": "2020-05-12T02:36:36.123+0000",
                "jcr:createdBy": "alice",
            }
        ]
        body = json.dumps(children).encode()
        with MockAEM(
            routes=[Route(r".*", body=body, content_type="application/json")]
        ) as target, self._http_conn(target) as conn:
            data, _, status = slurper.slurp(conn, "127.0.0.1", "/.children.json")
        self.assertEqual(status, 200)
        self.assertIsInstance(data, list)
        self.assertEqual(data[0]["jcr:createdBy"], "alice")

    def test_malformed_json_does_not_raise(self):
        slurper = self._load()
        with MockAEM(
            routes=[Route(r".*", body=b"{not json", content_type="application/json")]
        ) as target, self._http_conn(target) as conn:
            data, _, status = slurper.slurp(conn, "127.0.0.1", "/.children.json")
        self.assertEqual(status, 200)
        self.assertIsInstance(data, str, "malformed JSON should degrade, not raise")

    def test_connections_carry_a_timeout(self):
        """One unresponsive node must not hang the whole crawl."""
        slurper = self._load()
        self.assertGreater(slurper.TIMEOUT, 0)
        with MockAEM() as target:
            conn = slurper.connect("127.0.0.1")
            self.assertEqual(conn.timeout, slurper.TIMEOUT)
            conn.close()


class TestCredsPropagation(GlobalIsolationTestCase):
    """--creds must reach every check that authenticates, and never be printed."""

    SECRET = "sup3rs3cr3t"

    # Satisfies the exposure gate of every credential-gated check (loginstatus
    # looks for "authenticated", userinfo for "userID", currentuser for
    # "authorizableId") while being an outright rejection, so nothing is reported.
    GATE_PASSING_BODY = (
        b'{"authenticated": false, "userID": "", "authorizableId": "anonymous"}'
    )

    def _seen_auth(self, handler_name, creds):
        seen = []

        def route(method, path, headers):
            seen.append(headers.get("Authorization"))
            return self.GATE_PASSING_BODY

        with scanner(credentials=creds):
            with MockAEM(routes=[Route(r".*", body=route)]) as target:
                run_handler(aem_hacker.registered[handler_name], target)
        return seen

    def test_every_authenticating_check_honours_creds(self):
        """No check should still be hardcoded to admin:admin."""
        checks = [
            "create_new_nodes",
            "create_new_nodes2",
            "felix_console",
            "acs_tools",
            "version_disclosure",
            "currentuser_servlet",
            "userinfo_servlet",
            "loginstatus_servlet",
        ]
        with scanner(credentials=[("bob", self.SECRET)]):
            for name in checks:
                with self.subTest(check=name):
                    seen = self._seen_auth(name, [("bob", self.SECRET)])
                    self.assertTrue(seen, f"{name} sent no requests")
                    import base64

                    expected = (
                        "Basic "
                        + base64.b64encode(
                            "bob:{}".format(self.SECRET).encode()
                        ).decode()
                    )
                    self.assertIn(
                        expected,
                        seen,
                        f"{name} did not authenticate with the supplied credential",
                    )

    def test_create_new_nodes_reports_only_the_username(self):
        """The finding used to embed the whole user:pass string."""
        import base64

        bob = (
            "Basic " + base64.b64encode("bob:{}".format(self.SECRET).encode()).decode()
        )

        def route(method, path, headers):
            # Only the supplied credential is accepted, so the check has to walk
            # past the whole built-in list to reach it.
            if headers.get("Authorization") == bob:
                return b"<html><table><td>Parent Location</td></table></html>"
            return b"<html>nope</html>"

        with scanner(credentials=[("bob", self.SECRET)]):
            with MockAEM(routes=[Route(r".*", body=route)]) as target:
                result = run_handler(aem_hacker.registered["create_new_nodes"], target)
        self.assertTrue(result, "the working credential was not reported at all")
        report = " ".join(f.description for f in result)
        self.assertNotIn(self.SECRET, report, "the password leaked into a finding")
        self.assertIn("bob", report)

    def test_create_new_nodes_keeps_its_own_default_set(self):
        """--creds is appended; this check's built-in list must not change.

        It deliberately uses a smaller list than the global CREDS tuple, so it is
        also a check that the global one has not leaked in.
        """
        import base64

        seen = []

        def route(method, path, headers):
            seen.append(headers.get("Authorization"))
            return b"<html>nothing</html>"

        with scanner(credentials=[]):
            with MockAEM(routes=[Route(r".*", body=route)]) as target:
                run_handler(aem_hacker.registered["create_new_nodes"], target)

        own = {
            "Basic " + base64.b64encode(c.encode()).decode()
            for c in ("admin:admin", "author:author", "admin:password")
        }
        # The global list also contains grios:password; this check must not use it.
        global_only = {
            "Basic " + base64.b64encode(c.encode()).decode() for c in aem_hacker.CREDS
        } - own
        used = {a for a in seen if a}

        self.assertTrue(used, "no authenticated requests were made")
        self.assertTrue(
            used.issubset(own),
            "create_new_nodes probed credentials outside its own list: {0}".format(
                sorted(used - own)
            ),
        )
        self.assertFalse(
            used & global_only,
            "the global default list leaked into this check: {0}".format(
                sorted(used & global_only)
            ),
        )

    def test_no_hardcoded_admin_admin_remains_in_source(self):
        import base64

        blob = base64.b64encode(b"admin:admin").decode()
        with open(aem_hacker.__file__) as fh:
            source = fh.read()
        self.assertNotIn(
            blob,
            source,
            "a hardcoded admin:admin Authorization header is still in the source",
        )


class TestHeaderValidation(GlobalIsolationTestCase):
    def test_header_with_crlf_is_rejected(self):
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
                "-H",
                "X-A: v\r\nX-Injected: 1",
            ],
        ), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(
            err
        ):
            with self.assertRaises(SystemExit):
                aem_hacker.main()
        self.assertIn("CR, LF or NUL", out.getvalue() + err.getvalue())


class TestStrictZeroChecks(GlobalIsolationTestCase):
    def test_stripping_every_check_is_an_error(self):
        """Zero checks must not be reported as a clean scan."""

        def experimental_check(base_url, my_host, debug=False, proxy=None):
            return []

        experimental_check.experimental = True
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(
            aem_hacker, "registered", {"exp": experimental_check}
        ), mock.patch.object(
            sys,
            "argv",
            [
                "aem_hacker.py",
                "-u",
                "http://x",
                "--host",
                "1.2.3.4",
                "--strict",
            ],
        ), mock.patch.object(
            aem_hacker, "preflight", lambda *a, **k: True
        ), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(
            err
        ):
            with self.assertRaises(SystemExit) as ctx:
                aem_hacker.main()
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn("No checks left to run", err.getvalue())


class TestSiblingScripts(GlobalIsolationTestCase):
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


class TestHelpers(GlobalIsolationTestCase):
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
                "--header",
                "nocolon",
            ],
        ), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                aem_hacker.main()
        self.assertEqual(ctx.exception.code, aem_hacker.EXIT_USAGE)
        self.assertIn("nocolon", out.getvalue() + err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
