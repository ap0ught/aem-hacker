#! /usr/bin/env python3
# vim: et:ts=4:sts=4:sw=4:fileencoding=utf-8
r"""
Crawl an Adobe Experience Manager site.

Usage:

    python3 {script} HOSTNAME [/PATH]
"""

import os

if os.name == "nt":
    # Check if executing the Windows build of Python from a Cygwin shell.
    if "TZ" in os.environ:
        # The Windows build of Python (as opposed to the Cygwin one) appears
        # confused with the TZ variable set by the Cygwin shell.  The former
        # sets time.timezone to 0, time.altzone to -3600 (-1 hr) in the
        # presence of TZ="America/New_York", which turns the local time zone to
        # UTC.
        del os.environ["TZ"]
import time
import calendar

import http.client
import json
import ssl
import sys

# AEM nodes can be slow, and a crawler that hangs on one unresponsive node never
# finishes.  Bound every request.
TIMEOUT = 30


class Usage(SystemExit):
    def __init__(self, complaint=None):
        super(Usage, self).__init__(
            __doc__.format(script=os.path.basename(__file__))
            + ("" if complaint is None else "\nERROR: %s\n" % (complaint,))
        )


def to_s_since_epoch(tsz=None):
    if tsz is None:
        # 2020-05-12T02:36:36-0400
        tsz = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    if tsz.endswith("Z"):
        tsz = tsz[:-1] + "-00:00"
    if tsz[-3] == ":":
        tsz = tsz[:-3] + tsz[-2:]
    utcfix = 0
    utcsign = "-"
    if tsz[-5] in ("-", "+"):
        utcfix = 60 * ((60 * int(tsz[-4:-2])) + int(tsz[-2]))
        utcsign = tsz[-5]
        if utcsign == "+":
            utcfix = -utcfix
        tsz = tsz[:-5]
    if tsz[-4] == ".":
        tsz = tsz[:-4]
    ts = time.strptime(tsz + " -00:00", "%Y-%m-%dT%H:%M:%S %z")
    s_since_epoch = calendar.timegm(ts) + utcfix
    return s_since_epoch


def local_timestamp(s_since_epoch=None):
    if s_since_epoch is None:
        # This assumes that localtime() knows both the UTC time in seconds
        # since epoch and the local current time zone.
        pass
    else:
        # This assumes that s_since_epoch reflects the UTC time in seconds
        # since epoch.  The local current time zone is needed to properly
        # change that.
        if s_since_epoch < 0:
            return "infinity"
        elif s_since_epoch == 0:
            return "olden times"
    t = time.localtime(s_since_epoch)
    is_dst = time.daylight and t.tm_isdst
    zone = time.altzone if is_dst else time.timezone
    strtime = time.strftime("%Y-%m-%d %H:%M:%S", t)
    utcoff = -zone
    if utcoff > 0:
        utcsign = "+"
    else:
        utcsign = "-"
        utcoff = -utcoff
    strtime += "%s%02d%02d" % (utcsign, utcoff // 3600, (utcoff % 3600) // 60)
    return strtime


def connect(site):
    """Open an unverified HTTPS connection with a bounded timeout.

    Verification is off on purpose: AEM instances routinely use self-signed or
    internal CA certificates, and refusing to talk to them would defeat the
    purpose of a scanner.  The caller is expected to have authorisation.
    """
    return http.client.HTTPSConnection(
        site, context=ssl._create_unverified_context(), timeout=TIMEOUT
    )


def slurp(conn, site, uri):
    """Fetch *uri*, returning ``(data, conn, status)``.

    The status is returned rather than swallowed: a 401/403/404 used to be
    parsed as if it were a child list, so an error page or a dispatcher block
    looked exactly like a node with no children.  For a tool whose job is to
    report what it found, "I could not read this" must not be indistinguishable
    from "there is nothing here".
    """
    conn.request("GET", uri)
    try:
        r = conn.getresponse()
    except (http.client.RemoteDisconnected, http.client.ResponseNotReady):
        print(f"Reconnecting to {site}...", file=sys.stderr, flush=True)
        conn = connect(site)
        conn.request("GET", uri)
        r = conn.getresponse()
    data = r.read()
    headerslc = dict((k.lower(), v) for (k, v) in r.getheaders())
    ct = headerslc.get("content-type")
    if ct is not None:
        ct = ct.split(";")[0]
        if ct == "application/json":
            if len(data) == 0:
                data = []
            else:
                try:
                    data = json.loads(data)
                except ValueError:
                    # Not JSON despite the content type; hand back the raw body
                    # and let the caller notice the shape mismatch.
                    data = data.decode("utf-8", "replace")
        elif ct.split("/")[0] == "text":
            data = data.decode("utf-8", "replace")
    return data, conn, r.status


def start_dig(site, path=None):
    print(f"Connecting to {site}...", file=sys.stderr, flush=True)
    conn = connect(site)
    visited = {}
    unreadable = 0

    def dig(path, level=0):
        nonlocal conn, site, visited, unreadable
        if path is None:
            path = ""
        children, conn, status = slurp(conn, site, path + "/.children.json")
        if status != 200:
            unreadable += 1
            print(
                f"[!] HTTP {status} reading {path or '/'}/.children.json -- "
                "not crawled (blocked, or the node does not exist)",
                file=sys.stderr,
                flush=True,
            )
            return
        if not isinstance(children, list):
            unreadable += 1
            print(
                f"[!] {path or '/'}/.children.json returned "
                f"{type(children).__name__}, not a child list -- not crawled",
                file=sys.stderr,
                flush=True,
            )
            return
        for child in children:
            if "uri" in child:
                tsz = child.get("jcr:created", "2000-01-01T00:00:00Z")
                s_since_epoch = to_s_since_epoch(tsz)
                tsstr = local_timestamp(s_since_epoch)
                created_by = child.get("jcr:createdBy", "UNKNOWN")
                uri = child["uri"]
                if uri not in visited:
                    pt = child.get("jcr:primaryType")
                    if pt == "cq:Page":
                        dig(uri, level + 1)
                    elif pt == "cq:PageContent":
                        htmluri = uri
                        if htmluri.endswith("/jcr:content"):
                            htmluri = htmluri[: -len("/jcr:content")] + ".html"
                        html, conn, html_status = slurp(conn, site, htmluri)
                        if html_status != 200:
                            unreadable += 1
                            print(
                                f"[!] HTTP {html_status} reading {htmluri}",
                                file=sys.stderr,
                                flush=True,
                            )
                        child["FETCHED_HTML"] = html
                    print(tsstr, uri, created_by, json.dumps(child), flush=True)
                    visited[uri] = (tsstr, created_by)

    dig(path)

    if unreadable:
        # A crawl that reported nothing because everything was blocked is not a
        # clean result.  Say so on stderr so it cannot be mistaken for one.
        print(
            f"[!] {unreadable} node(s) could not be read; the crawl is " "incomplete.",
            file=sys.stderr,
            flush=True,
        )
    return unreadable


def main(site=None, *args):
    if site is None:
        raise Usage()
    path = None
    if len(args) > 0:
        path = args[0]
    start_dig(site, path)


if __name__ == "__main__":
    main(*sys.argv[1:])
