#!/usr/bin/env python3
"""Build an AdGuard Home blocklist from Maltrail's malware & phishing feeds.

Maltrail (https://github.com/stamparm/maltrail) no longer ships static trail
files inside its repository; instead it assembles trails at runtime by running
the fetchers under ``feeds/*.py``. Each fetcher exposes an ``__info__`` string
describing the threat class it produces (e.g. "malware", "phishing",
"trickbot (malware)"). This script imports only the fetchers whose threat class
matches ``--info-match`` (default: malware or phishing), runs them, reduces the
indicators they return to bare hostnames, and writes them out as AdGuard Home
network rules (``||host^$important``).

Why this is conservative on purpose
-----------------------------------
DNS-level filtering can only block whole hostnames, never individual URLs. Feeds
like OpenPhish and URLhaus frequently list malicious URLs hosted on shared or
compromised legitimate infrastructure. Blocking the whole host of such an entry
would take down the legitimate service too. To keep false positives low we:

  * drop anything that is not a plain hostname (IPs, IP:port, IPv6);
  * drop bare public suffixes (e.g. ``com``, ``blogspot.com``) using Maltrail's
    own ``data/public_suffix_icann.txt`` so we never block a whole registry;
  * drop anything present in Maltrail's own ``data/whitelist.txt``.

Even so, review the output before trusting it network-wide, and keep an
allowlist (``@@||host^``) in AdGuard Home for anything that turns out legit.

Usage:
    python3 build_maltrail_blocklist.py --maltrail ./.maltrail --output maltrail.txt
"""

from __future__ import annotations

import argparse
import datetime
import importlib
import os
import re
import sys

# A hostname label: letters/digits/hyphen, not starting or ending with a hyphen.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(r"^(?:%s\.)+%s$" % (_LABEL, _LABEL))
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def load_line_set(path: str) -> set[str]:
    """Read a newline-delimited file into a lowercased set, ignoring comments."""
    out: set[str] = set()
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                out.add(line)
    return out


def select_feeds(feeds_dir: str, info_match: re.Pattern) -> list[str]:
    """Return module names under feeds/ whose __info__ matches info_match."""
    selected = []
    for name in sorted(os.listdir(feeds_dir)):
        if not name.endswith(".py") or name == "__init__.py":
            continue
        text = open(os.path.join(feeds_dir, name), "r", encoding="utf-8",
                    errors="replace").read()
        m = re.search(r'^__info__\s*=\s*["\'](.*?)["\']', text, re.MULTILINE)
        if m and info_match.search(m.group(1)):
            selected.append(name[:-3])
    return selected


def to_hostname(indicator: str) -> str | None:
    """Reduce a Maltrail indicator to a bare hostname, or None if unusable."""
    host = indicator.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    # Strip any userinfo, path, query, or fragment — keep only the authority host.
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    host = host.strip().strip(".")
    if not host or ":" in host:            # empty, has a port, or IPv6
        return None
    if _IPV4_RE.match(host):               # literal IPv4
        return None
    if not _HOSTNAME_RE.match(host):       # not a valid domain shape
        return None
    return host


def is_public_suffix(host: str, suffixes: set[str]) -> bool:
    """True if host is itself a public suffix (blocking it would hit a registry)."""
    return host in suffixes


def build(maltrail_root: str, info_match: re.Pattern):
    feeds_dir = os.path.join(maltrail_root, "feeds")
    data_dir = os.path.join(maltrail_root, "data")
    if not os.path.isdir(feeds_dir):
        sys.exit("error: no feeds/ directory under %r — is this a Maltrail checkout?"
                 % maltrail_root)

    whitelist = load_line_set(os.path.join(data_dir, "whitelist.txt"))
    suffixes = load_line_set(os.path.join(data_dir, "public_suffix_icann.txt"))

    # Run the fetchers from inside the Maltrail root so their relative paths resolve.
    sys.path.insert(0, maltrail_root)
    prev_cwd = os.getcwd()
    os.chdir(maltrail_root)

    feeds = select_feeds(feeds_dir, info_match)
    hosts: set[str] = set()
    references: set[str] = set()
    per_feed: dict[str, int] = {}
    dropped = 0

    try:
        for feed in feeds:
            try:
                module = importlib.import_module("feeds.%s" % feed)
                result = module.fetch() or {}
            except Exception as exc:  # a single flaky feed must not sink the run
                print("  ! %-24s FAILED: %s: %s" % (feed, type(exc).__name__, exc),
                      file=sys.stderr)
                per_feed[feed] = 0
                continue
            kept = 0
            for indicator, meta in result.items():
                host = to_hostname(indicator)
                if host is None:
                    dropped += 1
                    continue
                if host in whitelist or is_public_suffix(host, suffixes):
                    dropped += 1
                    continue
                hosts.add(host)
                kept += 1
                if isinstance(meta, (list, tuple)) and len(meta) >= 2 and meta[1]:
                    references.add(str(meta[1]))
            per_feed[feed] = kept
            print("  + %-24s %6d indicators -> %6d hostnames kept"
                  % (feed, len(result), kept), file=sys.stderr)
    finally:
        os.chdir(prev_cwd)

    return sorted(hosts), sorted(references), per_feed, dropped


def render(hosts, references, per_feed, dropped) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    feeds_line = ", ".join("%s(%d)" % (f, n) for f, n in sorted(per_feed.items()))
    refs_line = ", ".join(references) if references else "-"
    lines = [
        "! Title: Maltrail malware & phishing domains (AdGuard Home)",
        "! Description: Domain malware & phishing hasil ekstraksi otomatis dari feed",
        "!              malware/phishing Maltrail (github.com/stamparm/maltrail).",
        "! Homepage: https://github.com/milisdad/phishing-indo",
        "! Generated: %s" % now,
        "! Sumber feed: %s" % feeds_line,
        "! Referensi hulu: %s" % refs_line,
        "! Jumlah domain: %d (dibuang saat filter: %d)" % (len(hosts), dropped),
        "!",
        "! DIBUAT OTOMATIS oleh scripts/build_maltrail_blocklist.py via GitHub Actions.",
        "! JANGAN diedit manual — perubahan akan tertimpa saat rebuild berikutnya.",
        "! Untuk domain sah yang salah terblokir, tambahkan @@||domain^ di",
        "! 'Custom filtering rules' AdGuard Home (allowlist menang atas rule ini).",
        "!",
    ]
    lines.extend("||%s^$important" % h for h in hosts)
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--maltrail", required=True,
                        help="path to a Maltrail checkout (contains feeds/ and data/)")
    parser.add_argument("--output", required=True,
                        help="path to write the AdGuard Home blocklist")
    parser.add_argument("--info-match", default=r"malware|phishing",
                        help="regex matched against each feed's __info__ "
                             "(default: 'malware|phishing')")
    args = parser.parse_args()

    info_match = re.compile(args.info_match, re.IGNORECASE)
    hosts, references, per_feed, dropped = build(args.maltrail, info_match)

    output = render(hosts, references, per_feed, dropped)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(output)

    print("wrote %d domains to %s (dropped %d during filtering)"
          % (len(hosts), args.output, dropped), file=sys.stderr)


if __name__ == "__main__":
    main()
