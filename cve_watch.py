#!/usr/bin/env python3
"""CVE / security advisory watch: NVD + GitHub Advisories + CISA KEV merged,
plus GitHub Advisories (incl. non-CVE ones) as their own section.

Each source is queried through its own public, unauthenticated feed — no
browser, no Google dork scraping (which gets CAPTCHA'd fast):

- CVEs: merged from NVD (hour-precision), GitHub Security Advisories and
  CISA KEV (both day-precision). Only CVEs matching the editorial PRODUCTS
  watchlist, or rated critical/KEV, are shown — NVD alone can list hundreds
  of CVEs a day, most of them irrelevant, so an unfiltered dump would bury
  the signal. Each selected CVE is further enriched with an EPSS score
  (probability of exploitation in the next 30 days, from cvedb.shodan.io)
  where available.
- GitHub Advisories: https://github.com/advisories, its own section separate
  from the CVE one above — fetch_ghsa() only pulls the CVE-linked subset to
  enrich NVD entries, but GitHub publishes plenty of advisories (especially
  npm/pip/go/etc. packages) that never get a CVE assigned at all, so they'd
  be invisible otherwise. Cursor-paginated via the response's
  `Link: rel="next"` header, not a page-number param. High volume (100+/day
  across all ecosystems), so same filtering discipline as the CVE section:
  only critical/high severity or a PRODUCTS watchlist match is shown.

Writes one combined, timestamped HTML digest with a section per source.
No state file: each run is self-contained and just looks back `--hours`
hours (rounded up to whole days for the day-precision sources: GitHub
Advisories, CISA KEV). A source that errors doesn't take the others down
with it — their results still get written, with the error called out at the
top of the page. If nothing new turned up anywhere AND nothing errored, no
file is written; if every source came up empty but at least one of them
errored, a file is still written so a quiet day and an outage don't look the
same from the folder.

Entries render as collapsed <details> rows (title + badges only) to keep a
long list scannable — click one to expand its full description.

Usage:
    python cve_watch.py                  # last 24h
    python cve_watch.py --hours 7
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import sys
import time
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from html import escape

import requests

# Avoid UnicodeEncodeError (or silently mangled em-dashes) on Windows consoles
# (cp1252) when this script's own output — or a scheduled run's redirected
# log — includes non-ASCII characters, same reconfiguration main.py/
# daily_pipeline.py do for themselves elsewhere in this workspace.
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

REQUEST_TIMEOUT = 15   # seconds
RETRY_MAX       = 3    # Max attempts per request
RETRY_DELAY     = 5    # Initial delay in seconds (doubled each attempt)
# Entries are collapsed by default (see _entry()), so this is a defensive cap
# against one pathological multi-thousand-char description, not a
# space-saving truncation anymore.
SUMMARY_LIMIT   = 1000

HEADERS = {"User-Agent": "TheWatcher-CVEWatch/1.0 (personal-security-digest)"}

NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD throttles/slow-walks large unauthenticated requests — resultsPerPage=
# 2000 was observed to reliably Read-time-out and burn through all 3 retries
# (confirmed: a 200-result page returns in ~8s, a 2000-result page in the
# same window either times out or takes 100+ seconds). Smaller pages, real
# pagination via startIndex.
NVD_PAGE_SIZE = 200
# 10 pages (2000 CVEs) was found 2026-10-21, via a cross-check against
# cvedb.shodan.io, to silently truncate on a genuinely high-volume day — NVD
# had 2508 CVEs in a 48h window that day, 508 of them past our old cap and
# dropped without any error or log line. Bumped to 20 pages (4000 CVEs) as a
# generous backstop, not a working limit: a day has to be ~60% busier than
# that already-unusual one to get truncated again. Still a hard ceiling, not
# unbounded — protects against a pathological --hours value (max 720) pulling
# tens of thousands of CVEs.
NVD_MAX_PAGES = 20
GHSA_URL = "https://api.github.com/advisories"
KEV_URL  = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
CVE_SEVERITIES = ("critical", "high", "medium", "low", "unknown")
# Collapsed entries take far less vertical space than the old always-expanded
# layout, so these caps were doubled when the collapsible UI was added.
CVE_WATCHED_CAP  = 100
CVE_CRITICAL_CAP = 60

# GitHub Advisories as their own section (https://github.com/advisories),
# distinct from fetch_ghsa() below (which only pulls the CVE-linked subset to
# enrich NVD entries in the CVE section). GitHub publishes plenty of
# advisories — especially for npm/pip/go/etc. packages — that never get a
# CVE assigned at all, so they're invisible to the CVE section no matter
# what. High volume (100+/day across all ecosystems), so only critical/high
# severity (or a PRODUCTS watchlist match, regardless of severity) are shown.
GHSA_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')
GHSA_SHOW_SEVERITIES = {"critical", "high"}
GHSA_CAP = 60
GHSA_MAX_PAGES = 10  # safety cap: 10 * 100 advisories per run, worst case

# Editorial watchlist, not an asset inventory. Labels are what readers see;
# aliases deliberately favour distinctive product names over generic words to
# keep a broad list useful without generating too much noise.
PRODUCTS = {
    # Operating systems, productivity and endpoint software
    "Microsoft Windows": ("microsoft windows", "windows server", "windows 11", "windows 10"),
    "Microsoft Exchange": ("microsoft exchange", "exchange server"),
    "Microsoft SharePoint": ("microsoft sharepoint", "sharepoint server"),
    "Microsoft Office": ("microsoft office", "microsoft 365", "office 365"),
    "Microsoft Active Directory": ("active directory", "active directory domain services"),
    "Microsoft SQL Server": ("microsoft sql server", "mssql"),
    "Microsoft Azure": ("microsoft azure", "azure active directory", "entra id"),
    "Microsoft Defender": ("microsoft defender", "defender for endpoint"),
    "Apple macOS / iOS": ("macos", "mac os", "ios", "ipados"),
    "Apple Safari": ("apple safari", "safari browser"),
    "Google Chrome / Chromium": ("google chrome", "chromium"),
    "Microsoft Edge": ("microsoft edge", "edge browser"),
    "Brave": ("brave browser",),
    "Opera": ("opera browser",),
    "Google Android": ("google android", "android os"),
    "Mozilla Firefox / Thunderbird": ("mozilla firefox", "mozilla thunderbird"),
    "Linux kernel": ("linux kernel",),
    "Ubuntu": ("ubuntu linux", "canonical ubuntu"),
    "Debian": ("debian linux",),
    "Red Hat": ("red hat enterprise linux", "rhel", "red hat openshift"),
    "SUSE": ("suse linux", "sles", "suse manager"),
    "CrowdStrike Falcon": ("crowdstrike falcon",),
    "SentinelOne": ("sentinelone", "sentinel one"),
    "Trellix / McAfee": ("trellix", "mcafee endpoint", "mcafee antivirus"),
    "Sophos Endpoint": ("sophos endpoint", "sophos antivirus", "sophos central"),
    "ESET": ("eset endpoint", "eset protect"),
    "Kaspersky": ("kaspersky endpoint", "kaspersky security center"),
    "Trend Micro": ("trend micro", "apex one", "deep security", "vision one"),
    "Bitdefender": ("bitdefender",),
    "Symantec / Broadcom": ("symantec endpoint", "broadcom endpoint security"),
    "Adobe Acrobat": ("adobe acrobat", "adobe reader"),
    "Java / OpenJDK": ("oracle java", "openjdk", "java runtime environment"),
    "OpenSSH": ("openssh",),
    "OpenSSL": ("openssl",),
    "PHP": ("php interpreter", "php runtime", "php-fpm"),
    "Node.js": ("node.js", "nodejs"),

    # Cloud, identity and collaboration
    "Amazon Web Services": ("amazon web services", "amazon aws", "aws"),
    "Google Cloud": ("google cloud platform", "google cloud", "gcp"),
    "Google Workspace": ("google workspace", "google workspace sync"),
    "Microsoft Teams": ("microsoft teams", "teams desktop client"),
    "Microsoft Power Platform": ("power platform", "power bi report server", "power automate"),
    "Oracle Cloud": ("oracle cloud infrastructure", "oracle cloud", "oci"),
    "Alibaba Cloud": ("alibaba cloud", "aliyun"),
    "Cloudflare": ("cloudflare", "cloudflare zero trust"),
    "Akamai": ("akamai", "akamai kona"),
    "Okta": ("okta", "auth0"),
    "Ping Identity": ("ping identity", "pingfederate", "pingaccess"),
    "CyberArk": ("cyberark",),
    "Keycloak": ("keycloak",),
    "Duo": ("cisco duo", "duo authentication"),
    "OneLogin": ("onelogin",),
    "ForgeRock": ("forgerock", "pingone access"),
    "Slack": ("slack desktop", "slack for windows", "slack for mac"),
    "Zoom": ("zoom client", "zoom workplace", "zoom meetings"),
    "TrueConf": ("trueconf server", "trueconf client"),
    "Mattermost": ("mattermost",),
    "Rocket.Chat": ("rocket.chat", "rocket chat"),
    "Atlassian": ("atlassian", "confluence", "jira software", "jira service management", "bitbucket server"),
    "GitHub": ("github enterprise", "github actions", "github desktop"),
    "GitLab": ("gitlab",),
    "Jenkins": ("jenkins",),
    "Gitea": ("gitea",),
    "SonarQube": ("sonarqube",),
    "JFrog": ("jfrog artifactory", "jfrog xray"),
    "Sonatype Nexus": ("sonatype nexus", "nexus repository"),
    "SUSE Rancher": ("suse rancher",),

    # Network, firewalls, VPNs, gateways and remote access
    "Cisco": ("cisco asa", "cisco firepower", "cisco ftd", "cisco ios xe", "cisco ios", "cisco nx-os", "cisco meraki", "cisco webex"),
    "Fortinet": ("fortinet", "fortigate", "fortios", "fortimanager", "fortianalyzer", "forticlient"),
    "Palo Alto Networks": ("palo alto networks", "pan-os", "globalprotect", "prisma access"),
    "Check Point": ("check point", "check point quantum", "gaia os"),
    "Juniper": ("juniper networks", "junos", "juniper srx", "juniper ex"),
    "SonicWall": ("sonicwall", "sonic os"),
    "WatchGuard": ("watchguard", "fireware os"),
    "Sophos Firewall": ("sophos firewall", "sophos xg", "sfos"),
    "F5 BIG-IP": ("f5 big-ip", "big-ip", "f5 networks"),
    "Citrix NetScaler": ("citrix netscaler", "citrix adc", "citrix gateway"),
    "Ivanti": ("ivanti connect secure", "ivanti policy secure", "pulse connect secure", "ivanti endpoint manager"),
    "Zscaler": ("zscaler", "zscaler client connector"),
    "Netskope": ("netskope",),
    "Barracuda": ("barracuda networks", "barracuda email security", "barracuda esm"),
    "VPN / remote access": ("openvpn", "wireguard", "tailscale", "apache guacamole", "beyondtrust remote support"),
    "pfSense / OPNsense": ("pfsense", "opnsense"),
    "MikroTik": ("mikrotik", "routeros"),
    "Ubiquiti": ("ubiquiti", "unifi network", "edgerouter"),
    "TP-Link": ("tp-link", "tplink", "omada controller"),
    "Arista": ("arista eos", "arista networks"),
    "Huawei": ("huawei vrp", "huawei usg", "huawei cloudengine"),
    "D-Link": ("d-link", "dlink router"),
    "NETGEAR": ("netgear", "netgear router"),
    "HPE Aruba": ("aruba networks", "arubaos", "aruba instant", "aruba clearpass"),
    "Extreme Networks": ("extreme networks", "extremenos", "extremecloud iq"),
    "Ruckus": ("ruckus wireless", "ruckus unleashed", "ruckus icx"),
    "Dell Networking": ("dell networking", "dell os10", "dell emc networking"),
    "TeamViewer": ("teamviewer",),
    "AnyDesk": ("anydesk",),
    "ConnectWise": ("connectwise screenconnect", "connectwise control"),
    "Forescout": ("forescout", "forescout counteract"),

    # Servers, virtualisation, containers, data and developer infrastructure
    "VMware": ("vmware", "vcenter server", "esxi", "vsphere", "vmware horizon"),
    "Hyper-V": ("microsoft hyper-v", "hyper-v server"),
    "Proxmox": ("proxmox", "proxmox ve"),
    "Nutanix": ("nutanix", "nutanix prism"),
    "QNAP": ("qnap", "qts", "quTS hero"),
    "Synology": ("synology", "diskstation manager", "synology dsm"),
    "Citrix Virtual Apps": ("citrix virtual apps", "citrix virtual desktops", "citrix workspace app"),
    "Docker": ("docker engine", "docker desktop", "moby"),
    "Kubernetes": ("kubernetes", "k8s", "kubelet", "kube-apiserver"),
    "Red Hat OpenShift": ("red hat openshift", "openshift container platform"),
    "Rancher": ("rancher", "rancher manager"),
    "HashiCorp": ("hashicorp vault", "hashicorp consul", "hashicorp nomad", "terraform"),
    "Apache HTTP Server": ("apache http server", "apache httpd"),
    "Apache Tomcat": ("apache tomcat",),
    "Apache Struts": ("apache struts",),
    "NGINX": ("nginx",),
    "Microsoft IIS": ("microsoft iis", "internet information services"),
    "Zimbra": ("zimbra collaboration", "zimbra collaboration suite", "zimbra zcs"),
    "HCL Domino": ("hcl domino", "ibm domino"),
    "Kerio": ("kerio connect", "kerio control"),
    "Oracle Database": ("oracle database", "oracle db", "oracle weblogic"),
    "MySQL": ("mysql server", "mysql enterprise"),
    "PostgreSQL": ("postgresql", "postgres database"),
    "MongoDB": ("mongodb",),
    "Couchbase": ("couchbase",),
    "Redis": ("redis server", "redis stack"),
    "Apache Kafka": ("apache kafka",),
    "Apache ActiveMQ": ("apache activemq",),
    "RabbitMQ": ("rabbitmq",),
    "Elastic": ("elasticsearch", "kibana", "elastic stack"),
    "Grafana": ("grafana",),
    "Graylog": ("graylog",),
    "Zabbix": ("zabbix",),
    "Splunk": ("splunk enterprise", "splunk universal forwarder"),
    "Wazuh": ("wazuh",),
    "Rapid7": ("rapid7", "insightvm", "metasploit framework"),
    "Tenable": ("tenable nessus", "tenable.sc", "tenable io"),
    "Qualys": ("qualys",),
    "Veeam": ("veeam backup", "veeam one"),
    "Progress MOVEit": ("progress moveit", "moveit transfer", "moveit cloud"),
    "Fortra GoAnywhere": ("fortra goanywhere", "goanywhere mft"),
    "Cleo": ("cleo harmony", "cleo vltrader", "cleo lexicom"),
    "SolarWinds": ("solarwinds", "orion platform"),
    "ManageEngine": ("manageengine", "adselfservice plus", "servicedesk plus"),
    "SAP": ("sap netweaver", "sap hana", "sap solution manager", "sap businessobjects"),
    "WordPress": ("wordpress", "wordpress core"),
    "Drupal": ("drupal",),
    "Joomla": ("joomla",),
    "Magento / Adobe Commerce": ("magento", "adobe commerce"),
    "TYPO3": ("typo3",),
    "Shopware": ("shopware",),
    "Nextcloud": ("nextcloud",),
    "ownCloud": ("owncloud",),
    "WSO2": ("wso2", "wso2 identity server", "wso2 api manager"),
}


# Word-boundary matching, not plain substring: a bare short/generic alias
# like "ios" was matching inside unrelated words ("Infoblox NIOS" contains
# "ios" as a raw substring) — confirmed as a real false-positive in
# production output (2026-11-10). \b on both sides fixes that whole class,
# not just the one alias found.
_TERM_RE_CACHE: dict[str, re.Pattern] = {}


def _term_matches(term: str, text: str) -> bool:
    pattern = _TERM_RE_CACHE.get(term)
    if pattern is None:
        pattern = re.compile(r"\b" + re.escape(term) + r"\b")
        _TERM_RE_CACHE[term] = pattern
    return pattern.search(text) is not None


def _request(method: str, url: str, **kwargs) -> requests.Response:
    last_error = None
    for attempt in range(RETRY_MAX):
        try:
            resp = requests.request(method, url, headers=HEADERS, timeout=REQUEST_TIMEOUT, **kwargs)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            last_error = exc
            if attempt + 1 < RETRY_MAX:
                time.sleep(RETRY_DELAY * (2 ** attempt))
    raise RuntimeError(str(last_error))


def _truncate(text: str, limit: int = SUMMARY_LIMIT) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"


# ── CVEs ─────────────────────────────────────────────────────────────────

def _cve_item(cve_id: str, title: str, description: str, severity: str = "unknown",
              cvss: float | None = None, products: list[str] | None = None) -> dict:
    return {"id": cve_id, "title": title or cve_id, "description": description or "",
            "severity": severity.lower() if severity.lower() in CVE_SEVERITIES else "unknown",
            "cvss": cvss, "products": products or [], "sources": set(), "kev": False,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}


def _nvd_severity(metrics: dict) -> tuple[str, float | None]:
    for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(version) or []
        if values:
            data = values[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or values[0].get("baseSeverity")
            return (str(severity or "unknown").lower(), float(score) if score is not None else None)
    return "unknown", None


def _nvd_products(configurations: list[dict]) -> list[str]:
    """Collect vendor/product pairs from NVD configuration trees, parsed out
    of each CPE criteria string (cpe:2.3:part:vendor:product:...), including
    nested nodes. Returns clean "vendor product" labels rather than the raw
    CPE string — both for a readable meta line, and so PRODUCTS watchlist
    matching runs against a clean, authoritative vendor/product token instead
    of fuzzy-matching free text alone (NVD's own structured field, not a
    substitute for it: GHSA/KEV items and NVD entries with no configurations
    data yet still fall back to the title/description text match)."""
    products: list[str] = []

    def visit(node: dict) -> None:
        for match in node.get("cpeMatch", []):
            fields = match.get("criteria", "").split(":")
            if len(fields) <= 4 or not fields[3] or fields[3] == "*":
                continue
            vendor = fields[3].replace("_", " ")
            product = fields[4].replace("_", " ") if fields[4] != "*" else ""
            label = f"{vendor} {product}".strip()
            if label:
                products.append(label)
        for child in node.get("nodes", []):
            visit(child)

    for configuration in configurations:
        for node in configuration.get("nodes", []):
            visit(node)
    return list(dict.fromkeys(products))[:10]


def fetch_nvd(hours: int) -> tuple[list[dict], bool]:
    """The one CVE source with real hour precision — NVD's API takes a
    timestamp, not just a date. Paginated via startIndex/totalResults in
    NVD_PAGE_SIZE chunks (see the comment by NVD_PAGE_SIZE for why: large
    single requests are unreliable). Returns (items, truncated) — truncated
    is True if NVD_MAX_PAGES was exhausted while totalResults still had more
    left, i.e. the same silent-truncation failure mode found 2026-10-21
    (see the comment by NVD_MAX_PAGES), so a future repeat of it is reported
    instead of discovered by chance again."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    # NVD API 2.0 expects its ISO local-date representation without a
    # timezone suffix. Appending "UTC" looks reasonable but causes an opaque
    # 404.
    base_params = {"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                   "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"), "resultsPerPage": NVD_PAGE_SIZE}
    items = []
    start_index = 0
    total_results = 0
    for _ in range(NVD_MAX_PAGES):
        payload = _request("get", NVD_URL, params={**base_params, "startIndex": start_index}).json()
        total_results = payload.get("totalResults", 0)
        vulnerabilities = payload.get("vulnerabilities", [])
        for entry in vulnerabilities:
            cve = entry.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions", [])
            description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), "")
            severity, cvss = _nvd_severity(cve.get("metrics", {}))
            products = _nvd_products(cve.get("configurations", []))
            item = _cve_item(cve_id, cve_id, description, severity, cvss, products)
            item["sources"].add("NVD")
            items.append(item)
        start_index += len(vulnerabilities)
        if not vulnerabilities or start_index >= total_results:
            return items, False
    return items, start_index < total_results


def fetch_ghsa(hours: int) -> list[dict]:
    """Day-precision only — GitHub's `published` filter takes a date.
    Cursor-paginated the same way fetch_github_advisories() is (the `Link:
    rel="next"` response header, not a page-number param) — a single
    per_page=100 request used to silently cap this at 100 CVE-linked
    advisories/day, which a high-publication day can exceed just like the
    dedicated GitHub Advisories section already accounted for."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).date().isoformat()
    url, params = GHSA_URL, {"published": since, "per_page": 100}
    all_advisories: list[dict] = []
    for _ in range(GHSA_MAX_PAGES):
        resp = _request("get", url, params=params)
        batch = resp.json()
        if not batch:
            break
        all_advisories.extend(batch)
        link_match = GHSA_LINK_NEXT_RE.search(resp.headers.get("Link", ""))
        if not link_match:
            break
        url, params = link_match.group(1), None  # the next-page URL already carries its own query string

    items = []
    for advisory in all_advisories:
        cve_id = next((identifier.get("value") for identifier in advisory.get("identifiers", [])
                       if identifier.get("type") == "CVE"), None)
        if not cve_id:
            continue
        severity = advisory.get("severity") or "unknown"
        item = _cve_item(cve_id, advisory.get("summary") or cve_id,
                         advisory.get("description") or "", severity,
                         products=[v.get("package", {}).get("name", "")
                                   for v in advisory.get("vulnerabilities", [])])
        item["sources"].add("GitHub Advisory")
        items.append(item)
    return items


def fetch_kev(hours: int) -> list[dict]:
    """Day-precision only — CISA's KEV catalog gives a bare `dateAdded`."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).date()
    rows = csv.DictReader(io.StringIO(_request("get", KEV_URL).text))
    items = []
    for row in rows:
        try:
            added = date.fromisoformat(row.get("dateAdded", ""))
        except ValueError:
            continue
        if added < cutoff:
            continue
        cve_id = row.get("cveID")
        if not cve_id:
            continue
        product = " ".join(filter(None, (row.get("vendorProject"), row.get("product"))))
        item = _cve_item(cve_id, product or cve_id, row.get("shortDescription", ""),
                         "unknown", products=[product])
        item["sources"].add("CISA KEV")
        item["kev"] = True
        item["kev_date_added"] = added.isoformat()
        item["kev_due_date"] = row.get("dueDate") or None
        items.append(item)
    return items


def _cve_merge(items: list[dict]) -> dict[str, dict]:
    merged: dict[str, dict] = {}
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for item in items:
        current = merged.get(item["id"])
        if current is None:
            merged[item["id"]] = item
            continue
        current["sources"] |= item["sources"]
        current["kev"] |= item["kev"]
        if item.get("kev_date_added"):
            current["kev_date_added"] = item["kev_date_added"]
            current["kev_due_date"] = item.get("kev_due_date")
        current["products"] = list(dict.fromkeys(current["products"] + item["products"]))
        if order[item["severity"]] > order[current["severity"]]:
            current["severity"] = item["severity"]
            if item["cvss"] is not None:  # don't let a higher-severity source with no
                current["cvss"] = item["cvss"]  # CVSS of its own (e.g. GHSA) wipe a valid NVD score
        if len(item["description"]) > len(current["description"]):
            current["description"] = item["description"]
        # Title and description are picked independently (not as a pair) —
        # NVD's title is just the bare CVE ID, so any other source's title is
        # already better; beyond that, prefer the longest real (non-ID) title
        # rather than whichever source happened to have the longest description.
        if item["title"] != item["id"] and (current["title"] == current["id"]
                                            or len(item["title"]) > len(current["title"])):
            current["title"] = item["title"]
    return merged


def _cve_mark_watched(items: list[dict]) -> None:
    for item in items:
        text = " ".join([item["title"], item["description"], *item["products"]]).lower()
        item["watched_products"] = [name for name, terms in PRODUCTS.items()
                                    if any(_term_matches(term, text) for term in terms)]


def fetch_cves(hours: int) -> tuple[dict, list[str]]:
    """NVD is canonical; GitHub Advisories adds newly published ecosystem
    advisories; CISA KEV adds an independent signal of known exploitation.
    All three can describe the same CVE, so items are merged by CVE ID. Only
    watchlist matches and critical/KEV CVEs are kept in the report — NVD
    alone can list hundreds of CVEs in a day, and dumping all of them would
    bury the few that matter."""
    collected: list[dict] = []
    errors: list[str] = []
    try:
        nvd_items, nvd_truncated = fetch_nvd(hours)
        collected.extend(nvd_items)
        if nvd_truncated:
            errors.append(f"CVE/NVD: hit the {NVD_MAX_PAGES}-page pagination cap with more results "
                         "still available — some recent CVEs may be missing from this run")
    except Exception as exc:  # A failed source must not suppress the other two.
        errors.append(f"CVE/NVD: {exc}")
    for name, fetcher in (("GitHub Advisories", fetch_ghsa), ("CISA KEV", fetch_kev)):
        try:
            collected.extend(fetcher(hours))
        except Exception as exc:
            errors.append(f"CVE/{name}: {exc}")
    items = list(_cve_merge(collected).values())
    _cve_mark_watched(items)
    counts = Counter(item["severity"] for item in items)
    for severity in CVE_SEVERITIES:
        counts.setdefault(severity, 0)
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    watched = sorted((i for i in items if i["watched_products"]),
                     key=lambda i: (not i["kev"], -order[i["severity"]], -(i["cvss"] or 0), i["id"]))
    critical = sorted((i for i in items if (i["severity"] == "critical" or i["kev"])
                       and not i["watched_products"]),
                      key=lambda i: (not i["kev"], -(i["cvss"] or 0), i["id"]))
    report = {"counts": dict(counts), "total": len(items),
              "watched": watched[:CVE_WATCHED_CAP], "watched_omitted": max(0, len(watched) - CVE_WATCHED_CAP),
              "critical": critical[:CVE_CRITICAL_CAP], "critical_omitted": max(0, len(critical) - CVE_CRITICAL_CAP)}
    return report, errors


# ── EPSS enrichment (cvedb.shodan.io) ───────────────────────────────────────
# Not a new "recent CVEs" section: cross-checked against our own NVD fetch on
# 2026-10-21 and cvedb.shodan.io turned out to be a *subset* of NVD (0 CVEs
# unique to it) — no coverage to gain from it as a source. What it does add:
# an EPSS score (FIRST.org's probability-of-exploitation-in-30-days estimate)
# per CVE, which neither NVD nor GHSA nor KEV give us. Applied as enrichment
# on top of the CVEs already selected into watched/critical, not a new
# section.
SHODAN_CVEDB_URL = "https://cvedb.shodan.io/cve/{}"


def fetch_epss(cve_id: str) -> tuple[float, float] | None:
    """Single-attempt, no retry/backoff — this runs once per already-selected
    CVE (up to ~160/run), so it deliberately skips the shared _request()'s 3x
    retry cost per item; a missing EPSS badge on one CVE is low-stakes.
    Returns None — no exception — for a clean 404 (the CVE just isn't in
    cvedb.shodan.io's DB yet; expected and common for very recent CVEs,
    confirmed their sync lags NVD by roughly a day) or for a CVE that has no
    EPSS value yet. Raises for anything that looks like the *service* being
    unavailable (timeout, connection error, 5xx), so the caller can tell
    "no data for this one" apart from "stop trying."""
    resp = requests.get(SHODAN_CVEDB_URL.format(cve_id), headers=HEADERS, timeout=8)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()
    epss = data.get("epss")
    return (epss, data.get("ranking_epss")) if epss is not None else None


def enrich_with_epss(items: list[dict]) -> dict:
    """Mutates `items` in place, adding 'epss'/'ranking_epss' keys. A clean
    "not found yet" (see fetch_epss) just leaves those keys None and doesn't
    count against the bail-out threshold — most very-recent CVEs will hit
    this, it's not a failure. Only 3 *consecutive* real errors (timeouts,
    connection errors, 5xx) bail out early, on the assumption the service
    itself is down — not worth hammering the rest of a large batch with
    individual timeouts one by one. Returns counts (enriched/unavailable/
    failed/bailed) so a 0% enrichment run (service genuinely has nothing yet)
    can be told apart from a broken one, instead of a single opaque bool."""
    consecutive_failures = 0
    enriched = unavailable = failed = 0
    for item in items:
        try:
            result = fetch_epss(item["id"])
        except Exception:
            item["epss"] = item["ranking_epss"] = None
            item["epss_status"] = "failed"
            failed += 1
            consecutive_failures += 1
            if consecutive_failures >= 3:
                return {"enriched": enriched, "unavailable": unavailable, "failed": failed, "bailed": True}
            continue
        consecutive_failures = 0
        if result is None:
            item["epss"] = item["ranking_epss"] = None
            item["epss_status"] = "unavailable"
            unavailable += 1
        else:
            item["epss"], item["ranking_epss"] = result
            item["epss_status"] = "enriched"
            enriched += 1
    return {"enriched": enriched, "unavailable": unavailable, "failed": failed, "bailed": False}


def fetch_github_advisories(hours: int, exclude_cve_ids: set[str] = frozenset()) -> tuple[list[dict], int]:
    """All GHSA advisories in the window, not just the CVE-linked subset
    fetch_ghsa() uses to enrich the CVE section. Cursor-paginated (the `Link:
    rel="next"` response header, not a page-number param) — one page already
    hits the 100-result cap most days, so following it matters. Returns
    (shown_items, total_scanned); total_scanned is always reported so an
    empty section reads as "nothing severe enough" rather than "maybe
    broken". `exclude_cve_ids` drops any advisory whose CVE is already shown
    in the CVE section (watched/critical) — without this, a critical CVE
    that also has a GHSA advisory would be shown twice on the page, once per
    section; this section's whole point is advisories that *don't* already
    have a CVE-section entry, not a second listing of the same ones."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).date().isoformat()
    url, params = GHSA_URL, {"published": since, "per_page": 100}
    all_advisories: list[dict] = []
    for _ in range(GHSA_MAX_PAGES):
        resp = _request("get", url, params=params)
        batch = resp.json()
        if not batch:
            break
        all_advisories.extend(batch)
        link_match = GHSA_LINK_NEXT_RE.search(resp.headers.get("Link", ""))
        if not link_match:
            break
        url, params = link_match.group(1), None  # the next-page URL already carries its own query string

    items: list[dict] = []
    for advisory in all_advisories:
        severity = (advisory.get("severity") or "unknown").lower()
        ecosystems = sorted({(v.get("package") or {}).get("ecosystem", "?")
                             for v in advisory.get("vulnerabilities", [])}) or ["?"]
        text = " ".join([advisory.get("summary") or "", advisory.get("description") or "",
                         *ecosystems]).lower()
        watched = [name for name, terms in PRODUCTS.items() if any(_term_matches(term, text) for term in terms)]
        if severity not in GHSA_SHOW_SEVERITIES and not watched:
            continue
        cve_id = advisory.get("cve_id")
        if cve_id and cve_id in exclude_cve_ids:
            continue
        label = advisory.get("ghsa_id", "?") + (f" / {cve_id}" if cve_id else "")
        items.append({"title": f"{label}: {advisory.get('summary', '?')}",
                      "url": advisory.get("html_url", ""), "program": ", ".join(ecosystems),
                      "severity": severity, "watched_products": watched,
                      "summary": advisory.get("description", "")})

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    items.sort(key=lambda i: (not i["watched_products"], -severity_rank.get(i["severity"], 0)))
    return items[:GHSA_CAP], len(all_advisories)


# ── HTML rendering ──────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#166534",
    "unknown": "#475569",
}
NEUTRAL_BADGE = "#334155"
WATCH_BADGE   = "#1d4ed8"
KEV_BADGE     = "#7c3aed"
EPSS_BADGE    = "#0e7490"


def _badge(label: str, color: str = NEUTRAL_BADGE) -> str:
    return f'<span class="badge" style="background:{color}">{escape(label)}</span>'


def _entry(title: str, url: str, meta_parts: list[str], badges: list[str], summary: str) -> str:
    """Renders as a native <details>/<summary> row: collapsed by default so a
    long list of entries stays scannable (badges + title only), click to
    expand the full description. No JS needed. The title itself is a link
    (target="_blank") straight to the source, so a CVE can be opened without
    expanding first — no new line added. Clicking it also toggles the parent
    <details> as a side effect of the click landing inside <summary> (a
    native browser quirk, not something we control without JS), but since
    the link opens in a new tab that's harmless: the current page's toggle
    state doesn't matter once the other tab has what you clicked for. The
    "Open" link in the expanded body stays too, for after it's already open."""
    meta_html = " · ".join(escape(part) for part in meta_parts if part)
    meta_div = f'<div class="meta">{meta_html}</div>' if meta_html else ""
    summary_html = f'<p class="summary">{escape(_truncate(summary))}</p>' if summary else ""
    return f"""<details class="entry">
  <summary>
    <div class="badges">{''.join(badges)}</div>
    <a class="title" href="{escape(url, quote=True)}" target="_blank" rel="noopener">{escape(title)}</a>
    {meta_div}
  </summary>
  <div class="entry-body">
    <a class="open-link" href="{escape(url, quote=True)}" target="_blank" rel="noopener">Open ↗</a>
    {summary_html}
  </div>
</details>"""


def _section(section_id: str, title: str, subtitle: str, entries_html: list[str],
             empty_message: str = "Nothing new.", extra: str = "") -> str:
    """`extra` is raw HTML (already built by the caller, e.g. a stats row) —
    unlike `subtitle`/`title`, it is NOT escaped, since it needs to render as
    markup rather than literal text."""
    body = "".join(entries_html) if entries_html else f'<p class="empty">{escape(empty_message)}</p>'
    return f"""
<section class="card" id="{section_id}">
  <header>
    <strong>{escape(title)}</strong>
    <div class="subtitle">{escape(subtitle)}</div>
  </header>
  {extra}
  <div class="entries-grid">{body}</div>
</section>"""


def _cve_entries(items: list[dict], show_watched: bool) -> list[str]:
    out = []
    for item in items:
        badges = [_badge(item["severity"].upper(), SEVERITY_COLORS[item["severity"]])]
        if item["cvss"] is not None:
            badges.append(_badge(f"CVSS {item['cvss']:.1f}", SEVERITY_COLORS[item["severity"]]))
        if item["kev"]:
            badges.append(_badge("CISA KEV", KEV_BADGE))
        epss = item.get("epss")
        if epss is not None:
            percentile = item.get("ranking_epss")
            label = f"EPSS {epss * 100:.0f}%" + (f" (P{percentile * 100:.0f})" if percentile is not None else "")
            badges.append(_badge(label, EPSS_BADGE))
        elif item.get("epss_status") == "unavailable":
            badges.append(_badge("EPSS: none yet", NEUTRAL_BADGE))
        elif item.get("epss_status") == "failed":
            badges.append(_badge("EPSS: lookup failed", NEUTRAL_BADGE))
        if item["kev"] and item.get("kev_date_added"):
            due = f", due {item['kev_due_date']}" if item.get("kev_due_date") else ""
            badges.append(_badge(f"KEV added {item['kev_date_added']}{due}", KEV_BADGE))
        if show_watched and item["watched_products"]:
            badges.append(_badge(", ".join(item["watched_products"]), WATCH_BADGE))
        meta = [", ".join(item["products"][:4])] if item["products"] else []
        meta.append("Sources: " + ", ".join(sorted(item["sources"])))
        title = f"{item['id']}: {item['title']}" if item["title"] != item["id"] else item["id"]
        out.append(_entry(title, item["url"], meta, badges, item["description"]))
    return out


def _ghsa_entries(items: list[dict]) -> list[str]:
    out = []
    for item in items:
        badges = [_badge(item["severity"].upper(), SEVERITY_COLORS[item["severity"]])]
        if item["watched_products"]:
            badges.append(_badge(", ".join(item["watched_products"]), WATCH_BADGE))
        # GitHub doesn't always populate vulnerabilities[].package.ecosystem
        # (seen on Oracle Database advisories) — "program" falls back to "?"
        # in that case; skip the meta line rather than show a lone "?".
        meta = [item["program"]] if item["program"] != "?" else []
        out.append(_entry(item["title"], item["url"], meta, badges, item["summary"]))
    return out


PAGE_STYLE = """
body { margin:0; background:#f1f5f9; color:#172554; font-family: Arial, Helvetica, sans-serif; }
main { max-width:95vw; margin:0 auto; padding:24px 16px; }
.hero { padding:34px 28px; border-radius:12px; text-align:center;
        background:linear-gradient(135deg,#111827,#312e81); color:#fff; }
.hero h1 { margin:0; font-size:29px; font-weight:700; }
.hero p { margin:9px 0 0; color:#c7d2fe; font-size:14px; }
.hero .window { margin-top:12px; color:#e0e7ff; font-size:12px; }
.errors { margin:20px 0 0; }
.error-box { margin:8px 0; padding:10px 14px; border:1px solid #fecaca; border-radius:7px;
             background:#fef2f2; color:#991b1b; font-size:12px; }
.card { margin:25px 0; background:#fff; border-radius:10px; overflow:hidden; box-shadow:0 1px 5px #dbe3ee; }
.card > header { padding:15px 18px; background:#172554; color:#fff; }
.card > header strong { font-size:16px; }
.card .subtitle { margin-top:3px; color:#cbd5e1; font-size:12px; }
/* 3-column grid: a 1px gap over a grey background draws consistent dividing
   lines between cells regardless of DOM order, which plain nth-child
   borders can't guarantee once a full-width label (grid-column:1/-1) breaks
   the column rhythm mid-list. */
.entries-grid { display:grid; grid-template-columns: repeat(3, 1fr); gap:1px; background:#e5e7eb; }
.entries-grid > .entry, .entries-grid > .empty { background:#fff; }
.entries-grid > .empty { grid-column: 1 / -1; margin:0; }
@media (max-width: 900px) {
  .entries-grid { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 600px) {
  .entries-grid { grid-template-columns: 1fr; }
}
.entry summary { cursor:pointer; padding:14px 18px; list-style:none; }
.entry summary::-webkit-details-marker { display:none; }
.entry summary::marker { content:""; }
.entry summary::before { content:"▸ "; color:#94a3b8; font-size:12px; }
.entry[open] summary::before { content:"▾ "; }
.entry .badges { display:inline; margin-bottom:5px; }
.badge { display:inline-block; margin:0 4px 4px 0; padding:3px 7px; border-radius:12px;
         color:#fff; font:600 11px Arial, sans-serif; }
.entry .title { font:700 15px Arial, sans-serif; color:#172554; text-decoration:none; }
.entry .title:hover { text-decoration:underline; }
.entry .meta { margin:5px 0 0; color:#64748b; font-size:12px; }
.entry .entry-body { padding:0 18px 16px 18px; }
.entry .open-link { display:inline-block; margin-bottom:8px; font:700 12px Arial, sans-serif;
                     color:#1d4ed8; text-decoration:none; }
.entry .open-link:hover { text-decoration:underline; }
.entry .summary { margin:0; color:#334155; font-size:13px; line-height:1.5; }
.empty { margin:0; padding:14px 18px; color:#64748b; font-size:13px; }
.stats { display:flex; gap:10px; justify-content:center; flex-wrap:wrap; margin:20px 0 6px; }
.stats-note { margin:0 0 14px; padding:0 18px; color:#94a3b8; font-size:11px; text-align:center; }
.stat-tile { min-width:92px; padding:11px; background:#fff; border-radius:8px; text-align:center; }
.stat-tile .count { font:700 22px Arial, sans-serif; }
.stat-tile .label { font-size:11px; color:#64748b; }
footer { padding:18px; text-align:center; color:#94a3b8; font-size:12px; }
"""


def build_html(hours: int, cve_report: dict, ghsa_items: list[dict], ghsa_total: int,
               errors: list[str], epss_stats: dict | None = None) -> str:
    now = datetime.now()
    days = (hours + 23) // 24

    errors_html = ""
    if errors:
        boxes = "".join(f'<div class="error-box">⚠ {escape(err)}</div>' for err in errors)
        errors_html = f'<div class="errors">{boxes}</div>'

    counts = cve_report["counts"]
    cve_stats = "".join(
        f'<div class="stat-tile"><div class="count" style="color:{SEVERITY_COLORS[level]}">{counts[level]}'
        f'</div><div class="label">{level.title()}</div></div>'
        for level in CVE_SEVERITIES)
    cve_entries = []
    if cve_report["watched"]:
        omitted = cve_report["watched_omitted"]
        note = f" ({len(cve_report['watched'])} of {len(cve_report['watched']) + omitted})" if omitted else ""
        cve_entries.append(f'<p class="empty"><strong>Watchlist matches{note}</strong></p>')
        cve_entries += _cve_entries(cve_report["watched"], show_watched=True)
    if cve_report["critical"]:
        omitted = cve_report["critical_omitted"]
        note = f" ({len(cve_report['critical'])} of {len(cve_report['critical']) + omitted})" if omitted else ""
        cve_entries.append(f'<p class="empty"><strong>Other critical / KEV{note}</strong></p>')
        cve_entries += _cve_entries(cve_report["critical"], show_watched=False)
    epss_line = ""
    if epss_stats is not None:
        epss_total = epss_stats["enriched"] + epss_stats["unavailable"] + epss_stats["failed"]
        if epss_total:
            epss_line = (f'<p class="empty">EPSS enrichment: {epss_stats["enriched"]}/{epss_total} enriched'
                        f' · {epss_stats["unavailable"]} unavailable · {epss_stats["failed"]} failed</p>')

    stats_note = ('<p class="stats-note">Severity breakdown of all '
                  f'{cve_report["total"]} CVEs scanned this window — the lists below are '
                  'filtered to watchlist/critical matches only, and capped.</p>')
    cve_section = _section("cves", "CVEs",
                           f"{days}-day window — NVD + GitHub Advisories + CISA KEV ({cve_report['total']} scanned)",
                           cve_entries, "Nothing watchlisted or critical/KEV in this window.",
                           extra=f'<div class="stats">{cve_stats}</div>{stats_note}{epss_line}')

    ghsa_subtitle = f"{days}-day window — github.com/advisories, critical/high or watchlist match ({ghsa_total} scanned)"
    ghsa_section = _section("ghsa", "GitHub Advisories", ghsa_subtitle, _ghsa_entries(ghsa_items),
                            "Nothing critical/high or watchlisted in this window.")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CVE Watch — {now:%Y-%m-%d %H:%M}</title>
<style>{PAGE_STYLE}</style>
</head>
<body>
<main>
  <header class="hero">
    <h1>🛡️ CVE Watch</h1>
    <p>CVEs (NVD + GitHub Advisories + CISA KEV) · GitHub Advisories</p>
    <div class="window">{now:%Y-%m-%d %H:%M} · last {hours} hours</div>
  </header>
  {errors_html}
  {cve_section}
  {ghsa_section}
  <footer>Auto-generated digest · no state file, no dedup — same entry can reappear across runs</footer>
</main>
</body>
</html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours, default: 24")
    args = parser.parse_args()
    if args.hours < 1 or args.hours > 24 * 30:
        parser.error("--hours must be between 1 and 720")

    errors: list[str] = []

    try:
        cve_report, cve_errors = fetch_cves(args.hours)
        errors.extend(cve_errors)
    except Exception as exc:
        errors.append(f"CVEs: {exc}")
        cve_report = {"counts": {s: 0 for s in CVE_SEVERITIES}, "total": 0,
                      "watched": [], "watched_omitted": 0, "critical": [], "critical_omitted": 0}

    epss_stats = None
    try:
        epss_stats = enrich_with_epss(cve_report["watched"] + cve_report["critical"])
        if epss_stats["bailed"]:
            errors.append("EPSS enrichment (cvedb.shodan.io): stopped after repeated failures, "
                          "some CVEs may be missing an EPSS badge")
    except Exception as exc:
        errors.append(f"EPSS enrichment: {exc}")

    try:
        shown_cve_ids = {item["id"] for item in cve_report["watched"] + cve_report["critical"]}
        ghsa_items, ghsa_total = fetch_github_advisories(args.hours, exclude_cve_ids=shown_cve_ids)
    except Exception as exc:
        errors.append(f"GitHub Advisories: {exc}")
        ghsa_items, ghsa_total = [], 0

    cve_has_content = bool(cve_report["watched"] or cve_report["critical"])
    if not (cve_has_content or ghsa_items) and not errors:
        print(f"Nothing new anywhere in the last {args.hours}h — no file written.")
        return
    # If every source came up empty but at least one of them *errored* rather
    # than genuinely having nothing new, still write a file — a quiet day and
    # an outage must not look the same from the folder.

    html_doc = build_html(args.hours, cve_report, ghsa_items, ghsa_total, errors, epss_stats)
    filename = f"cve_watch_{datetime.now():%Y-%m-%d_%H%M}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print(f"Saved: {filename}")
    print(f"CVEs: {cve_report['total']} scanned, {len(cve_report['watched'])} watched, "
          f"{len(cve_report['critical'])} critical/KEV  |  "
          f"GitHub Advisories: {ghsa_total} scanned, {len(ghsa_items)} shown")
    for err in errors:
        print(f"[source error] {err}")


if __name__ == "__main__":
    main()
