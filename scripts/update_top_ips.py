import csv
import datetime
import io
import ipaddress
import os
import sys
import urllib.parse
import urllib.request

START = "<!-- top-ips:start -->"
END = "<!-- top-ips:end -->"
SITE = "https://isipsafe.com"


def fetch_top(api_key: str, base_url: str, limit: int, days: int) -> list[dict]:
    query = urllib.parse.urlencode({"limit": limit, "days": days, "format": "csv"})
    req = urllib.request.Request(
        f"{base_url}/blocklist?{query}",
        headers={"Authorization": f"Bearer {api_key}", "User-Agent": "isipsafe-profile-updater"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8")
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    rows = []
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        ipaddress.ip_address(row["ip"])
        rows.append(row)
    return rows[:limit]


def render(rows: list[dict], today: datetime.date, days: int) -> str:
    out = [
        START,
        f"_Updated every Monday. Last update: {today.isoformat()}. "
        f"The {len(rows)} addresses with the highest confidence score reported in the last {days} days._",
        "",
        "| # | IP address | Confidence | Reports | Country | Last reported | Categories |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rows, 1):
        ip = r["ip"]
        cat_list = [c for c in r.get("categories", "").split(",") if c]
        cats = ", ".join(cat_list[:3]) or "-"
        last = (r.get("last_reported") or "")[:10] or "-"
        out.append(
            f"| {i} | [`{ip}`]({SITE}/ip/{ip}) | {r.get('confidence', '-')}% | {r.get('reports', '-')} "
            f"| {r.get('country') or '-'} | {last} | {cats} |"
        )
    out += ["", f"Full list and live lookups: [{SITE.removeprefix('https://')}]({SITE})", END]
    return "\n".join(out)


def main() -> int:
    readme = sys.argv[1] if len(sys.argv) > 1 else "README.md"
    api_key = os.environ.get("ISIPSAFE_API_KEY", "").strip()
    if not api_key:
        print("ISIPSAFE_API_KEY is not set", file=sys.stderr)
        return 1
    base_url = os.environ.get("ISIPSAFE_BASE_URL", f"{SITE}/api/v1").rstrip("/")
    limit = int(os.environ.get("TOP_IPS_LIMIT", "10"))
    days = int(os.environ.get("TOP_IPS_DAYS", "7"))

    rows = fetch_top(api_key, base_url, limit, days)
    if not rows:
        print("The API returned no addresses; leaving the README unchanged", file=sys.stderr)
        return 1

    with open(readme, encoding="utf-8") as f:
        content = f.read()
    start, end = content.find(START), content.find(END)
    if start == -1 or end == -1 or end < start:
        print(f"{readme} has no {START} ... {END} block", file=sys.stderr)
        return 1

    today = datetime.datetime.now(datetime.timezone.utc).date()
    updated = content[:start] + render(rows, today, days) + content[end + len(END):]
    if updated != content:
        with open(readme, "w", encoding="utf-8") as f:
            f.write(updated)
    print(f"Wrote {len(rows)} addresses to {readme}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
