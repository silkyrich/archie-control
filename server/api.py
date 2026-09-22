#!/usr/bin/env python3
"""
HTTP API for the home policy engine, for the Archie Control iPhone app.

Binds to 127.0.0.1 only. The only thing that can reach it is the cloudflared
tunnel on this host, and Cloudflare Access in front of the public hostname
does the sign-in (Google). Access stamps every forwarded request with
`Cf-Access-Authenticated-User-Email`; we additionally require that email to be
on the allow-list so a misconfigured Access policy can't widen who has the
buttons.

Endpoints:
  GET  /health                     public, for monitoring
  GET  /auth/start                 sign-in bounce: hands the Access JWT to the app
  GET  /api/status                 rules, overrides, engine health
  POST /api/allow  {target, minutes | until, reason}
  POST /api/revoke {target}
  POST /api/flush  {target}
  GET  /api/usage                  today's per-device usage for Archie's kit
"""

import datetime as dt
import json
import os
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy  # noqa: E402  (same directory)

HERE = policy.HERE
ALLOWED_FILE = os.path.join(HERE, "allowed-emails.txt")
DEVICES_FILE = os.path.join(HERE, "devices.json")
AUDIT_LOG = os.path.join(HERE, "audit.log")
ENGINE_LOG = os.path.join(HERE, "engine.log")
APP_SCHEME = "archiecontrol"
PORT = int(os.environ.get("PORT", "8787"))
TZ = policy.TZ

# UniFi DPI categories we care about, by the ids the gateway uses.
CATEGORY = {8: "Games", 4: "Streaming", 13: "Web", 24: "Social", 0: "Messaging", 3: "File transfer",
            5: "Mail", 6: "VoIP", 20: "Network", 28: "Cloud", 14: "Business", 255: "Unknown"}


def allowed_emails():
    try:
        with open(ALLOWED_FILE) as f:
            return {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}
    except FileNotFoundError:
        return set()


def devices():
    """Archie's devices for the usage view: the group definition (consoles,
    wifi, anything seen behind his hub), falling back to devices.json."""
    members = policy.group_members()
    if members:
        # Traffic direction is swapped for wired clients, so the usage code
        # needs to know which addresses are wired: anything seen behind the
        # hub, plus any the group file marks as such.
        g = policy.load_group() or {}
        wired = set(policy.load_state()["hub_seen"]) | {m.lower() for m in g.get("wired", [])}
        return [{"name": n, "macs": macs, "wired_macs": [m for m in macs if m in wired]} for n, macs in members.items()]
    with open(DEVICES_FILE) as f:
        return json.load(f)


def audit(email, action, detail=""):
    with open(AUDIT_LOG, "a") as f:
        f.write(f"{dt.datetime.now(TZ):%Y-%m-%d %H:%M:%S} {email} {action} {detail}\n")


def engine_health():
    """When did the cron tick last succeed? state.json is rewritten every tick."""
    try:
        age = time.time() - os.path.getmtime(policy.STATE_FILE)
    except FileNotFoundError:
        age = None
    return {"last_tick_s_ago": None if age is None else int(age), "ok": age is not None and age < 180}


def rule_view(r, state, now):
    s = r.get("schedule") or {}
    ov = state["overrides"].get(r["_id"])
    return {
        "id": r["_id"],
        "name": r["description"].replace(policy.MANAGED_PREFIX, "", 1),
        "enabled": r["enabled"],
        "blocking": bool(r["enabled"] and policy.in_window(r, now)),
        "schedule": "always" if s.get("mode") == "ALWAYS" else
                    {"days": s.get("repeat_on_days"), "start": s.get("time_range_start"), "end": s.get("time_range_end")},
        "override": None if not ov else {"until": ov["until"], "reason": ov.get("reason"), "set_at": ov.get("set_at")},
    }


def status():
    now = dt.datetime.now(TZ)
    state = policy.load_state()
    return {
        "now": now.isoformat(timespec="seconds"),
        "rules": [rule_view(r, state, now) for r in policy.managed_rules()],
        "engine": engine_health(),
    }


# ── usage ────────────────────────────────────────────────────────────────

def usage():
    now = dt.datetime.now(TZ)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start_ms, end_ms = int(day_start.timestamp() * 1000), int(now.timestamp() * 1000)
    devs = devices()
    mac_to_dev = {m.lower(): d["name"] for d in devs for m in d["macs"]}
    all_macs = list(mac_to_dev)

    # Sessions take SECONDS; the report and the v2 traffic endpoint take MILLISECONDS.
    # Ask from two days back: a session that began yesterday and is still open
    # (the iPad, typically) is otherwise missed, and we clamp to today below.
    sessions = policy.api(f"api/s/{policy.SITE}/stat/session",
                          {"type": "all", "start": start_ms // 1000 - 48 * 3600, "end": end_ms // 1000}, "POST").get("data", [])
    report = policy.api(f"api/s/{policy.SITE}/stat/report/5minutes.user",
                        {"attrs": ["rx_bytes", "tx_bytes", "time"], "start": start_ms, "end": end_ms, "macs": all_macs}, "POST").get("data", [])
    dpi = policy.api(f"v2/api/site/{policy.SITE}/traffic?start={start_ms}&end={end_ms}&includeUnidentified=true")

    out = {d["name"]: {"device": d["name"], "first_seen": None, "last_seen": None, "online_minutes": 0,
                       "down_mb": 0.0, "up_mb": 0.0, "categories": {}, "timeline": []} for d in devs}

    # The session log only has finished sessions. A device that is online now
    # (the iPad, for days at a time) appears only in the live client list, so
    # add its current session from there, open-ended.
    for c in policy.api(f"api/s/{policy.SITE}/stat/sta").get("data", []):
        if str(c.get("mac", "")).lower() in mac_to_dev and c.get("assoc_time"):
            sessions.append({"mac": c["mac"], "assoc_time": c["assoc_time"], "duration": None})

    for s in sessions:
        name = mac_to_dev.get(str(s.get("mac", "")).lower())
        if not name or not s.get("assoc_time"):
            continue
        a = max(s["assoc_time"], start_ms // 1000)
        # A still-open session has no duration; treat it as running to now.
        b = min(s["assoc_time"] + s["duration"], end_ms // 1000) if s.get("duration") else end_ms // 1000
        if b <= a:
            continue
        o = out[name]
        o["online_minutes"] += int((b - a) / 60)
        fa = dt.datetime.fromtimestamp(a, TZ).isoformat(timespec="minutes")
        fb = dt.datetime.fromtimestamp(b, TZ).isoformat(timespec="minutes")
        o["first_seen"] = min(o["first_seen"] or fa, fa)
        o["last_seen"] = max(o["last_seen"] or fb, fb)

    # Direction: for wireless clients tx is the client's download. All of
    # Archie's kit is wireless except the Xbox's wired port, which is swapped.
    wired = {m.lower() for d in devs for m in d.get("wired_macs", [])}
    buckets = {}
    for r in report:
        mac = str(r.get("user", "")).lower()
        name = mac_to_dev.get(mac)
        if not name:
            continue
        down, up = (r.get("rx_bytes", 0), r.get("tx_bytes", 0)) if mac in wired else (r.get("tx_bytes", 0), r.get("rx_bytes", 0))
        out[name]["down_mb"] += down / 1e6
        out[name]["up_mb"] += up / 1e6
        t = dt.datetime.fromtimestamp(r["time"] / 1000, TZ)
        slot = t.replace(minute=0 if t.minute < 30 else 30, second=0, microsecond=0)
        buckets.setdefault((name, slot), 0)
        buckets[(name, slot)] += down + up
    for (name, slot), b in sorted(buckets.items()):
        if b > 1e6:
            out[name]["timeline"].append({"at": slot.isoformat(timespec="minutes"), "mb": round(b / 1e6, 1)})

    for c in dpi.get("client_usage_by_app", []) if isinstance(dpi, dict) else []:
        name = mac_to_dev.get(str((c.get("client") or {}).get("mac", "")).lower())
        if not name:
            continue
        cats = out[name]["categories"]
        for a in c.get("usage_by_app", []):
            label = CATEGORY.get(a.get("category"), f"cat {a.get('category')}")
            cats[label] = cats.get(label, 0) + a.get("total_bytes", 0)
    for o in out.values():
        o["down_mb"] = round(o["down_mb"], 1)
        o["up_mb"] = round(o["up_mb"], 1)
        o["categories"] = [{"name": k, "mb": round(v / 1e6, 1)} for k, v in sorted(o["categories"].items(), key=lambda x: -x[1]) if v > 1e6]
    return {"day": day_start.date().isoformat(), "now": now.isoformat(timespec="seconds"), "devices": list(out.values())}


# ── actions (thin wrappers over the engine, with audit) ─────────────────

def do_allow(email, body):
    target = body.get("target", "all")
    spec = str(body.get("until") or body.get("minutes") or "60")
    reason = (body.get("reason") or "") + f" [{email}]"
    policy.cmd_allow(target, spec, reason.strip())
    audit(email, "allow", f"{target} {spec} {body.get('reason','')}")


def do_revoke(email, body):
    policy.cmd_revoke(body.get("target", "all"))
    audit(email, "revoke", body.get("target", "all"))


def do_flush(email, body):
    policy.cmd_flush(body.get("target", "all"))
    audit(email, "flush", body.get("target", "all"))


# ── HTTP ─────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "archie-api/1"

    def log_message(self, fmt, *args):  # keep the journal quiet; audit.log has what matters
        pass

    def send_json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def user(self):
        # A person signing in through Access arrives with their email. A
        # machine using an Access service token (the MCP connector) carries no
        # email, so it names the person who asked in X-Home-Actor. Both are
        # trustworthy only because nothing but the tunnel can reach this port.
        email = (self.headers.get("Cf-Access-Authenticated-User-Email") or
                 self.headers.get("X-Home-Actor") or "").lower()
        return email if email and email in allowed_emails() else None

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/health":
            return self.send_json(200, {"ok": True, "engine": engine_health()})
        if path == "/auth/start":
            # Access has already authenticated the browser session; hand the app
            # the JWT so it can send it back as `cf-access-token` on API calls.
            email = self.user()
            jwt = self.headers.get("Cf-Access-Jwt-Assertion")
            if not email or not jwt:
                return self.send_json(403, {"error": "not signed in, or not on the allow-list"})
            audit(email, "sign-in")
            self.send_response(302)
            self.send_header("Location", f"{APP_SCHEME}://auth?" + urllib.parse.urlencode({"token": jwt, "email": email}))
            self.end_headers()
            return
        email = self.user()
        if not email:
            return self.send_json(403, {"error": "forbidden"})
        try:
            if path == "/api/status":
                return self.send_json(200, status())
            if path == "/api/usage":
                return self.send_json(200, usage())
        except SystemExit as e:  # policy.py reports UniFi errors this way
            return self.send_json(502, {"error": str(e)})
        self.send_json(404, {"error": "no such endpoint"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        email = self.user()
        if not email:
            return self.send_json(403, {"error": "forbidden"})
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self.send_json(400, {"error": "bad json"})
        action = {"/api/allow": do_allow, "/api/revoke": do_revoke, "/api/flush": do_flush}.get(path)
        if not action:
            return self.send_json(404, {"error": "no such endpoint"})
        try:
            action(email, body)
        except SystemExit as e:
            return self.send_json(400, {"error": str(e)})
        self.send_json(200, status())


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
