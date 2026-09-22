#!/usr/bin/env python3
"""
HTTP API for the home policy engine.

Two consumers: the family iPhone app, and an MCP connector that stays
paper-thin by asking this service what it can do.

Binds to 127.0.0.1 only; the only route in is the cloudflared tunnel on this
host, with Cloudflare Access in front doing sign-in. A person arrives with
`Cf-Access-Authenticated-User-Email`; a machine holding an Access service
token (the connector) names the person who asked in `X-Home-Actor`. Either
must be on the allow-list.

  GET  /health
  GET  /auth/start                 sign-in bounce for the app (hands over the Access JWT)
  GET  /services                   the tool catalogue, MCP-shaped, for connectors
  POST /call/<tool>  {args}        run one tool from the catalogue
  GET  /api/groups                 (also reachable as REST for the app)
  GET  /api/<group>/status | usage
  POST /api/<group>/allow | revoke | flush
"""

import datetime as dt
import json
import os
import re
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy  # noqa: E402

HERE = policy.HERE
ALLOWED_FILE = os.path.join(HERE, "allowed-emails.txt")
AUDIT_LOG = os.path.join(HERE, "audit.log")
APP_SCHEME = "archiecontrol"
PORT = int(os.environ.get("PORT", "8787"))
TZ = policy.TZ

CATEGORY = {8: "Games", 4: "Streaming", 13: "Web", 24: "Social", 0: "Messaging", 3: "File transfer",
            5: "Mail", 6: "VoIP", 20: "Network", 28: "Cloud", 14: "Business", 255: "Unknown"}


def allowed_emails():
    try:
        with open(ALLOWED_FILE) as f:
            return {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}
    except FileNotFoundError:
        return set()


def audit(email, action, detail=""):
    with open(AUDIT_LOG, "a") as f:
        f.write(f"{dt.datetime.now(TZ):%Y-%m-%d %H:%M:%S} {email} {action} {detail}\n")


def engine_health():
    try:
        age = time.time() - os.path.getmtime(policy.STATE_FILE)
    except FileNotFoundError:
        age = None
    return {"last_tick_s_ago": None if age is None else int(age), "ok": age is not None and age < 180}


# ── services: what this engine offers, described for an MCP connector ────
#
# Each entry is an MCP tool definition plus `run`, the function that serves
# it. A connector fetches this list, shows the tools to the model verbatim,
# and posts calls to /call/<name>. Add a capability here and every connector
# has it on its next tools/list; nothing to redeploy elsewhere.

GROUP_ARG = {"type": "string", "description": "Which person, from home_groups (e.g. \"archie\")."}
TARGET_ARG = {"type": "string", "description": "Which rules: \"all\" (default), a word from a rule's name such as \"games\" or \"youtube\", or a rule id."}


def svc_groups(actor, args):
    now = dt.datetime.now(TZ)
    state = policy.load_state()
    rules = policy.all_rules()
    out = []
    for name in policy.load_groups():
        st = policy.group_status(name, rules, state, now)
        out.append({"group": name, "devices": list(st["members"]), "rules": len(st["rules"]),
                    "blocking_now": [r["name"] for r in st["rules"] if r["blocking"]],
                    "paused_until": max((r["override"]["until"] for r in st["rules"] if r["override"]), default=None)})
    return {"groups": out, "engine": engine_health()}


def svc_status(actor, args):
    st = policy.group_status(args["group"])
    st["engine"] = engine_health()
    return st


def svc_allow(actor, args):
    spec = args.get("until") or args.get("minutes")
    if not spec:
        raise policy.PolicyError("Give either `minutes` or `until` (HH:MM).")
    reason = (args.get("reason") or "").strip()
    until = policy.cmd_allow(args["group"], args.get("target") or "all", spec, f"{reason} [{actor}]".strip())
    audit(actor, "allow", f"{args['group']} {args.get('target') or 'all'} until {until:%a %H:%M} {reason}")
    return svc_status(actor, args)


def svc_revoke(actor, args):
    policy.cmd_revoke(args["group"], args.get("target") or "all")
    audit(actor, "revoke", f"{args['group']} {args.get('target') or 'all'}")
    return svc_status(actor, args)


def svc_flush(actor, args):
    policy.cmd_flush(args["group"], args.get("target") or "all")
    audit(actor, "flush", f"{args['group']} {args.get('target') or 'all'}")
    return svc_status(actor, args)


def svc_usage(actor, args):
    gname = args["group"]
    now = dt.datetime.now(TZ)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start_ms, end_ms = int(day_start.timestamp() * 1000), int(now.timestamp() * 1000)
    devs = policy.members(gname)
    mac_to_dev = {m: n for n, d in devs.items() for m in d["macs"]}
    wired = {m for d in devs.values() for m in d["wired"]}

    # Units trap: /stat/session takes SECONDS, the report and v2 traffic take MILLISECONDS.
    # Ask sessions from two days back: one that began yesterday and is still open is otherwise missed.
    sessions = policy.api(f"api/s/{policy.SITE}/stat/session",
                          {"type": "all", "start": start_ms // 1000 - 48 * 3600, "end": end_ms // 1000}, "POST").get("data", [])
    # The session log only has finished sessions; a device online now is only in the live list.
    for c in policy.live_clients():
        if str(c.get("mac", "")).lower() in mac_to_dev and c.get("assoc_time"):
            sessions.append({"mac": c["mac"], "assoc_time": c["assoc_time"], "duration": None})
    report = policy.api(f"api/s/{policy.SITE}/stat/report/5minutes.user",
                        {"attrs": ["rx_bytes", "tx_bytes", "time"], "start": start_ms, "end": end_ms, "macs": list(mac_to_dev)}, "POST").get("data", [])
    dpi = policy.api(f"v2/api/site/{policy.SITE}/traffic?start={start_ms}&end={end_ms}&includeUnidentified=true")

    out = {n: {"device": n, "first_seen": None, "last_seen": None, "online_minutes": 0,
               "down_mb": 0.0, "up_mb": 0.0, "categories": {}, "timeline": []} for n in devs}
    for s in sessions:
        name = mac_to_dev.get(str(s.get("mac", "")).lower())
        if not name or not s.get("assoc_time"):
            continue
        a = max(s["assoc_time"], start_ms // 1000)
        b = min(s["assoc_time"] + s["duration"], end_ms // 1000) if s.get("duration") else end_ms // 1000
        if b <= a:
            continue
        o = out[name]
        o["online_minutes"] += int((b - a) / 60)
        fa = dt.datetime.fromtimestamp(a, TZ).isoformat(timespec="minutes")
        fb = dt.datetime.fromtimestamp(b, TZ).isoformat(timespec="minutes")
        o["first_seen"] = min(o["first_seen"] or fa, fa)
        o["last_seen"] = max(o["last_seen"] or fb, fb)
    buckets = {}
    for r in report:
        mac = str(r.get("user", "")).lower()
        name = mac_to_dev.get(mac)
        if not name:
            continue
        # Direction is swapped for wired clients relative to wireless.
        down, up = (r.get("rx_bytes", 0), r.get("tx_bytes", 0)) if mac in wired else (r.get("tx_bytes", 0), r.get("rx_bytes", 0))
        out[name]["down_mb"] += down / 1e6
        out[name]["up_mb"] += up / 1e6
        t = dt.datetime.fromtimestamp(r["time"] / 1000, TZ)
        slot = t.replace(minute=0 if t.minute < 30 else 30, second=0, microsecond=0)
        buckets[(name, slot)] = buckets.get((name, slot), 0) + down + up
    for (name, slot), b in sorted(buckets.items()):
        if b > 1e6:
            out[name]["timeline"].append({"at": slot.isoformat(timespec="minutes"), "mb": round(b / 1e6, 1)})
    for c in dpi.get("client_usage_by_app", []) if isinstance(dpi, dict) else []:
        name = mac_to_dev.get(str((c.get("client") or {}).get("mac", "")).lower())
        if not name:
            continue
        for a in c.get("usage_by_app", []):
            label = CATEGORY.get(a.get("category"), f"cat {a.get('category')}")
            out[name]["categories"][label] = out[name]["categories"].get(label, 0) + a.get("total_bytes", 0)
    for o in out.values():
        o["down_mb"], o["up_mb"] = round(o["down_mb"], 1), round(o["up_mb"], 1)
        o["categories"] = [{"name": k, "mb": round(v / 1e6, 1)} for k, v in sorted(o["categories"].items(), key=lambda x: -x[1]) if v > 1e6]
    return {"group": gname, "day": day_start.date().isoformat(), "now": now.isoformat(timespec="seconds"), "devices": list(out.values())}


SERVICES = [
    {"name": "home_groups", "run": svc_groups, "annotations": {"readOnlyHint": True},
     "description": "The people this home's screen-time engine manages, with their devices, how many rules each has, what is blocking right now and any pause in force. Call first to learn the group names the other home_* tools take.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "home_status", "run": svc_status, "annotations": {"readOnlyHint": True},
     "description": "One person's rules right now: each rule, whether it is blocking at this moment, its weekly schedule, any active pause and when it ends, and their devices. Answers 'is he blocked right now?'.",
     "inputSchema": {"type": "object", "properties": {"group": GROUP_ARG}, "required": ["group"], "additionalProperties": False}},
    {"name": "home_allow", "run": svc_allow, "annotations": {"readOnlyHint": False, "destructiveHint": False},
     "description": "Let someone on: pause their rules for a while ('give him an hour', 'until 5pm', 'the rest of the day' = until 23:59). The rules come back on by themselves when the time is up. Pass minutes or an until time (HH:MM, 24-hour, home local time; a time already past means tomorrow). Defaults to all their rules; target 'games' or 'youtube' to pause just one.",
     "inputSchema": {"type": "object", "properties": {"group": GROUP_ARG, "minutes": {"type": "number"}, "until": {"type": "string", "description": "HH:MM local time"}, "target": TARGET_ARG, "reason": {"type": "string", "description": "Short note for the audit log."}}, "required": ["group"], "additionalProperties": False}},
    {"name": "home_revoke", "run": svc_revoke, "annotations": {"readOnlyHint": False, "destructiveHint": False},
     "description": "End a pause early: put someone's rules back to their normal schedule now. Inside a blocking window this cuts whatever they have open.",
     "inputSchema": {"type": "object", "properties": {"group": GROUP_ARG, "target": TARGET_ARG}, "required": ["group"], "additionalProperties": False}},
    {"name": "home_cut_sessions", "run": svc_flush, "annotations": {"readOnlyHint": False, "destructiveHint": False},
     "description": "Cut whatever someone has open right now (a stream, a game session) without changing any schedule: each rule currently blocking is switched off and on, which drops established connections.",
     "inputSchema": {"type": "object", "properties": {"group": GROUP_ARG, "target": TARGET_ARG}, "required": ["group"], "additionalProperties": False}},
    {"name": "home_usage", "run": svc_usage, "annotations": {"readOnlyHint": True},
     "description": "What someone's devices did today: per device, when it first came online, time online, download, kinds of traffic (games, streaming, web) and a half-hourly timeline. For 'what time did he start?' and 'was he on the Xbox?'.",
     "inputSchema": {"type": "object", "properties": {"group": GROUP_ARG}, "required": ["group"], "additionalProperties": False}},
]
SERVICE_BY_NAME = {s["name"]: s for s in SERVICES}


# ── HTTP ─────────────────────────────────────────────────────────────────

REST = {  # the app's REST shape, mapped onto the same services
    ("GET", "groups"): "home_groups", ("GET", "status"): "home_status", ("GET", "usage"): "home_usage",
    ("POST", "allow"): "home_allow", ("POST", "revoke"): "home_revoke", ("POST", "flush"): "home_cut_sessions",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "home-policy-api/2"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def actor(self):
        email = (self.headers.get("Cf-Access-Authenticated-User-Email") or self.headers.get("X-Home-Actor") or "").lower()
        return email if email and email in allowed_emails() else None

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            raise policy.PolicyError("bad json")

    def run_service(self, name, actor, args):
        svc = SERVICE_BY_NAME.get(name)
        if not svc:
            return self.send_json(404, {"error": f"no service '{name}'"})
        try:
            return self.send_json(200, svc["run"](actor, args or {}))
        except policy.PolicyError as e:
            return self.send_json(400, {"error": str(e)})
        except KeyError as e:
            return self.send_json(400, {"error": f"missing argument {e}"})

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/health":
            return self.send_json(200, {"ok": True, "engine": engine_health()})
        actor = self.actor()
        if path == "/auth/start":
            jwt = self.headers.get("Cf-Access-Jwt-Assertion")
            if not actor or not jwt:
                return self.send_json(403, {"error": "not signed in, or not on the allow-list"})
            audit(actor, "sign-in")
            self.send_response(302)
            self.send_header("Location", f"{APP_SCHEME}://auth?" + urllib.parse.urlencode({"token": jwt, "email": actor}))
            self.end_headers()
            return
        if not actor:
            return self.send_json(403, {"error": "forbidden"})
        if path == "/services":
            return self.send_json(200, {"tools": [{k: s[k] for k in ("name", "description", "inputSchema", "annotations")} for s in SERVICES]})
        m = re.fullmatch(r"/api/(?:(?P<group>[^/]+)/)?(?P<op>groups|status|usage)", path)
        if m and ("GET", m["op"]) in REST:
            return self.run_service(REST[("GET", m["op"])], actor, {"group": m["group"]} if m["group"] else {})
        self.send_json(404, {"error": "no such endpoint"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        actor = self.actor()
        if not actor:
            return self.send_json(403, {"error": "forbidden"})
        try:
            args = self.body()
        except policy.PolicyError as e:
            return self.send_json(400, {"error": str(e)})
        m = re.fullmatch(r"/call/(?P<tool>[a-z_]+)", path)
        if m:
            return self.run_service(m["tool"], actor, args)
        m = re.fullmatch(r"/api/(?P<group>[^/]+)/(?P<op>allow|revoke|flush)", path)
        if m:
            return self.run_service(REST[("POST", m["op"])], actor, {**args, "group": m["group"]})
        self.send_json(404, {"error": "no such endpoint"})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
