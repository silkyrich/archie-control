#!/usr/bin/env python3
"""
Home policy engine for UniFi traffic rules.

UniFi enforces the rules and their weekly schedules itself. This script fills
the two gaps we found by testing on 2026-09-17:

  1. When a scheduled window STARTS, the gateway only blocks NEW connections.
     A YouTube stream or Roblox session opened before 08:30 carries on.
     Switching the rule off and on again kills those sessions, so `tick` does
     that at the moment each window opens.
  2. Timed overrides ("give Archie an hour"): the rule is disabled now and
     re-enabled when the override expires. Re-enabling inside a window also
     kills open sessions.

Only rules whose description starts with MANAGED_PREFIX are touched.

Usage:
  policy.py tick                         run every minute from cron
  policy.py status
  policy.py allow <target> <minutes|HH:MM> [reason...]
  policy.py revoke <target>
  policy.py flush <target>               kill open sessions now

<target> is `all`, a rule id, or a word from the rule's description
(`youtube`, `games`, `xbox`, ...).
"""

import copy
import datetime as dt
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(HERE, "unifi.key")
HOST_FILE = os.path.join(HERE, "host.id")   # present => cloud key, relay via api.ui.com
STATE_FILE = os.path.join(HERE, "state.json")
GROUP_FILE = os.path.join(HERE, "archie-group.json")
GATEWAY = "https://192.168.0.1/proxy/network/"
SITE = "default"
TZ = ZoneInfo("Europe/London")  # the host clock is UTC; UniFi schedules are local
MANAGED_PREFIX = "Archie - "
DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

_ctx = ssl._create_unverified_context()  # the gateway's certificate is self-signed


def log(msg):
    print(f"{dt.datetime.now(TZ):%Y-%m-%d %H:%M:%S} {msg}", flush=True)


def base_url():
    """A local gateway key talks to 192.168.0.1 directly; a Site Manager key
    goes through Ubiquiti's cloud relay, which forwards the same paths."""
    if os.path.exists(HOST_FILE):
        with open(HOST_FILE) as f:
            return f"https://api.ui.com/v1/connector/consoles/{f.read().strip()}/proxy/network/"
    return GATEWAY


def api(path, body=None, method="GET", tries=3):
    with open(KEY_FILE) as f:
        key = f.read().strip()
    last = None
    for attempt in range(tries):
        req = urllib.request.Request(
            base_url() + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"X-API-KEY": key, "Content-Type": "application/json"},
            method=method,
        )
        try:
            raw = urllib.request.urlopen(req, timeout=30, context=_ctx).read().decode()
            return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            raise SystemExit(f"UniFi {method} {path} -> {e.code}: {e.read().decode()[:300]}")
        except (json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError) as e:
            # The cloud relay occasionally returns a truncated body or drops
            # the connection; a second try a moment later almost always works.
            last = e
            time.sleep(2 * (attempt + 1))
    raise SystemExit(f"UniFi {method} {path} failed after {tries} tries: {last!r}"[:300])


def rules_url(rid=""):
    return f"v2/api/site/{SITE}/trafficrules" + (f"/{rid}" if rid else "")


def managed_rules():
    return [r for r in api(rules_url()) if r.get("description", "").startswith(MANAGED_PREFIX)]


def load_state():
    try:
        with open(STATE_FILE) as f:
            s = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        s = {}
    s.setdefault("overrides", {})
    s.setdefault("in_window", {})
    s.setdefault("hub_seen", {})   # mac -> {"name", "last_seen"} for devices wired behind the hub
    return s


def load_group():
    try:
        with open(GROUP_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def live_clients():
    return api(f"api/s/{SITE}/stat/sta").get("data", [])


def sync_group(state, now, clients=None):
    """Keep the rules' device lists in step with Archie's group.

    'hub' members are discovered from where wired clients sit: behind his Flex
    Mini, or straight into the Office switch port it uplinks on. They are
    remembered for `remember_days` so the Xbox is still covered when it's
    powered off and comes back at 07:31. Members are only ever added to a
    rule, never removed, so hand-made targets survive.
    """
    g = load_group()
    if not g:
        return []
    hub = g.get("hub") or {}
    fb = hub.get("fallback_port") or {}
    for c in (clients if clients is not None else live_clients()):
        if not c.get("is_wired"):
            continue
        sw, port = str(c.get("sw_mac", "")).lower(), c.get("sw_port")
        behind_hub = sw == hub.get("switch_mac", "").lower()
        on_port = sw == str(fb.get("switch_mac", "")).lower() and port == fb.get("port")
        if behind_hub or on_port:
            state["hub_seen"][c["mac"].lower()] = {"name": c.get("name") or c.get("hostname") or c["mac"],
                                                    "last_seen": now.isoformat(timespec="seconds")}
    keep = now - dt.timedelta(days=hub.get("remember_days", 30))
    for mac in [m for m, v in state["hub_seen"].items() if dt.datetime.fromisoformat(v["last_seen"]) < keep]:
        state["hub_seen"].pop(mac)

    sets = {"hub": set(state["hub_seen"]),
            "consoles": {m.lower() for m in (g.get("consoles") or {})},
            "wifi": {m.lower() for m in (g.get("wifi") or {})}}
    changed = []
    rules = {r["_id"]: r for r in managed_rules()}
    for rid, want_sets in (g.get("rules") or {}).items():
        r = rules.get(rid)
        if not r:
            continue
        want = set().union(*(sets[s] for s in want_sets if s in sets))
        have = {str(t.get("client_mac", "")).lower() for t in r.get("target_devices", []) if t.get("type") == "CLIENT"}
        missing = sorted(want - have)
        if missing:
            body = copy.deepcopy(r)
            body["target_devices"] = r.get("target_devices", []) + [{"type": "CLIENT", "client_mac": m} for m in missing]
            api(rules_url(rid), body, "PUT")
            changed.append((r["description"], missing))
    return changed


def group_members():
    """Name -> macs for everything in the group, for status and the app."""
    g = load_group() or {}
    state = load_state()
    out = {}
    for m, n in (g.get("consoles") or {}).items():
        out.setdefault(n, []).append(m.lower())
    for m, n in (g.get("wifi") or {}).items():
        out.setdefault(n, []).append(m.lower())
    for m, v in state["hub_seen"].items():
        if not any(m in macs for macs in out.values()):
            out.setdefault(v["name"], []).append(m)
    return out


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, STATE_FILE)


def in_window(rule, now):
    """Is the rule's own UniFi schedule active at `now` (local time)?"""
    s = rule.get("schedule") or {}
    mode = s.get("mode", "ALWAYS")
    if mode == "ALWAYS":
        return True
    if mode != "EVERY_WEEK":
        return False  # one-off modes aren't used here
    today = DAYS[now.weekday()]
    yesterday = DAYS[(now.weekday() - 1) % 7]
    days = s.get("repeat_on_days") or []
    if s.get("time_all_day"):
        return today in days
    start = dt.time.fromisoformat(s["time_range_start"])
    end = dt.time.fromisoformat(s["time_range_end"])
    t = now.time()
    if start <= end:
        return today in days and start <= t < end
    # Overnight window, e.g. 21:00-07:00: the early part belongs to the day before.
    return (today in days and t >= start) or (yesterday in days and t < end)


def set_enabled(rule, enabled):
    body = copy.deepcopy(rule)
    body["enabled"] = enabled
    return api(rules_url(rule["_id"]), body, "PUT")


def flush(rule):
    """Off then on: the only update we found that kills established sessions."""
    set_enabled(rule, False)
    time.sleep(3)
    set_enabled(rule, True)


def resolve(target, rules):
    if target == "all":
        return rules
    hit = [r for r in rules if r["_id"] == target or target.lower() in r["description"].lower()]
    if not hit:
        raise SystemExit(f"No managed rule matches '{target}'. Try: status")
    return hit


def parse_until(spec, now):
    if ":" in spec:
        h, m = (int(x) for x in spec.split(":"))
        until = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if until <= now:
            until += dt.timedelta(days=1)
        return until
    return now + dt.timedelta(minutes=int(spec))


def cmd_tick():
    if not os.path.exists(KEY_FILE):
        return  # not provisioned yet; stay quiet rather than fill the log every minute
    now = dt.datetime.now(TZ)
    state = load_state()
    for desc, macs in sync_group(state, now):
        log(f"group: added {', '.join(macs)} to {desc}")
    for rule in managed_rules():
        rid, name = rule["_id"], rule["description"]
        active_now = in_window(rule, now)
        was_active = state["in_window"].get(rid)
        ov = state["overrides"].get(rid)
        ov_live = bool(ov) and dt.datetime.fromisoformat(ov["until"]) > now

        if ov and not ov_live:
            state["overrides"].pop(rid)
            log(f"override expired: {name}")

        if ov_live:
            if rule["enabled"]:
                set_enabled(rule, False)
                log(f"override active until {ov['until'][11:16]}, disabled: {name}")
        elif not rule["enabled"]:
            # Re-enabling inside a window also kills open sessions.
            set_enabled(rule, True)
            log(f"re-enabled{' (in window, sessions cut)' if active_now else ''}: {name}")
        elif active_now and was_active is False:
            flush(rule)
            log(f"window opened, sessions cut: {name}")

        state["in_window"][rid] = active_now
    save_state(state)


def cmd_status():
    now = dt.datetime.now(TZ)
    state = load_state()
    print(f"now {now:%a %H:%M} Europe/London")
    for r in managed_rules():
        s = r.get("schedule") or {}
        when = "always" if s.get("mode") == "ALWAYS" else \
            f"{','.join(s.get('repeat_on_days') or [])} {s.get('time_range_start')}-{s.get('time_range_end')}"
        ov = state["overrides"].get(r["_id"])
        extra = f"  OVERRIDE until {ov['until'][11:16]} ({ov.get('reason') or 'no reason'})" if ov else ""
        print(f"  {'ON ' if r['enabled'] else 'off'} {'BLOCKING' if r['enabled'] and in_window(r, now) else 'idle    '} "
              f"{r['description']}  [{when}]  id={r['_id']}{extra}")
    members = group_members()
    if members:
        print("group:", "; ".join(f"{n} ({', '.join(m)})" for n, m in members.items()))
        hub = load_state()["hub_seen"]
        print("behind the hub:", ", ".join(f"{v['name']} (seen {v['last_seen'][:16]})" for v in hub.values()) or "nothing seen yet")


def cmd_allow(target, spec, reason):
    now = dt.datetime.now(TZ)
    until = parse_until(spec, now)
    state = load_state()
    for r in resolve(target, managed_rules()):
        state["overrides"][r["_id"]] = {"until": until.isoformat(timespec="seconds"), "reason": reason,
                                        "set_at": now.isoformat(timespec="seconds")}
        if r["enabled"]:
            set_enabled(r, False)
        log(f"allow until {until:%a %H:%M}: {r['description']}" + (f" ({reason})" if reason else ""))
    save_state(state)


def cmd_revoke(target):
    state = load_state()
    for r in resolve(target, managed_rules()):
        state["overrides"].pop(r["_id"], None)
        if not r["enabled"]:
            set_enabled(r, True)
        log(f"override revoked, rule on: {r['description']}")
    save_state(state)


def cmd_flush(target):
    for r in resolve(target, managed_rules()):
        if r["enabled"]:
            flush(r)
            log(f"sessions cut: {r['description']}")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return
    cmd, args = argv[0], argv[1:]
    if cmd == "tick":
        cmd_tick()
    elif cmd == "status":
        cmd_status()
    elif cmd == "allow" and len(args) >= 2:
        cmd_allow(args[0], args[1], " ".join(args[2:]))
    elif cmd == "revoke" and len(args) == 1:
        cmd_revoke(args[0])
    elif cmd == "flush" and len(args) == 1:
        cmd_flush(args[0])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
