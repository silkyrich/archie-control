#!/usr/bin/env python3
"""
Home policy engine: a people layer over UniFi traffic rules.

UniFi enforces the rules and their weekly schedules. This adds what it lacks:

  * groups — a person is the set of hosts we know are theirs: anything wired
    behind their own switch (discovered, remembered 30 days), plus named
    consoles and wifi devices. Rules belong to a group by description prefix.
  * session cuts — when a rule's window OPENS, UniFi only blocks new
    connections; a stream started beforehand carries on. Off→on kills it, so
    `tick` does that the minute a window opens.
  * timed overrides — "allow until 17:00" disables the rules now and the tick
    restores them on time. Restoring inside a window also cuts sessions.

Usage:
  policy.py tick                                    every minute from cron
  policy.py groups
  policy.py status [group]
  policy.py allow  <group> <target> <minutes|HH:MM> [reason...]
  policy.py revoke <group> <target>
  policy.py flush  <group> <target>                 cut open sessions now
  policy.py forget <group> <mac>                    drop a wrongly-discovered device

<target> is `all`, a rule id, or a word from the rule's description
(`youtube`, `games`, `xbox`, ...).

Config: groups.json — {"<group>": {"prefix": "Archie - ", "hub": {...},
"consoles": {mac: name}, "wifi": {mac: name}, "wired": [mac], "rules":
{rule_id: ["hub","consoles","wifi"]}}}. A legacy single-group
archie-group.json is read as group "archie".
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
GROUPS_FILE = os.path.join(HERE, "groups.json")
LEGACY_GROUP_FILE = os.path.join(HERE, "archie-group.json")
GATEWAY = "https://192.168.0.1/proxy/network/"
SITE = "default"
TZ = ZoneInfo("Europe/London")  # the host clock is UTC; UniFi schedules are local
DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

_ctx = ssl._create_unverified_context()  # the gateway's certificate is self-signed


def log(msg):
    print(f"{dt.datetime.now(TZ):%Y-%m-%d %H:%M:%S} {msg}", flush=True)


class PolicyError(Exception):
    """A user-facing problem (bad target, unknown group, gateway refused)."""


# ── UniFi ────────────────────────────────────────────────────────────────

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
            raise PolicyError(f"UniFi {method} {path} -> {e.code}: {e.read().decode()[:300]}")
        except (json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError) as e:
            # The cloud relay occasionally returns a truncated body or drops
            # the connection; a second try a moment later almost always works.
            last = e
            time.sleep(2 * (attempt + 1))
    raise PolicyError(f"UniFi {method} {path} failed after {tries} tries: {last!r}"[:300])


def rules_url(rid=""):
    return f"v2/api/site/{SITE}/trafficrules" + (f"/{rid}" if rid else "")


def all_rules():
    return api(rules_url())


def live_clients():
    return api(f"api/s/{SITE}/stat/sta").get("data", [])


# ── config and state ─────────────────────────────────────────────────────

def load_groups():
    """name -> group definition. Falls back to the legacy single-group file."""
    if os.path.exists(GROUPS_FILE):
        with open(GROUPS_FILE) as f:
            return {k: v for k, v in json.load(f).items() if not k.startswith("_")}
    if os.path.exists(LEGACY_GROUP_FILE):
        with open(LEGACY_GROUP_FILE) as f:
            g = json.load(f)
        g.setdefault("prefix", "Archie - ")
        return {"archie": g}
    return {}


def group(name):
    gs = load_groups()
    if name not in gs:
        raise PolicyError(f"No group '{name}'. Groups: {', '.join(gs) or 'none configured'}")
    return gs[name]


def load_state():
    try:
        with open(STATE_FILE) as f:
            s = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        s = {}
    s.setdefault("overrides", {})     # rule id -> {until, reason, set_at}
    s.setdefault("in_window", {})     # rule id -> bool, last tick
    hub = s.setdefault("hub_seen", {})  # group -> mac -> {name, last_seen}
    if hub and all(":" in k for k in hub):  # pre-groups layout: flat mac map
        s["hub_seen"] = {"archie": hub}
    return s


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, STATE_FILE)


# ── rules ────────────────────────────────────────────────────────────────

def managed_rules(gname, rules=None):
    prefix = group(gname).get("prefix", "")
    return [r for r in (rules if rules is not None else all_rules()) if r.get("description", "").startswith(prefix)]


def in_window(rule, now):
    """Is the rule's own UniFi schedule active at `now` (local time)?"""
    s = rule.get("schedule") or {}
    mode = s.get("mode", "ALWAYS")
    if mode == "ALWAYS":
        return True
    if mode != "EVERY_WEEK":
        return False
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
    return (today in days and t >= start) or (yesterday in days and t < end)  # overnight window


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
    if target in ("all", "", None):
        return rules
    hit = [r for r in rules if r["_id"] == target or target.lower() in r["description"].lower()]
    if not hit:
        raise PolicyError(f"No rule matches '{target}'. Rules: " + "; ".join(r["description"] for r in rules))
    return hit


def parse_until(spec, now):
    spec = str(spec)
    if ":" in spec:
        h, m = (int(x) for x in spec.split(":"))
        until = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if until <= now:
            until += dt.timedelta(days=1)
        return until
    return now + dt.timedelta(minutes=int(spec))


# ── groups: membership discovery ─────────────────────────────────────────

def sync_groups(state, now, clients=None):
    """Keep each group's rules in step with its members.

    'hub' members are discovered from where wired clients sit: behind the
    group's own switch, or on the upstream port it uplinks through. They are
    remembered for `remember_days` so a console that is off tonight is still
    covered when it comes back tomorrow. Members are only ever added to a
    rule, never removed, so hand-made targets survive.
    """
    groups = load_groups()
    if not groups:
        return []
    clients = clients if clients is not None else live_clients()
    rules = {r["_id"]: r for r in all_rules()}
    changed = []
    for gname, g in groups.items():
        hub = g.get("hub") or {}
        fb = hub.get("fallback_port") or {}
        seen = state["hub_seen"].setdefault(gname, {})
        for c in clients:
            if not c.get("is_wired"):
                continue
            sw, port = str(c.get("sw_mac", "")).lower(), c.get("sw_port")
            if sw == str(hub.get("switch_mac", "")).lower() or \
               (sw == str(fb.get("switch_mac", "")).lower() and port == fb.get("port")):
                seen[c["mac"].lower()] = {"name": c.get("name") or c.get("hostname") or c["mac"],
                                          "last_seen": now.isoformat(timespec="seconds")}
        keep = now - dt.timedelta(days=hub.get("remember_days", 30))
        for mac in [m for m, v in seen.items() if dt.datetime.fromisoformat(v["last_seen"]) < keep]:
            seen.pop(mac)

        sets = {"hub": set(seen),
                "consoles": {m.lower() for m in (g.get("consoles") or {})},
                "wifi": {m.lower() for m in (g.get("wifi") or {})}}
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
                changed.append((gname, r["description"], missing))
    return changed


def members(gname, state=None):
    """Device name -> {macs, wired} for everything in the group."""
    g = group(gname)
    state = state or load_state()
    seen = state["hub_seen"].get(gname, {})
    wired = set(seen) | {m.lower() for m in g.get("wired", [])}
    out = {}
    for m, n in list((g.get("consoles") or {}).items()) + list((g.get("wifi") or {}).items()):
        out.setdefault(n, {"macs": [], "wired": []})["macs"].append(m.lower())
    for m, v in seen.items():
        if not any(m in d["macs"] for d in out.values()):
            out.setdefault(v["name"], {"macs": [], "wired": []})["macs"].append(m)
    for d in out.values():
        d["wired"] = [m for m in d["macs"] if m in wired]
    return out


# ── views (shared by the CLI and the API) ────────────────────────────────

def rule_view(r, state, now):
    s = r.get("schedule") or {}
    ov = state["overrides"].get(r["_id"])
    return {
        "id": r["_id"],
        "name": r["description"],
        "enabled": r["enabled"],
        "blocking": bool(r["enabled"] and in_window(r, now)),
        "schedule": "always" if s.get("mode") == "ALWAYS" else
                    {"days": s.get("repeat_on_days"), "start": s.get("time_range_start"), "end": s.get("time_range_end")},
        "override": None if not ov else {"until": ov["until"], "reason": ov.get("reason"), "set_at": ov.get("set_at")},
    }


def group_status(gname, rules=None, state=None, now=None):
    now = now or dt.datetime.now(TZ)
    state = state or load_state()
    rs = managed_rules(gname, rules)
    return {
        "group": gname,
        "now": now.isoformat(timespec="seconds"),
        "rules": [rule_view(r, state, now) for r in rs],
        "members": members(gname, state),
    }


# ── commands ─────────────────────────────────────────────────────────────

def cmd_tick():
    if not os.path.exists(KEY_FILE):
        return  # not provisioned yet; stay quiet rather than fill the log every minute
    now = dt.datetime.now(TZ)
    state = load_state()
    for gname, desc, macs in sync_groups(state, now):
        log(f"{gname}: added {', '.join(macs)} to {desc}")
    rules = all_rules()
    for gname in load_groups():
        for rule in managed_rules(gname, rules):
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
                set_enabled(rule, True)  # re-enabling inside a window also cuts sessions
                log(f"re-enabled{' (in window, sessions cut)' if active_now else ''}: {name}")
            elif active_now and was_active is False:
                flush(rule)
                log(f"window opened, sessions cut: {name}")
            state["in_window"][rid] = active_now
    save_state(state)


def cmd_allow(gname, target, spec, reason):
    now = dt.datetime.now(TZ)
    until = parse_until(spec, now)
    state = load_state()
    for r in resolve(target, managed_rules(gname)):
        state["overrides"][r["_id"]] = {"until": until.isoformat(timespec="seconds"), "reason": reason,
                                        "set_at": now.isoformat(timespec="seconds")}
        if r["enabled"]:
            set_enabled(r, False)
        log(f"{gname}: allow until {until:%a %H:%M}: {r['description']}" + (f" ({reason})" if reason else ""))
    save_state(state)
    return until


def cmd_revoke(gname, target):
    state = load_state()
    for r in resolve(target, managed_rules(gname)):
        state["overrides"].pop(r["_id"], None)
        if not r["enabled"]:
            set_enabled(r, True)
        log(f"{gname}: override revoked, rule on: {r['description']}")
    save_state(state)


def cmd_flush(gname, target):
    for r in resolve(target, managed_rules(gname)):
        if r["enabled"]:
            flush(r)
            log(f"{gname}: sessions cut: {r['description']}")


def cmd_forget(gname, mac):
    """Drop a device from a group: from the discovered members and from every
    rule's target list. For when the wrong thing got plugged into the hub."""
    mac = mac.lower()
    state = load_state()
    was = state["hub_seen"].get(gname, {}).pop(mac, None)
    removed = []
    for r in managed_rules(gname):
        targets = r.get("target_devices", [])
        keep = [t for t in targets if str(t.get("client_mac", "")).lower() != mac]
        if len(keep) != len(targets):
            body = copy.deepcopy(r)
            body["target_devices"] = keep
            api(rules_url(r["_id"]), body, "PUT")
            removed.append(r["description"])
    save_state(state)
    log(f"{gname}: forgot {mac} ({(was or {}).get('name', '?')}); removed from {len(removed)} rules")
    return {"was_member": bool(was), "removed_from": removed}


def cmd_status(gname=None):
    now = dt.datetime.now(TZ)
    state = load_state()
    rules = all_rules()
    print(f"now {now:%a %H:%M} Europe/London")
    for g in ([gname] if gname else load_groups()):
        st = group_status(g, rules, state, now)
        print(f"[{g}]")
        for r in st["rules"]:
            when = r["schedule"] if r["schedule"] == "always" else \
                f"{','.join(r['schedule']['days'] or [])} {r['schedule']['start']}-{r['schedule']['end']}"
            ov = r["override"]
            extra = f"  OVERRIDE until {ov['until'][11:16]} ({ov.get('reason') or 'no reason'})" if ov else ""
            print(f"  {'ON ' if r['enabled'] else 'off'} {'BLOCKING' if r['blocking'] else 'idle    '} {r['name']}  [{when}]  id={r['id']}{extra}")
        print("  members:", "; ".join(f"{n} ({', '.join(d['macs'])})" for n, d in st["members"].items()) or "none")
        hub = state["hub_seen"].get(g, {})
        print("  behind the hub:", ", ".join(f"{v['name']} (seen {v['last_seen'][:16]})" for v in hub.values()) or "nothing seen yet")


def main(argv):
    try:
        if not argv or argv[0] in ("-h", "--help"):
            print(__doc__)
        elif argv[0] == "tick":
            cmd_tick()
        elif argv[0] == "groups":
            for n, g in load_groups().items():
                print(f"{n}: prefix {g.get('prefix')!r}, {len(g.get('rules') or {})} rules")
        elif argv[0] == "status":
            cmd_status(argv[1] if len(argv) > 1 else None)
        elif argv[0] == "allow" and len(argv) >= 4:
            cmd_allow(argv[1], argv[2], argv[3], " ".join(argv[4:]))
        elif argv[0] == "revoke" and len(argv) == 3:
            cmd_revoke(argv[1], argv[2])
        elif argv[0] == "flush" and len(argv) == 3:
            cmd_flush(argv[1], argv[2])
        elif argv[0] == "forget" and len(argv) == 3:
            print(cmd_forget(argv[1], argv[2]))
        else:
            raise SystemExit(__doc__)
    except PolicyError as e:
        raise SystemExit(str(e))


if __name__ == "__main__":
    main(sys.argv[1:])
