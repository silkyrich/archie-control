# Archie Control

Screen-time rules for one child, enforced by the home router, with a phone app the
other parent can mash buttons on: *give him an hour*, *back to the rules*, *kick him off
now*, and a view of what his devices did today.

Built on a UniFi network (a Cloud Gateway Max), a small always-on Linux box at home, and
Cloudflare for the phone-to-home link. Nothing here is specific to our house except the
addresses in two git-ignored files.

```
 iPhone (SwiftUI) --Google sign-in via Cloudflare Access--> Cloudflare Tunnel
                                                                 |
                                            home Linux box: api.py  <-- cron: policy.py (every minute)
                                                                 |
                              UniFi gateway: traffic rules (block internet / games / YouTube)
```

## Why it exists

UniFi traffic rules do the actual blocking, and they support weekly schedules. Two things
they don't do, which this repo adds:

1. **Cut sessions when a window opens.** A scheduled rule only blocks *new* connections. A
   YouTube stream or Roblox game started at 07:29 carries on all day. Turning the rule off
   and on again kills the open sessions; the engine does that the minute each window opens.
2. **Timed overrides.** "Allow games until 5pm" = disable the rule now, re-enable it at
   17:00 without anyone remembering. Re-enabling inside a window also cuts open sessions.

Plus: **the device group is discovered, not typed.** Anything wired behind the child's
own little switch is theirs, remembered for 30 days, and added to every rule
automatically. When a Switch dock appeared on Ethernet with a new address, it was covered
within a minute.

## Layout

- `server/policy.py` - the engine. People are *groups* of hosts. `tick` (cron), `groups`,
  `status [group]`, `allow <group> <target> <minutes|HH:MM>`, `revoke`, `flush`, `forget`. Talks to the gateway with a UniFi API key: a local key against the
  gateway's IP, or a Site Manager key through Ubiquiti's cloud relay (put the console id in
  `host.id`).
- `server/api.py` - a stdlib HTTP API on `127.0.0.1:8787`. It *advertises its services*:
  `GET /services` returns MCP-shaped tool definitions (`home_groups`, `home_status`,
  `home_allow`, ...) and `POST /call/<tool>` runs one, so an MCP connector can stay
  paper-thin and pick up new capabilities without redeploying. The app uses the same
  services as REST under `/api/<group>/...`. It trusts the `Cf-Access-Authenticated-User-Email` header, which is safe
  because only the tunnel on the same host can reach it, and Cloudflare Access sets it.
- `server/groups.example.json` - the group definitions: per person, their hub switch,
  consoles, wifi devices, and which rule covers which set.
- `ArchieControl/` - the iPhone app. Signs in with `ASWebAuthenticationSession` against
  `/auth/start`; the API bounces the Access JWT back through a custom URL scheme and the
  app sends it as `cf-access-token` from then on.

## Setting it up

1. **Rules.** In UniFi, create your traffic rules (Policy Engine, Simple view): e.g. an
   *Internet* block for the consoles, an *App category: Games* block and a *Domain* block
   for YouTube on the kids' network, all Mon-Fri school hours. Give them a common
   description prefix (`MANAGED_PREFIX` in `policy.py`, default `Archie - `).
2. **Server.** Copy `server/` to your Linux box. Put a UniFi API key in `unifi.key` (0600).
   Copy `groups.example.json` to `groups.json` and fill in your addresses and rule ids
   (`policy.py status` prints them). Copy `allowed-emails.example.txt` to
   `allowed-emails.txt`. Install the systemd unit and a cron line:
   `* * * * * /path/policy.py tick >> /path/engine.log 2>&1`.
3. **Cloudflare.** A Tunnel public hostname pointing at `http://localhost:8787`, and an
   Access self-hosted application on that hostname allowing the parents' emails (Google
   login, 30-day sessions).
4. **App.** Set the hostname in `ArchieControl/API.swift`, run `xcodegen generate`, ship via
   TestFlight. The other parent signs in once with Google.

## Things learned the hard way

- `/stat/session` takes seconds; `/stat/report/...` takes milliseconds. Mixing them up
  returns 200 with no rows.
- Traffic counters are swapped for wired clients relative to wireless.
- The session log only holds *finished* sessions; a device that has been online for days
  is only in the live client list.
- A `PUT` of an unchanged rule does not cut sessions, and force-provisioning the gateway
  does not either. Off then on does.
- Ubiquiti's cloud relay occasionally returns a truncated body; retry.
- Don't define a group by a switch *port* on a shared switch. Recabling put the family
  server on that port for an hour and the engine dutifully blocked it the next school day.
  Discover by the child's own switch only, and keep a `forget` command.

MIT licence. No warranty; it's a hobby project that happens to work.
