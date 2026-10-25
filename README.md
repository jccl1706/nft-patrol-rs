# nft-patrol-rs

**An nftables firewall dashboard for Arch Linux, in Rust, with a
[ratatui](https://ratatui.rs) terminal interface.**

nftables rules are precise and hard to read at a glance. nft-patrol shows
them the way you would explain them: `ip saddr 192.168.10.0/24 tcp dport 22
accept` is "Allow SSH (tcp 22) from 192.168.10.0/24 (home LAN)". It also
answers the question a ruleset rarely does by itself: *which of the ports
this machine listens on can the network actually reach, and from where?*

> **Status: phase 2 - editing.** Rules can be added, changed and deleted
> from the dashboard, logging switched on, and a blocked sender or an
> exposed port allowed in one key. Every change is previewed, applied in
> one transaction and **undoes itself after 30 seconds unless you keep it**
> - so a mistake cannot lock you out, even over SSH. Tested on a VM,
> including a change that cut SSH with the session killed mid-way.

## Install

```sh
git clone https://github.com/jccl1706/nft-patrol-rs
cd nft-patrol-rs/packaging/arch
makepkg -si                    # builds, runs the tests, installs nft-patrol-git
```

## Use

```sh
sudo nft-patrol                # the dashboard, live: the kernel's ruleset, hit counts
pkexec /usr/bin/nft-patrol     # the same, with the password asked by the desktop's polkit agent
nft-patrol                     # without root: /etc/nftables.conf, as written
nft-patrol -f other.nft        # any nftables file, before you load it
```

From a desktop launcher, run it in a terminal as `pkexec /usr/bin/nft-patrol`:
the package's polkit action (`io.github.jccl1706.nft-patrol`) has the
password asked in the desktop's own window - "Authentication is required to
view and change the firewall" - rather than at a `sudo` prompt.

Reading the live ruleset needs root. Without it, nft-patrol shows
`/etc/nftables.conf` instead: the file is loaded into a private, empty
network namespace that only nft-patrol's own process can see (`unshare
--user --net`, no root needed) and listed back from there. nft itself does
the parsing, so the file looks exactly as it will once loaded, and the real
firewall is never touched. If the file has a mistake, nft's own message
says which line.

The dashboard has three tabs:

- **Rules** - every chain, its hook and policy, and its rules in plain
  words, each with a badge (ALLOW, BLOCK, REFUSE, JUMP, NAT...). The panel
  beside the list breaks the selected rule into its conditions, shows its
  comment, its hit count (live) and the rule in nft's own syntax.
- **Exposure** - every port this machine listens on, the program behind it,
  and who can reach it over IPv4 and IPv6: *anyone*, *only* some networks,
  or *nobody* - with the rule that decides it. A port bound to loopback is
  "this machine only", firewall or not.
- **Blocked** - packets a rule with `log` recorded, read from the kernel
  log. Nothing is logged unless a rule asks for it.

| Key | |
|---|---|
| `↑↓` `j` `k` `PgUp` `PgDn` `g` `G` | move |
| `Tab` `←→` `1` `2` `3` | Rules, Exposure, Blocked |
| `/` | search all three tabs: words, ports, addresses, programs |
| `Esc` | clear the search |
| `r` | reload now |
| `?` | help |
| `q` | quit |

As root, the rules can be changed:

| Key | |
|---|---|
| `a` | add a rule - above the one picked, or above the chain's catch-all rules at the end |
| `e` | change the rule picked (when it is simple enough for the form) |
| `d` | delete the rule picked |
| `L` | log blocked packets (rate-limited) for the Blocked tab; again to stop |
| `a` on Exposure | allow that port |
| `a` on Blocked | allow what that sender was blocked from |
| `y` / `n` | keep / undo an applied change |

A rule is never typed: the form has five fields - action (allow, block,
refuse), protocol, ports, from (anywhere, a named network, the network an
interface is on, or an address of your own) and a comment - and shows the
rule in words and in nft syntax as you fill it in. A rule needs ports or an
address: one for everything would decide every packet.

### How a change is applied

1. The table the change touches is rewritten from nft's own listing (one
   line added, replaced or removed) and checked with `nft -c`.
2. That table, with the rest of the live ruleset, is loaded into a private
   network namespace, and the review shows what would change: the rule's
   line before and after, which listening ports open or close to whom, and
   a warning if a machine connected over SSH right now could not log in
   again.
3. Enter applies it. First the table as it is goes to
   `/run/nft-patrol/revert.nft` and a systemd timer is started to load it
   back in 30 seconds; then the new table replaces the old one in a single
   transaction. Other tables (docker's, libvirt's) are never touched.
4. `y` stops the timer and saves: `/etc/nftables.conf` is rewritten with the
   tables it had plus the one changed, each as it now is (`destroy table`
   then the table - the same pattern as Arch's default file), checked with
   `nft -c` first, and the old file kept as `/etc/nftables.conf.nft-patrol.bak`.
   `n`, or no answer, loads the old table back.

The timer belongs to systemd, not to nft-patrol: if the change cuts the
session the dashboard runs in, or the dashboard is killed, the firewall
still goes back by itself. A dashboard opened while a change is waiting
picks it up and asks again.

Saving writes nft's listing, so `define`s and comments between rules in a
hand-written file are not kept (rule comments are); the backup has them.
Rewriting a table also starts its hit counts from zero.

The mouse works too: click a row or a tab, scroll the wheel. As root the
dashboard re-reads the ruleset every 2 seconds, so hit counts move; a file
is reloaded whenever it changes, so you can edit it in another pane and
watch.

Without a dashboard:

```sh
nft-patrol list [-v]           # every chain and rule in plain words (-v: and nft's line)
nft-patrol exposure            # the listening ports and who can reach them
nft-patrol status [--json]     # firewall on?, what is open; JSON for desktop widgets
nft-patrol blocked [-n 50]     # the newest logged packets
```

## How exposure is worked out

Each listening socket (from `/proc/net`) is put to the input chains as a
new connection from elsewhere, once over IPv4 and once over IPv6, and walked
the way the kernel would: rules in order, jumps and gotos followed, the
chain's policy at the end, every input chain having to accept. A rule that
depends on the source address is collected rather than decided ("allowed
from 192.168.10.0/24"); rules about connection state, loopback, protocol,
ports, packet type and IPv4/IPv6 are decided. When a rule on the way is one
it cannot reason about - a match on something else, a jump that depends on
the interface - the answer is marked with `?`: likely, not certain.

## Configuration

Optional: `/etc/nft-patrol/config.toml` (see `config.toml.example`). Its
main use is naming networks:

```toml
[networks]
"home LAN" = "192.168.10.0/24"
```

Without names, a range that an interface is on right now is shown as "the
network on wlan0", and well-known ranges are named: private network,
link-local, loopback, Tailscale.

## Development

```sh
cargo test                     # unit tests; the namespace tests need unprivileged user namespaces
cargo clippy --all-targets -- -D warnings
```

`tests/data/` holds two rulesets (`*.nft`) and what nft lists for them
(`*.json`, `*.txt`), regenerated with:

```sh
cd tests/data
for n in archydots rich; do
  unshare -rn sh -c "nft -f $n.nft && nft -j list ruleset > $n.json && nft -a list ruleset > $n.txt"
done
```

## License

GPL-3.0-or-later. See `LICENSE` and `NOTICE`.
