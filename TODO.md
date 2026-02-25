# ferm-nftables TODO

## Working Features

- Basic table/chain parsing
- Simple rules (interface, saddr, daddr, proto, sport, dport)
- Port lists → multiport
- Variables (`@def $VAR = value`)
- Module parsing (state, conntrack, limit, etc.)
- Targets (ACCEPT, DROP, REJECT, LOG, MASQUERADE, SNAT, DNAT, etc.)
- nat, filter, mangle tables
- Policy setting
- Native nftables output (inet tables - handles both IPv4 and IPv6)
- `--lines`, `--noexec` modes

## Parser Bugs Fixed

- Module parsing consuming targets ✓
- Module values not setting has_rule ✓
- Parentheses in module values ✓
- state module output ✓

## Examples

Working: webserver, workstation, mailserver, ipv6

Not working (need functions): antiddos, arptables, dmz_router, dsl_router, ebtables, fileserver, resolve

## Not Implemented

### High Priority

- [x] **Functions** - `@def &func($arg) = {...}`
- [ ] **DNS resolution** - `@resolve("hostname")`
- [ ] **@include patterns** - Glob patterns in includes

### Medium Priority

- [ ] **Conditionals** - `@if/@else/@endif`
- [ ] **@exec commands** - Shell command execution
- [ ] **Advanced modules** - geoip, psd, u32, nth, random, etc.

### Low Priority

- [ ] **Interactive confirm mode** - `--interactive`
- [ ] **Rollback on failure**
- [ ] **Remote mode**

## Tests

- 153 tests passing
- 62% code coverage

## Build

- Refactored into `ferm/` package
- Constants in `constants.toml`
- Native nft default (vs --iptables for legacy)
