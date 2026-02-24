# ferm-nftables

A Python implementation of ferm syntax that generates iptables-nftables commands.

## Installation

```bash
# From source
./build.sh

# Or install the .deb package
dpkg -i ferm-nftables_*.deb
```

## Usage

```bash
# Apply firewall rules
ferm-nftables /etc/ferm/ferm.conf

# Show what would be done without executing
ferm-nftables -n /etc/ferm/ferm.conf

# Show iptables commands
ferm-nftables -l /etc/ferm/ferm.conf

# Interactive mode - confirms before applying
ferm-nftables -i /etc/ferm/ferm.conf

# Flush all rules
ferm-nftables -F /etc/ferm/ferm.conf
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-n`, `--noexec` | Don't execute, just show what would be done |
| `-F`, `--flush` | Flush all chains |
| `-l`, `--lines` | Show all iptables commands |
| `-i`, `--interactive` | Interactive mode - ask for confirmation |
| `-t`, `--timeout` | Timeout for interactive mode (seconds, default: 30) |
| `--remote` | Remote mode - ignore host-specific config |
| `-V`, `--version` | Show version |
| `--slow` | Don't use iptables-restore |
| `--shell` | Generate shell script |
| `--domain` | Process only ip or ip6 |
| `-d`, `--def` | Override a variable |
| `--noflush` | Don't flush existing rules when restoring |
| `--use-nft` | Use iptables-nft (default) |
| `--use-legacy` | Use iptables-legacy |

## Configuration Syntax

### Basic Structure

```
@def $TCP tcp
@def $UDP udp
@def $SSH 22

table filter {
    chain INPUT {
        policy ACCEPT;
        
        # Accept established connections
        mod conntrack ctstate (ESTABLISHED,RELATED) ACCEPT;
        
        # Accept localhost
        interface lo ACCEPT;
        
        # Accept SSH
        proto $TCP dport $SSH ACCEPT;
        
        # Drop everything else
        policy DROP;
    }
}
```

### Domains

```
# IPv4 only
ip { ... }

# IPv6 only  
ip6 { ... }

# Both (default)
@include "ipv4.conf"
@include "ipv6.conf"
```

### Tables and Chains

```
table filter {
    chain INPUT {
        # rules
    }
    
    chain OUTPUT {
        # rules
    }
}

table nat {
    chain PREROUTING {
        # rules
    }
}
```

### Rule Elements

| Element | Description |
|---------|-------------|
| `interface` | Input interface |
| `outerface` | Output interface |
| `saddr` | Source address |
| `daddr` | Destination address |
| `proto` | Protocol (tcp, udp, icmp, etc.) |
| `sport` | Source port |
| `dport` | Destination port |
| `mod` | iptables module |
| `log` | Log rules |
| `limit` | Rate limiting |

### Targets

- ACCEPT
- DROP
- REJECT
- LOG
- MASQUERADE
- SNAT
- DNAT
- REDIRECT
- RETURN
- MARK

### Variables

```
@def $ALLOWED_TCP_PORTS (80 443 8080)

proto tcp dport $ALLOWED_TCP_PORTS ACCEPT;
```

### Conditionals

```
@if defined $ENVIRONMENT
@include "production.conf"
@else
@include "development.conf"
@endif
```

### Includes

```
@include "common.conf"
@include "/full/path/to/rules.conf"
```

## Files

- `/etc/ferm/ferm.conf` - Default configuration file
- `/etc/ferm/` - Directory for included configurations

## Security Features

- Input validation on IPs, ports, protocols
- Module validation against allowed list
- iptables-restore injection prevention
- Root privilege check
- Rollback on partial failure
