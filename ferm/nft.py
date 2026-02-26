from .parser import Domain, Rule


VERSION = "2.9"

PROTO_TCP_UDP = ('tcp', 'udp')
PROTO_ICMP = 'icmp'


def sanitize_nft(value: str) -> str:
    """Sanitize values to prevent injection."""
    if not isinstance(value, str):
        return str(value)
    if any(ord(c) < 32 or c == '\n' or c == '\r' for c in value):
        raise ValueError(f"Invalid control character in value: {repr(value)}")
    return value


def _format_negated(value: str, nft_prefix: str) -> str:
    """Format a possibly negated value with nft syntax."""
    if value.startswith('!'):
        return f"{nft_prefix} != {value[1:]}"
    return f"{nft_prefix} {value}"


def _format_ports(ports: str) -> str:
    """Format port list for nftables."""
    if ports.startswith('(') and ports.endswith(')'):
        port_list = ports[1:-1].split()
        return f"{{ {', '.join(port_list)} }}"
    return ports


def _parse_negated(value: str) -> tuple[str, bool]:
    """Parse negated value, returns (actual_value, is_negated)."""
    if value.startswith('!'):
        return value[1:], True
    return value, False


def _format_log_target(rule: Rule, base: str) -> list[str]:
    """Format LOG target."""
    parts = [base]
    if rule.log_prefix:
        parts.append(f'prefix "{rule.log_prefix}"')
    if rule.log_level:
        parts.append(f'level {rule.log_level}')
    return parts


def _format_mark_target(rule: Rule, base: str) -> list[str]:
    """Format MARK target."""
    mark_value = None
    for i, opt in enumerate(rule.target_options):
        if opt.lower() == 'set-mark' and i + 1 < len(rule.target_options):
            mark_value = rule.target_options[i + 1]
            break
    if mark_value:
        return [f"{base} {mark_value}"]
    return [base]


TARGET_MAP = {
    'LOG': ('log', _format_log_target),
    'ACCEPT': ('accept', None),
    'DROP': ('drop', None),
    'REJECT': ('reject', None),
    'RETURN': ('return', None),
    'MASQUERADE': ('masquerade', None),
    'SNAT': ('nat snat', None),
    'DNAT': ('nat dnat', None),
    'REDIRECT': ('redirect', None),
    'MARK': ('meta mark set', _format_mark_target),
}


def _format_target(rule: Rule) -> list[str]:
    """Format the target part of a rule."""
    target = rule.target
    
    if target in TARGET_MAP:
        nft_target, formatter = TARGET_MAP[target]
        if formatter:
            return formatter(rule, nft_target)
        return [nft_target]
    
    # Default: jump to chain
    return [f"jump {target}"]


def generate_nft_command(rule: Rule, chain_name: str, table_name: str = "filter") -> str:
    """Generate a single nft rule command."""
    parts = []
    
    # Interface
    if rule.interface:
        iface = rule.interface
        value, negated = _parse_negated(iface)
        prefix = "iif" if not negated else "iif !="
        parts.append(f"{prefix} {value}")
    
    if rule.outer_interface:
        iface = rule.outer_interface
        value, negated = _parse_negated(iface)
        prefix = "oif" if not negated else "oif !="
        parts.append(f"{prefix} {value}")
    
    # Protocol
    if rule.protocol:
        proto = rule.protocol
        value, negated = _parse_negated(proto)
        if negated:
            parts.append(f"ip protocol != {value}")
        elif value.lower() in PROTO_TCP_UDP:
            parts.append(f"{value}")
        elif value.lower() != PROTO_ICMP:
            parts.append(f"ip protocol {value}")
    
    # Source/Dest
    if rule.source:
        parts.append(_format_negated(rule.source, "ip saddr"))
    
    if rule.dest:
        parts.append(_format_negated(rule.dest, "ip daddr"))
    
    if rule.fragment:
        parts.append("frag more-fragments")
    
    # Ports
    if rule.sport:
        value, negated = _parse_negated(rule.sport)
        prefix = "sport" if not negated else "sport !"
        if value.startswith('(') and value.endswith(')'):
            parts.append(f"sport {_format_ports(value)}")
        else:
            parts.append(f"{prefix} {value}")
    
    if rule.dport:
        value, negated = _parse_negated(rule.dport)
        prefix = "dport" if not negated else "dport !"
        if value.startswith('(') and value.endswith(')'):
            parts.append(f"dport {_format_ports(value)}")
        else:
            parts.append(f"{prefix} {value}")
    
    # ICMP - icmp without type is not valid in inet tables
    if rule.protocol and rule.protocol.lower() == PROTO_ICMP and not rule.icmp_type:
        pass
    
    if rule.icmp_type:
        parts.append(_format_negated(rule.icmp_type, "icmp type"))
    
    # Connection tracking
    if rule.ctstate:
        ctstate, negated = _parse_negated(rule.ctstate)
        if ctstate.startswith('(') and ctstate.endswith(')'):
            ctstate = ctstate[1:-1].replace(' ', ',')
        ctstate = ctstate.lower()
        if negated:
            parts.append(f"ct state != {ctstate}")
        else:
            parts.append(f"ct state {ctstate}")
    
    # Mark
    if rule.mark:
        parts.append(_format_negated(rule.mark, "mark"))
    
    # TOS
    if rule.tos:
        parts.append(_format_negated(rule.tos, "meta tos"))
    
    # TTL
    if rule.ttl:
        parts.append(_format_negated(rule.ttl, "meta ttl"))
    
    # Modules
    for module, options in rule.match_modules.items():
        if module == 'state':
            module = 'conntrack'
        if module == 'conntrack' and 'state' in options:
            state_val = options.get('state', '')
            if state_val:
                parts.append(f"ct state {state_val}")
            continue
        for key, value in options.items():
            if module == 'conntrack' and key == 'state':
                key = 'ctstate'
            nft_key = key.replace('_', ' ')
            parts.append(f"{module} {nft_key} {value}")
    
    # Target
    if rule.target:
        parts.extend(_format_target(rule))
    
    return ' '.join(parts)


TARGET_MAP = {
    'LOG': ('log', _format_log_target),
    'ACCEPT': ('accept', None),
    'DROP': ('drop', None),
    'REJECT': ('reject', None),
    'RETURN': ('return', None),
    'MASQUERADE': ('masquerade', None),
    'SNAT': ('nat snat', None),
    'DNAT': ('nat dnat', None),
    'REDIRECT': ('redirect', None),
    'MARK': ('meta mark set', _format_mark_target),
}


def _format_target(rule: Rule) -> list[str]:
    """Format the target part of a rule."""
    target = rule.target
    
    if target in TARGET_MAP:
        nft_target, formatter = TARGET_MAP[target]
        if formatter:
            return formatter(rule, nft_target)
        return [nft_target]
    
    # Default: jump to chain
    return [f"jump {target}"]


def generate_nft_rules(domain) -> str:
    """Generate nft script for all rules. Uses inet tables."""
    if isinstance(domain, dict):
        domain = list(domain.values())[0]
    
    output = []
    output.append(f"# Generated by ferm-nftables {VERSION}")
    output.append("")
    
    if not domain.tables:
        return '\n'.join(output)
    
    base_chains = {'input', 'output', 'forward', 'prerouting', 'postrouting'}
    
    for table_name, table in sorted(domain.tables.items()):
        output.append(f"table inet {table_name} {{")
        
        for chain_name, chain in sorted(table.chains.items()):
            is_base = chain_name.lower() in base_chains
            has_rules = len(chain.rules) > 0
            
            if not is_base and not has_rules:
                continue
                
            policy = chain.policy.lower() if chain.policy else "accept"
            output.append(f"    chain {chain_name.lower()} {{")
            
            if is_base:
                output.append(f"        type filter hook {chain_name.lower()} priority 0; policy {policy};")
            else:
                output.append(f"        policy {policy};")
            
            for rule in chain.rules:
                cmd = generate_nft_command(rule, chain_name, table_name)
                output.append(f"            {cmd}")
            
            output.append(f"    }}")
        
        output.append(f"}}")
    
    return '\n'.join(output)


def apply_nft_rules(dry_run: bool = False) -> bool:
    """Apply nft rules by running nft -f."""
    import sys
    content = generate_nft_rules(Domain('inet'))
    
    if dry_run:
        print(content)
        return True
    
    try:
        import subprocess
        proc = subprocess.Popen(['nft', '-f', '-'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=content.encode())
        if proc.returncode != 0:
            try:
                err_msg = stderr.decode('utf-8', errors='replace')
            except Exception:
                err_msg = '<binary error output>'
            print(f"Error applying nft rules: {err_msg}", file=sys.stderr)
            return False
        return True
    except Exception as e:
        print(f"Error applying nft rules: {e}", file=sys.stderr)
        return False
