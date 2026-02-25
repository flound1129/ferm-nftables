from .parser import Domain, Rule


VERSION = "2.9"


def sanitize_nft(value: str) -> str:
    """Sanitize values to prevent injection."""
    if not isinstance(value, str):
        return str(value)
    if any(ord(c) < 32 or c == '\n' or c == '\r' for c in value):
        raise ValueError(f"Invalid control character in value: {repr(value)}")
    return value


def generate_nft_command(rule: Rule, chain_name: str, table_name: str = "filter") -> str:
    """Generate a single nft rule command."""
    parts = []
    
    parts.append(f"add rule inet {table_name} {chain_name}")
    
    if rule.interface:
        iface = rule.interface
        if iface.startswith('!'):
            parts.append(f"iif != {iface[1:]}")
        else:
            parts.append(f"iif {iface}")
    
    if rule.outer_interface:
        iface = rule.outer_interface
        if iface.startswith('!'):
            parts.append(f"oif != {iface[1:]}")
        else:
            parts.append(f"oif {iface}")
    
    if rule.protocol:
        proto = rule.protocol
        if proto.startswith('!'):
            parts.append(f"ip protocol != {proto[1:]}")
        elif proto.lower() in ('tcp', 'udp'):
            parts.append(f"{proto}")
        elif proto.lower() != 'icmp':
            parts.append(f"ip protocol {proto}")
    
    if rule.source:
        src = rule.source
        if src.startswith('!'):
            parts.append(f"ip saddr != {src[1:]}")
        else:
            parts.append(f"ip saddr {src}")
    
    if rule.dest:
        dst = rule.dest
        if dst.startswith('!'):
            parts.append(f"ip daddr != {dst[1:]}")
        else:
            parts.append(f"ip daddr {dst}")
    
    if rule.fragment:
        parts.append("frag more-fragments")
    
    if rule.sport:
        sport = rule.sport
        if sport.startswith('(') and sport.endswith(')'):
            ports = sport[1:-1].split()
            parts.append(f"{{ sport {{ {', '.join(ports)} }} }}")
        elif sport.startswith('!'):
            parts.append(f"sport != {sport[1:]}")
        else:
            parts.append(f"sport {sport}")
    
    if rule.dport:
        dport = rule.dport
        if dport.startswith('(') and dport.endswith(')'):
            ports = dport[1:-1].split()
            parts.append(f"{{ dport {{ {', '.join(ports)} }} }}")
        elif dport.startswith('!'):
            parts.append(f"dport != {dport[1:]}")
        else:
            parts.append(f"dport {dport}")
    
    if rule.protocol and rule.protocol.lower() == 'icmp' and not rule.icmp_type:
        parts.append("icmp")
    
    if rule.icmp_type:
        icmp = rule.icmp_type
        if icmp.startswith('!'):
            parts.append(f"icmp type != {icmp[1:]}")
        else:
            parts.append(f"icmp type {icmp}")
    
    if rule.ctstate:
        ctstate = rule.ctstate
        if ctstate.startswith('!'):
            ctstate_val = ctstate[1:]
        else:
            ctstate_val = ctstate
        if ctstate_val.startswith('(') and ctstate_val.endswith(')'):
            ctstate_val = ctstate_val[1:-1].replace(' ', ',')
        ctstate_val = ctstate_val.lower()
        if ctstate.startswith('!'):
            parts.append(f"ct state != {ctstate_val}")
        else:
            parts.append(f"ct state {ctstate_val}")
    
    if rule.mark:
        mark = rule.mark
        if mark.startswith('!'):
            parts.append(f"mark != {mark[1:]}")
        else:
            parts.append(f"mark {mark}")
    
    if rule.tos:
        tos = rule.tos
        if tos.startswith('!'):
            parts.append(f"meta mark != {tos[1:]}")
        else:
            parts.append(f"meta tos {tos}")
    
    if rule.ttl:
        ttl = rule.ttl
        if ttl.startswith('!'):
            parts.append(f"meta ttl != {ttl[1:]}")
        else:
            parts.append(f"meta ttl {ttl}")
    
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
    
    if rule.target:
        target = rule.target
        if target == 'LOG':
            parts.append("log")
            if rule.log_prefix:
                parts.append(f'prefix "{rule.log_prefix}"')
            if rule.log_level:
                parts.append(f'level {rule.log_level}')
        elif target == 'ACCEPT':
            parts.append("accept")
        elif target == 'DROP':
            parts.append("drop")
        elif target == 'REJECT':
            parts.append("reject")
        elif target == 'RETURN':
            parts.append("return")
        elif target == 'MASQUERADE':
            parts.append("masquerade")
        elif target == 'SNAT':
            parts.append("nat snat")
        elif target == 'DNAT':
            parts.append("nat dnat")
        elif target == 'REDIRECT':
            parts.append("redirect")
        elif target == 'MARK':
            mark_value = None
            for i, opt in enumerate(rule.target_options):
                if opt.lower() == 'set-mark' and i + 1 < len(rule.target_options):
                    mark_value = rule.target_options[i + 1]
                    break
            if mark_value:
                parts.append(f"meta mark set {mark_value}")
        else:
            parts.append(f"jump {target}")
    
    return ' '.join(parts)


def generate_nft_rules(domain) -> str:
    """Generate nft commands for all rules. Uses inet tables."""
    if isinstance(domain, dict):
        domain = list(domain.values())[0]
    
    output = []
    output.append(f"# Generated by ferm-nftables {VERSION}")
    output.append("")
    
    tables_created = set()
    
    if not domain.tables:
        return '\n'.join(output)
    
    for table_name, table in sorted(domain.tables.items()):
        table_key = f"inet.{table_name}"
        if table_key not in tables_created:
            output.append(f"add table inet {table_name}")
            tables_created.add(table_key)
        
        for chain_name, chain in sorted(table.chains.items()):
            policy = chain.policy.lower() if chain.policy else "accept"
            output.append(f"add chain inet {table_name} {chain_name} {{ policy {policy}; }}")
            
            for rule in chain.rules:
                cmd = generate_nft_command(rule, chain_name, table_name)
                output.append(cmd)
    
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
