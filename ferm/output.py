import re
from typing import Any, Dict, List

from .parser import Domain, Rule


VERSION = "2.8"


def sanitize_for_iptables(value: str) -> str:
    """Sanitize values to prevent iptables-restore injection."""
    if not isinstance(value, str):
        return str(value)
    if any(ord(c) < 32 or c == '\n' or c == '\r' for c in value):
        raise ValueError(f"Invalid control character in value: {repr(value)}")
    return value


def generate_iptables_command(rule: Rule, chain_name: str, append: bool = True) -> List[str]:
    cmd = ['iptables' if rule.domain == 'ip' else 'ip6tables']
    
    if rule.table and rule.table != 'filter':
        cmd.extend(['-t', rule.table])
    
    cmd.append('-A' if append else '-I')
    cmd.append(chain_name)
    
    if rule.interface:
        iface = rule.interface
        if iface.startswith('!'):
            cmd.extend(['!', '-i', iface[1:]])
        else:
            cmd.extend(['-i', iface])
    
    if rule.outer_interface:
        iface = rule.outer_interface
        if iface.startswith('!'):
            cmd.extend(['!', '-o', iface[1:]])
        else:
            cmd.extend(['-o', iface])
    
    if rule.protocol:
        proto = rule.protocol
        if proto.startswith('!'):
            cmd.extend(['!', '-p', proto[1:]])
        else:
            cmd.extend(['-p', proto])
    
    if rule.source:
        src = rule.source
        if src.startswith('!'):
            cmd.extend(['!', '-s', src[1:]])
        else:
            cmd.extend(['-s', src])
    
    if rule.dest:
        dst = rule.dest
        if dst.startswith('!'):
            cmd.extend(['!', '-d', dst[1:]])
        else:
            cmd.extend(['-d', dst])
    
    if rule.fragment:
        cmd.append('-f')
    
    if rule.sport:
        sport = rule.sport
        if sport.startswith('(') and sport.endswith(')'):
            ports = sport[1:-1].split()
            cmd.extend(['-m', 'multiport', '--sports', ','.join(ports)])
        elif sport.startswith('!'):
            cmd.extend(['!', '--sport', sport[1:]])
        else:
            cmd.extend(['--sport', sport])
    
    if rule.dport:
        dport = rule.dport
        if dport.startswith('(') and dport.endswith(')'):
            ports = dport[1:-1].split()
            cmd.extend(['-m', 'multiport', '--dports', ','.join(ports)])
        elif dport.startswith('!'):
            cmd.extend(['!', '--dport', dport[1:]])
        else:
            cmd.extend(['--dport', dport])
    
    if rule.icmp_type:
        icmp = rule.icmp_type
        if icmp.startswith('!'):
            cmd.extend(['!', '--icmp-type', icmp[1:]])
        else:
            cmd.extend(['--icmp-type', icmp])
    
    if rule.ctstate:
        ctstate = rule.ctstate
        if ctstate.startswith('!'):
            cmd.extend(['!', '-m', 'conntrack', '--ctstate', ctstate[1:]])
        else:
            cmd.extend(['-m', 'conntrack', '--ctstate', ctstate])
    elif 'state' in rule.match_modules.get('state', {}) or 'ctstate' in rule.match_modules.get('state', {}):
        vals = rule.match_modules.get('state', {})
        state_val = vals.get('state') or vals.get('ctstate', '')
        if state_val:
            cmd.extend(['-m', 'conntrack', '--ctstate', state_val])
    
    if rule.mark:
        mark = rule.mark
        if mark.startswith('!'):
            cmd.extend(['!', '-m', 'mark', '--mark', mark[1:]])
        else:
            cmd.extend(['-m', 'mark', '--mark', mark])
    
    if rule.tos:
        tos = rule.tos
        if tos.startswith('!'):
            cmd.extend(['!', '-m', 'tos', '--tos', tos[1:]])
        else:
            cmd.extend(['-m', 'tos', '--tos', tos])
    
    if rule.ttl:
        ttl = rule.ttl
        if ttl.startswith('!'):
            cmd.extend(['!', '-m', 'ttl', '--ttl', ttl[1:]])
        else:
            cmd.extend(['-m', 'ttl', '--ttl', ttl])
    
    for module, options in rule.match_modules.items():
        if module == 'state':
            module = 'conntrack'
        if module == 'conntrack' and 'state' in options:
            continue
        cmd.extend(['-m', module])
        for key, value in options.items():
            if module == 'conntrack' and key == 'state':
                key = 'ctstate'
            dash_key = key.replace('_', '-')
            cmd.extend([f'--{dash_key}', str(value)])
    
    if rule.target:
        cmd.extend(['-j', rule.target])
        
        if rule.target == 'LOG':
            if rule.log_level:
                cmd.extend(['--log-level', rule.log_level])
            if rule.log_prefix:
                cmd.extend(['--log-prefix', rule.log_prefix])
        
        for opt in rule.target_options:
            cmd.append(opt)
    
    return cmd


def generate_iptables_restore(domains: Dict[str, Domain], flush: bool = False) -> Dict[str, str]:
    """Generate iptables-restore input. Returns dict keyed by domain ('ip' or 'ip6')."""
    result = {}
    
    for domain_name in ['ip', 'ip6']:
        domain = domains.get(domain_name)
        if not domain:
            continue
        
        if not domain.tables:
            continue
        
        output = []
        output.append(f"# Generated by ferm-nftables {VERSION}")
        
        for table_name, table in sorted(domain.tables.items()):
            sanitized_table = sanitize_for_iptables(table_name)
            output.append(f'*{sanitized_table}')
            
            for chain_name, chain in sorted(table.chains.items()):
                sanitized_chain = sanitize_for_iptables(chain_name)
                policy = chain.policy if chain.policy else 'ACCEPT'
                sanitized_policy = sanitize_for_iptables(policy)
                output.append(f':{sanitized_chain} {sanitized_policy} [0:0]')
                
                for rule in chain.rules:
                    cmd = generate_iptables_command(rule, sanitized_chain)
                    output.append(' '.join(cmd))
            
            output.append('COMMIT')
        
        if output:
            result[domain_name] = '\n'.join(output)
    
    return result
