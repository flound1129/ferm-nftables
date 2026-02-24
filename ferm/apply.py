import argparse
import os
import subprocess
import sys
from typing import Dict

from .lexer import FermError
from .output import VERSION, generate_iptables_restore
from .nft import generate_nft_rules
from .parser import Domain, Parser
from .lexer import Lexer


class Ferm:
    def __init__(self):
        self.domains: Dict[str, Domain] = {'ip': Domain('ip'), 'ip6': Domain('ip6')}
        self.noexec = False
        self.flush = False
        self.lines = False
        self.slow = False
        self.remote = False
        self.noflush = False
        self.shell = False
        self.defines: Dict[str, str] = {}
        self.confirm = False
        self.timeout = 0
        self.use_nft = True

    def load_config(self, filename: str):
        with open(filename, 'r') as f:
            content = f.read()
        
        lexer = Lexer(content, filename)
        tokens = lexer.tokenize()
        
        parser = Parser(tokens, filename, self.defines)
        parsed_domains = parser.parse()
        
        for domain_name, domain in parsed_domains.items():
            if domain_name not in self.domains:
                self.domains[domain_name] = domain
            else:
                for table_name, table in domain.tables.items():
                    if table_name not in self.domains[domain_name].tables:
                        self.domains[domain_name].tables[table_name] = table
                    else:
                        for chain_name, chain in table.chains.items():
                            self.domains[domain_name].tables[table_name].chains[chain_name] = chain

    def _save_current_rules(self) -> Dict[str, str]:
        """Save current iptables rules before applying new ones."""
        saved = {}
        
        for domain_name in ['ip', 'ip6']:
            cmd = ['iptables-save' if domain_name == 'ip' else 'ip6tables-save']
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = proc.communicate()
                if proc.returncode == 0:
                    saved[domain_name] = stdout.decode()
            except Exception as e:
                print(f"Warning: Failed to save current {domain_name} rules: {e}", file=sys.stderr)
        
        return saved

    def _rollback(self, saved_rules: Dict[str, str]):
        """Rollback to saved rules."""
        for domain_name, rules in saved_rules.items():
            cmd = ['iptables-restore' if domain_name == 'ip' else 'ip6tables-restore']
            try:
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                proc.communicate(input=rules.encode())
            except Exception as e:
                print(f"Error rolling back {domain_name}: {e}", file=sys.stderr)

    def apply(self):
        if self.use_nft:
            self._apply_nft()
        else:
            self._apply_iptables()
    
    def _apply_nft(self):
        nft_output = generate_nft_rules(self.domains)
        
        if self.lines:
            print(nft_output)
        
        if self.noexec:
            return
        
        try:
            proc = subprocess.Popen(['nft', '-f', '-'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate(input=nft_output.encode())
            if proc.returncode != 0:
                print(f"Error applying nft rules: {stderr.decode()}", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Error applying nft rules: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _apply_iptables(self):
        save_outputs = generate_iptables_restore(self.domains, self.flush)
        
        if self.lines:
            for domain_name, output in sorted(save_outputs.items()):
                print(f"=== {domain_name.upper()} ===")
                print(output)
        
        if self.noexec:
            return
        
        saved_rules = self._save_current_rules()
        
        if self.confirm and not saved_rules:
            print("Warning: Could not save current rules, interactive mode disabled", file=sys.stderr)
            self.confirm = False
        
        success = True
        applied_domains = []
        for domain_name, output in save_outputs.items():
            cmd = ['iptables-restore' if domain_name == 'ip' else 'ip6tables-restore']
            if self.noflush:
                cmd.append('--noflush')
            
            try:
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = proc.communicate(input=output.encode())
                if proc.returncode != 0:
                    print(f"Error applying rules for {domain_name}: {stderr.decode()}", file=sys.stderr)
                    success = False
                else:
                    applied_domains.append(domain_name)
            except Exception as e:
                print(f"Error applying rules for {domain_name}: {e}", file=sys.stderr)
                success = False
        
        if not success and saved_rules and applied_domains:
            print("Failed to apply rules for some domains. Rolling back...", file=sys.stderr)
            self._rollback(saved_rules)
            print("Firewall rules rolled back.", file=sys.stderr)
            sys.exit(1)
        elif not success:
            sys.exit(1)
        
        if self.confirm and success:
            print("\nNew firewall rules have been applied.", file=sys.stderr)
            print("Please type 'yes' to confirm (or wait {} seconds):".format(self.timeout), file=sys.stderr)
            sys.stderr.flush()
            
            try:
                import signal
                
                def alarm_handler(signum, frame):
                    raise TimeoutError()
                
                signal.signal(signal.SIGALRM, alarm_handler)
                signal.alarm(self.timeout)
                
                response = input()
                
                signal.alarm(0)
                
                if response.strip().lower() != 'yes':
                    print("Confirmation failed. Rolling back...", file=sys.stderr)
                    self._rollback(saved_rules)
                    print("Firewall rules rolled back.", file=sys.stderr)
                    sys.exit(1)
            except (EOFError, TimeoutError):
                print("Timeout expired. Rolling back...", file=sys.stderr)
                self._rollback(saved_rules)
                print("Firewall rules rolled back.", file=sys.stderr)
                sys.exit(1)
            except KeyboardInterrupt:
                print("\nInterrupted. Rolling back...", file=sys.stderr)
                self._rollback(saved_rules)
                print("Firewall rules rolled back.", file=sys.stderr)
                sys.exit(1)

    def show_lines(self):
        save_output = generate_iptables_restore(self.domains, self.flush)
        print(save_output)


def main():
    if os.geteuid() != 0:
        print("Error: ferm-nftables must be run as root", file=sys.stderr)
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description='ferm-nftables - A Python implementation of ferm syntax for iptables-nftables'
    )
    parser.add_argument('config', nargs='*', default=['/etc/ferm/ferm.conf'],
                        help='Configuration files (default: /etc/ferm/ferm.conf)')
    parser.add_argument('-n', '--noexec', action='store_true',
                        help='Do not execute, just show what would be done')
    parser.add_argument('-F', '--flush', action='store_true',
                        help='Flush all chains')
    parser.add_argument('-l', '--lines', action='store_true',
                        help='Show all iptables commands')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Interactive mode - ask for confirmation')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                        help='Timeout for interactive mode (seconds)')
    parser.add_argument('--remote', action='store_true',
                        help='Remote mode - ignore host-specific config')
    parser.add_argument('-V', '--version', action='version', version=f'ferm-nftables {VERSION}')
    parser.add_argument('--slow', action='store_true',
                        help='Do not use iptables-restore')
    parser.add_argument('--shell', action='store_true',
                        help='Generate shell script')
    parser.add_argument('--domain', choices=['ip', 'ip6'], default=None,
                        help='Process only the specified domain')
    parser.add_argument('-d', '--def', dest='defines', action='append', default=[],
                        help='Override a variable (e.g., "$name=value")')
    parser.add_argument('--noflush', action='store_true',
                        help='Do not flush existing rules when restoring')
    parser.add_argument('--nft', action='store_true', default=True,
                        help='Use native nftables (default: true)')
    parser.add_argument('--iptables', action='store_true',
                        help='Use iptables-restore instead of native nftables')
    parser.add_argument('--use-legacy', action='store_true',
                        help='Use iptables-legacy instead of iptables-nft')

    args = parser.parse_args()

    ferm = Ferm()
    ferm.noexec = args.noexec
    ferm.flush = args.flush
    ferm.lines = args.lines
    ferm.slow = args.slow
    ferm.noflush = args.noflush
    ferm.shell = args.shell
    ferm.remote = args.remote
    ferm.confirm = args.interactive
    ferm.timeout = args.timeout
    ferm.use_nft = not args.iptables

    for define in args.defines:
        if '=' in define:
            key, value = define.split('=', 1)
            ferm.defines[key] = value

    if args.use_legacy:
        os.environ['IPTABLES_LEGACY'] = '1'

    for config_file in args.config:
        if os.path.exists(config_file):
            try:
                ferm.load_config(config_file)
            except FermError as e:
                print(f"Error: {e.message}", file=sys.stderr)
                sys.exit(1)
        elif config_file != '/etc/ferm/ferm.conf':
            print(f"Warning: Config file not found: {config_file}", file=sys.stderr)

    if args.remote:
        ferm.noexec = True
        ferm.lines = True

    if args.flush:
        ferm.show_lines()
    elif ferm.lines:
        ferm.show_lines()
    else:
        ferm.apply()


if __name__ == '__main__':
    main()
