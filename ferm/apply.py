import argparse
import os
import subprocess
import sys

from .lexer import FermError, Lexer
from .nft import generate_nft_rules
from .parser import Domain, Parser


VERSION = "2.9"


class Ferm:
    def __init__(self):
        self.domain = Domain('inet')
        self.noexec = False
        self.flush = False
        self.lines = False
        self.slow = False
        self.remote = False
        self.noflush = False
        self.shell = False
        self.confirm = False
        self.timeout = 0
        self.use_nft = True
        self.defines: dict = {}
    
    @property
    def domains(self):
        return {'ip': self.domain}

    def load_config(self, filename: str):
        with open(filename, 'r') as f:
            content = f.read()
        
        lexer = Lexer(content, filename)
        tokens = lexer.tokenize()
        
        parser = Parser(tokens, filename, self.defines)
        parsed_domains = parser.parse()
        
        for domain_name, domain in parsed_domains.items():
            for table_name, table in domain.tables.items():
                if table_name not in self.domain.tables:
                    self.domain.tables[table_name] = table
                else:
                    for chain_name, chain in table.chains.items():
                        self.domain.tables[table_name].chains[chain_name] = chain

    def apply(self):
        nft_output = generate_nft_rules(self.domain)
        
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

    def show_lines(self):
        nft_output = generate_nft_rules(self.domain)
        print(nft_output)


def main():
    if os.geteuid() != 0:
        print("Error: ferm-nftables must be run as root", file=sys.stderr)
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description='ferm-nftables - ferm syntax for nftables'
    )
    parser.add_argument('config', nargs='*', default=['/etc/ferm/ferm.conf'],
                        help='Configuration files (default: /etc/ferm/ferm.conf)')
    parser.add_argument('-n', '--noexec', action='store_true',
                        help='Do not execute, just show what would be done')
    parser.add_argument('-l', '--lines', action='store_true',
                        help='Show generated nft commands')
    parser.add_argument('--remote', action='store_true',
                        help='Remote mode - ignore host-specific config')
    parser.add_argument('-V', '--version', action='version', version=f'ferm-nftables {VERSION}')
    parser.add_argument('-d', '--def', dest='defines', action='append', default=[],
                        help='Override a variable (e.g., "$name=value")')

    args = parser.parse_args()

    ferm = Ferm()
    ferm.noexec = args.noexec
    ferm.lines = args.lines

    for define in args.defines:
        if '=' in define:
            key, value = define.split('=', 1)
            ferm.defines[key] = value

    for config_file in args.config:
        if os.path.exists(config_file):
            try:
                ferm.load_config(config_file)
            except FermError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
        elif config_file != '/etc/ferm/ferm.conf':
            print(f"Warning: Config file not found: {config_file}", file=sys.stderr)

    if args.remote:
        ferm.noexec = True
        ferm.lines = True

    if ferm.lines:
        ferm.show_lines()
    else:
        ferm.apply()


if __name__ == '__main__':
    main()
