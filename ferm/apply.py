import argparse
import os
import subprocess
import sys

from .lexer import FermError, Lexer
from .nft import generate_nft_rules
from .parser import Domain, Parser


VERSION = "2.9"
DEFAULT_CONFIG = '/etc/ferm/ferm.conf'
NFT_COMMAND = ['nft', '-f', '-']


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
        
        self._merge_domains(parsed_domains)

    def _merge_domains(self, parsed_domains):
        """Merge parsed domains into main domain."""
        for domain_name, domain in parsed_domains.items():
            for table_name, table in domain.tables.items():
                if table_name not in self.domain.tables:
                    self.domain.tables[table_name] = table
                else:
                    for chain_name, chain in table.chains.items():
                        self.domain.tables[table_name].chains[chain_name] = chain

    def _generate_output(self) -> str:
        """Generate nft rules output."""
        return generate_nft_rules(self.domain)

    def _apply_rules(self, nft_output: str):
        """Apply nft rules."""
        try:
            proc = subprocess.Popen(NFT_COMMAND, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate(input=nft_output.encode())
            if proc.returncode != 0:
                self._handle_error(stderr)
        except FileNotFoundError:
            self._error_exit("nft command not found. Is nftables installed?")
        except Exception as e:
            self._error_exit(str(e))

    def _handle_error(self, stderr: bytes):
        """Handle nft error output."""
        try:
            err_msg = stderr.decode('utf-8', errors='replace')
        except Exception:
            err_msg = '<binary error output>'
        self._error_exit(f"Error applying nft rules: {err_msg}")

    def _error_exit(self, message: str):
        """Print error and exit."""
        print(message, file=sys.stderr)
        sys.exit(1)

    def apply(self):
        nft_output = self._generate_output()
        
        if self.lines:
            print(nft_output)
        
        if self.noexec:
            return
        
        self._apply_rules(nft_output)

    def show_lines(self):
        nft_output = self._generate_output()
        print(nft_output)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='ferm-nftables - ferm syntax for nftables'
    )
    parser.add_argument('config', nargs='*', default=[DEFAULT_CONFIG],
                        help=f'Configuration files (default: {DEFAULT_CONFIG})')
    parser.add_argument('-n', '--noexec', action='store_true',
                        help='Do not execute, just show what would be done')
    parser.add_argument('-l', '--lines', action='store_true',
                        help='Show generated nft commands')
    parser.add_argument('--remote', action='store_true',
                        help='Remote mode - ignore host-specific config')
    parser.add_argument('-V', '--version', action='version', version=f'ferm-nftables {VERSION}')
    parser.add_argument('-d', '--def', dest='defines', action='append', default=[],
                        help='Override a variable (e.g., "$name=value")')
    return parser.parse_args()


def _check_root():
    if os.geteuid() != 0:
        print("Error: ferm-nftables must be run as root", file=sys.stderr)
        sys.exit(1)


def _load_configs(ferm: Ferm, config_files: list):
    for config_file in config_files:
        if os.path.exists(config_file):
            try:
                ferm.load_config(config_file)
            except FermError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
        elif config_file != DEFAULT_CONFIG:
            print(f"Warning: Config file not found: {config_file}", file=sys.stderr)


def main():
    _check_root()
    
    args = _parse_args()
    
    ferm = Ferm()
    ferm.noexec = args.noexec
    ferm.lines = args.lines

    for define in args.defines:
        if '=' in define:
            key, value = define.split('=', 1)
            ferm.defines[key] = value

    _load_configs(ferm, args.config)

    if args.remote:
        ferm.noexec = True
        ferm.lines = True

    if ferm.lines:
        ferm.show_lines()
    else:
        ferm.apply()


if __name__ == '__main__':
    main()
